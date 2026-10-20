"""Authenticated HTTPS log transport, independent of the client's public IP."""
import hashlib,hmac,ipaddress,io,json,secrets,uuid,zipfile
from datetime import timedelta
from pathlib import Path
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db import transaction
from django.db.models import F,Sum
from django.http import JsonResponse,HttpResponse,HttpResponseForbidden
from django.shortcuts import get_object_or_404,redirect,render
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from .models import SecureLogChannel,SecureLogReceipt,Device,WorkerState,ExportConfiguration,FirewallOnboarding
from .security import encrypt,decrypt,audit,mfa_fresh
from .invitations import origin

NETWORK=ipaddress.ip_network('127.80.0.0/16')
MAX_BODY=128*1024

def queue_has_room(channel,size):
    pending=SecureLogReceipt.objects.exclude(encrypted_payload='').exclude(status__in=['forwarded','legacy','confirmed'])
    return ((pending.filter(channel=channel).aggregate(n=Sum('bytes_count'))['n'] or 0)+size<=64*1024*1024 and
        (pending.aggregate(n=Sum('bytes_count'))['n'] or 0)+size<=256*1024*1024)

def active_channels():
    return SecureLogChannel.objects.filter(enabled=True,device__active=True,device__site__active=True,device__site__client__active=True,client_scope_id=F('device__site__client_id'))

def ensure_local_guard():
    """Only the privileged receiver worker calls this before trusting aliases."""
    import pwd,subprocess
    uid=pwd.getpwnam('socportal').pw_uid
    exists=subprocess.run(['nft','list','table','inet','soc_https_logs'],capture_output=True,timeout=5).returncode==0
    rules=f'''table inet soc_https_logs {{
      chain input {{ type filter hook input priority -30; policy accept;
        ip saddr 127.80.0.0/16 iifname != "lo" drop
      }}
      chain output {{ type filter hook output priority -30; policy accept;
        ip saddr 127.80.0.0/16 meta skuid != {{ 0, {uid} }} drop
      }}
    }}'''
    script=('delete table inet soc_https_logs\n' if exists else '')+rules
    subprocess.run(['nft','--check','-f','-'],input=script,text=True,check=True,capture_output=True,timeout=5)
    subprocess.run(['nft','-f','-'],input=script,text=True,check=True,capture_output=True,timeout=5)

def prepare(device):
    with transaction.atomic():
        WorkerState.objects.get_or_create(name='secure-log-allocation')
        WorkerState.objects.filter(name='secure-log-allocation').update(offset=F('offset')+1)
        old=SecureLogChannel._base_manager.filter(device=device).first()
        if old:
            if old.client_scope_id!=device.site.client_id:raise ValueError('El equipo cambió de cliente. Revoca el canal anterior antes de continuar.')
            return old
        used=set(SecureLogChannel._base_manager.values_list('source_identity',flat=True))|set(ExportConfiguration._base_manager.exclude(source_ip=None).values_list('source_ip',flat=True))
        identity=next((str(ip) for ip in NETWORK.hosts() if str(ip) not in used),None)
        if identity is None:raise ValueError('No quedan identidades de recepción disponibles.')
        token=secrets.token_urlsafe(32)
        channel=SecureLogChannel.objects.create(device=device,client_scope_id=device.site.client_id,source_identity=identity,token_hash=hashlib.sha256(token.encode()).hexdigest(),encrypted_token=encrypt(token))
        ExportConfiguration.objects.get_or_create(device=device,defaults={'source_ip':identity,'status':'configured','configured_at':timezone.now()})
        return channel

@csrf_exempt
@never_cache
@require_http_methods(['POST'])
def ingest(request,channel_id):
    if not request.is_secure():return JsonResponse({'error':'HTTPS required'},status=400)
    channel=active_channels().filter(pk=channel_id).first()
    auth=request.headers.get('Authorization','')
    if not channel or not auth.startswith('Bearer ') or len(auth)>128 or not hmac.compare_digest(hashlib.sha256(auth[7:].encode()).hexdigest(),channel.token_hash):return JsonResponse({'error':'Unauthorized'},status=401)
    if not channel.receiver_ready:return JsonResponse({'error':'Receiver pending'},status=503)
    try:
        if request.content_type!='application/json' or int(request.META.get('CONTENT_LENGTH') or 0)>MAX_BODY:return JsonResponse({'error':'Invalid payload'},status=413)
        raw=request.body
        if len(raw)>MAX_BODY:raise ValueError
        body=json.loads(raw)
        batch=uuid.UUID(body['batch_id']);lines=body['messages']
        if not isinstance(lines,list) or not 1<=len(lines)<=32:raise ValueError
        payload=[]
        for line in lines:
            if not isinstance(line,str) or not line or any(ord(c)<32 and c!='\t' for c in line) or '\x7f' in line:raise ValueError
            encoded=line.encode('utf-8')
            if len(encoded)>8192:raise ValueError
            payload.append(encoded)
    except (ValueError,TypeError,KeyError,AttributeError,UnicodeError):return JsonResponse({'error':'Invalid payload'},status=400)
    digest=hashlib.sha256(json.dumps(lines,ensure_ascii=False,separators=(',',':')).encode()).hexdigest()
    with transaction.atomic():
        # Serialize deduplication/rate checks, including on SQLite.
        SecureLogChannel.objects.filter(pk=channel.pk).update(last_received_at=F('last_received_at'))
        channel.refresh_from_db()
        if not active_channels().filter(pk=channel.pk).exists() or not hmac.compare_digest(hashlib.sha256(auth[7:].encode()).hexdigest(),channel.token_hash):return JsonResponse({'error':'Unauthorized'},status=401)
        existing=SecureLogReceipt.objects.filter(channel=channel,batch_id=batch).first()
        if existing:
            if existing.digest!=digest:return JsonResponse({'error':'Batch conflict'},status=409)
            # Upgrade old receipts safely: an old receipt cannot attest durable storage.
            # Do not replay these automatically, as the old UDP send may have arrived.
            if existing.status=='legacy' and not existing.encrypted_payload:
                if not queue_has_room(channel,len(raw)):return JsonResponse({'error':'Durable queue full; retain the local batch'},status=503)
                existing.encrypted_payload=encrypt(json.dumps(lines,ensure_ascii=False,separators=(',',':')))
                existing.status='uncertain';existing.error='Recibo anterior: el reenvío UDP no dispone de confirmación.'
                existing.save(update_fields=['encrypted_payload','status','error'])
            return persisted_reply(existing,duplicate=True)
        recent=SecureLogReceipt.objects.filter(channel=channel,received_at__gte=timezone.now()-timedelta(minutes=1))
        if recent.count()>=200 or (recent.aggregate(n=Sum('bytes_count'))['n'] or 0)+len(raw)>10*1024*1024:return JsonResponse({'error':'Rate limit'},status=429)
        # Bound uncompleted storage without deleting unforwarded data. Transactions
        # serialize the capacity check with insertions, including under SQLite.
        if not queue_has_room(channel,len(raw)):
            return JsonResponse({'error':'Durable queue full; retain the local batch'},status=503)
        receipt=SecureLogReceipt.objects.create(channel=channel,batch_id=batch,digest=digest,bytes_count=len(raw),messages_count=len(lines),
            status='queued',transport_version=2,encrypted_payload=encrypt(json.dumps(lines,ensure_ascii=False,separators=(',',':'))))
        try:transport=str(ipaddress.ip_address(request.META.get('REMOTE_ADDR','')))
        except ValueError:transport=None
        SecureLogChannel.objects.filter(pk=channel.pk).update(last_received_at=timezone.now(),last_transport_ip=transport)
    return persisted_reply(receipt)

def persisted_reply(receipt,duplicate=False):
    return JsonResponse({'accepted':receipt.messages_count,'batch_id':str(receipt.batch_id),'digest':receipt.digest,
        'persisted':True,'duplicate':duplicate,'status':receipt.status,
        'wazuh_processed':receipt.confirmed_at is not None,'wazuh_verified':False},status=202)

@login_required
@never_cache
@require_http_methods(['GET','POST'])
def setup(request,pk):
    device=get_object_or_404(Device.objects.select_related('site__client'),pk=pk)
    if not request.user.has_perm('core.manage_connections'):return HttpResponseForbidden('Permiso de conexiones requerido.')
    channel=SecureLogChannel.objects.filter(device=device).first()
    if request.method=='POST':
        if not mfa_fresh(request):return redirect('mfa_challenge')
        action=request.POST.get('action')
        if action=='prepare':
            try:channel=prepare(device)
            except ValueError as exc:messages.error(request,str(exc));return redirect('secure_log_setup',pk=pk)
            audit('logs.https_prepared',device)
        elif channel and action=='disable':
            channel.enabled=False;channel.receiver_ready=False;channel.save(update_fields=['enabled','receiver_ready']);audit('logs.https_disabled',device)
        elif channel and channel.client_scope_id==device.site.client_id:
            if action=='rotate':
                token=secrets.token_urlsafe(32);channel.token_hash=hashlib.sha256(token.encode()).hexdigest();channel.encrypted_token=encrypt(token);channel.enabled=True;channel.save(update_fields=['token_hash','encrypted_token','enabled']);audit('logs.https_rotated',device)
            elif action=='download':return relay_package(channel)
            elif action=='retry':
                from .log_delivery import retry_reviewed
                if request.POST.get('confirm_replay')=='yes' and retry_reviewed(channel,request.POST.get('receipt','')):
                    audit('logs.https_retry_reviewed',device)
                    messages.success(request,'Reintento programado desde el mensaje pendiente. Puede duplicarse el mensaje cuya entrega no se pudo confirmar.')
                else:messages.error(request,'Selecciona un lote pendiente de revisión y confirma el posible duplicado.')
            elif action=='verify' and channel.enabled:
                config,_=ExportConfiguration.objects.get_or_create(device=device)
                config.source_ip=channel.source_identity;config.destination='172.20.10.20';config.port=5514;config.status='configured';config.receiver_ready=channel.receiver_ready;config.configured_at=timezone.now();config.save()
                row,_=FirewallOnboarding.objects.get_or_create(device=device)
                row.method='https';row.step=5;row.verified_at=row.event_at=row.zenarmor_event_at=None;row.verification_started_at=timezone.now();row.verification_error='';row.save()
                device.log_method='syslog';device.integration='pending';device.save(update_fields=['log_method','integration'])
                audit('logs.https_verification',device)
                return redirect('device_onboarding',pk=pk)
        return redirect('secure_log_setup',pk=pk)
    from .log_delivery import queue_summary
    return render(request,'secure_log_setup.html',{'device':device,'channel':channel,
        'queue':queue_summary(channel) if channel else None,
        'receipts':SecureLogReceipt.objects.filter(channel=channel).order_by('-received_at')[:20] if channel else []})

def relay_package(channel):
    from django.urls import reverse
    config={'url':origin()+reverse('secure_log_ingest',args=[channel.pk]),'token':decrypt(channel.encrypted_token),'listen_host':'127.0.0.1','listen_port':5515,'spool':'/var/lib/soc-log-relay/spool.sqlite3'}
    buffer=io.BytesIO()
    root=Path(__file__).resolve().parent.parent/'deploy'/'relay'
    with zipfile.ZipFile(buffer,'w',zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('soc-log-relay.json',json.dumps(config,indent=2))
        for name in ('soc_log_relay.py','soc-log-relay.service','LEEME.md'):archive.write(root/name,name)
    audit('logs.https_credentials_downloaded',channel.device)
    response=HttpResponse(buffer.getvalue(),content_type='application/zip');response['Content-Disposition']=f'attachment; filename="soc-logs-equipo-{channel.device_id}.zip"';return response

"""Signed provider events; primary recipients only, immutable dispatch correlation."""
import base64,json,time,uuid
from datetime import datetime,timedelta,timezone as utc
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.asymmetric import ec
from django import forms
from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.http import HttpResponse,HttpResponseForbidden
from django.shortcuts import render,get_object_or_404,redirect
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST,require_http_methods
from .models import MailDispatch,MailEvent,DeliverySettings,Client,UrgentAlert,OperationalIssue,WorkerState
from .security import audit,mfa_fresh
from .forms import ScopedModelForm

def verification_key(value):
    value=value.strip()
    key=serialization.load_pem_public_key(value.encode()) if value.startswith('-----BEGIN') else serialization.load_der_public_key(base64.b64decode(value,validate=True))
    if not isinstance(key,ec.EllipticCurvePublicKey) or not isinstance(key.curve,ec.SECP256R1):raise ValueError('Clave de firma no válida')
    return key

@csrf_exempt
@require_POST
def delivery_webhook(request):
    config=DeliverySettings.objects.filter(pk=1,enabled=True).first()
    if not config or not config.public_key:return HttpResponse(status=503)
    raw=request.body
    if len(raw)>1024*1024:return HttpResponse(status=413)
    stamp=request.headers.get('X-Twilio-Email-Event-Webhook-Timestamp','')
    try:
        # Provider retries can span 24 h. Reject future signatures separately.
        if not stamp.isascii() or not stamp.isdigit() or len(stamp)>12 or not -300<=time.time()-int(stamp)<=7*86400:raise ValueError()
        signature=base64.b64decode(request.headers.get('X-Twilio-Email-Event-Webhook-Signature',''),validate=True)
        verification_key(config.public_key).verify(signature,stamp.encode()+raw,ec.ECDSA(hashes.SHA256()))
    except Exception:return HttpResponse(status=403)
    try:
        events=json.loads(raw)
        if not isinstance(events,list) or len(events)>500:raise ValueError()
    except (ValueError,TypeError):return HttpResponse(status=400)
    valid={'processed','delivered','deferred','bounce','dropped'}
    matched=False
    with transaction.atomic():
        # Serialize dispatch status calculation, including SQLite workers.
        DeliverySettings.objects.filter(pk=config.pk).update(last_signed_at=timezone.now())
        for event in events:
            if not isinstance(event,dict) or event.get('event') not in valid:continue
            try:
                token=uuid.UUID(str(event.get('soc_dispatch','')))
                if isinstance(event['timestamp'],bool) or not isinstance(event['sg_event_id'],str):continue
                happened=datetime.fromtimestamp(int(event['timestamp']),utc.utc)
                event_id=event['sg_event_id']
                if not event_id or len(event_id)>1000:continue
            except (ValueError,TypeError,KeyError,OverflowError,OSError):continue
            dispatch=MailDispatch.objects.filter(token=token,recipient__iexact=str(event.get('email',''))).first()
            if not dispatch or happened<dispatch.created_at-timedelta(minutes=5) or happened>timezone.now()+timedelta(minutes=5):continue
            import hashlib
            event_hash=hashlib.sha256(event_id.encode()).hexdigest()
            _,created=MailEvent.objects.get_or_create(event_hash=event_hash,defaults={'dispatch':dispatch,'kind':event['event'],'occurred_at':happened})
            if not created:continue
            matched=True
            # Event order can differ from delivery order; failures stay visible after delivery.
            all_events=list(dispatch.events.order_by('occurred_at','pk'))
            failures=[e for e in all_events if e.kind in ('bounce','dropped')]
            latest=failures[-1] if failures else next((e for e in reversed(all_events) if e.kind=='delivered'),all_events[-1])
            dispatch.status=latest.kind;dispatch.event_at=latest.occurred_at;dispatch.save(update_fields=['status','event_at'])
        if matched:DeliverySettings.objects.filter(pk=config.pk).update(last_matched_at=timezone.now())
    return HttpResponse(status=204)

class DeliveryForm(ScopedModelForm):
    class Meta:
        model=DeliverySettings;fields=['public_key','enabled','ack_minutes']
        widgets={'public_key':forms.Textarea(attrs={'rows':4})}
    def clean_public_key(self):
        value=self.cleaned_data['public_key'].strip()
        if value:
            try:verification_key(value)
            except Exception:raise forms.ValidationError('Pega la clave pública de firma ECDSA que proporciona SendGrid.')
        return value
    def clean_ack_minutes(self):
        value=self.cleaned_data['ack_minutes']
        if not 5<=value<=1440:raise forms.ValidationError('Usa entre 5 y 1440 minutos.')
        return value
    def clean(self):
        values=super().clean()
        if values.get('enabled') and not values.get('public_key'):self.add_error('public_key','La firma es obligatoria para activar el webhook.')
        return values

@login_required
@require_http_methods(['GET','POST'])
def delivery_settings(request):
    access=getattr(request.user,'soc_access',None)
    if not request.user.has_perm('core.manage_connections') or not (request.user.is_superuser or access and access.all_clients):return HttpResponseForbidden()
    config=DeliverySettings.objects.filter(pk=1).first() or DeliverySettings(pk=1)
    form=DeliveryForm(request.POST or None,instance=config)
    if request.method=='POST':
        if not mfa_fresh(request):return redirect('mfa_challenge')
        if request.POST.get('action')=='diagnose':
            from .delivery_provider import diagnose
            diagnose();audit('mail.webhook_checked',config);return redirect('delivery_settings')
        if form.is_valid():
            if 'public_key' in form.changed_data:config.last_signed_at=None;config.last_matched_at=None
            form.save();audit('mail.webhook_settings',config,{'fields':form.changed_data});return redirect('delivery_status')
    for field in form.fields.values():field.widget.attrs['class']='input'
    return render(request,'delivery_settings.html',{'form':form,'provider':WorkerState.objects.filter(pk='delivery-provider').first()})

@login_required
def delivery_status(request):
    rows=MailDispatch.objects.select_related('client','report','urgent')
    alerts=UrgentAlert.objects.exclude(status__in=('suppressed','expired')).select_related('client','acknowledged_by')
    client=request.GET.get('client','')
    if client.isdigit():
        selected=get_object_or_404(Client,pk=client);rows=rows.filter(client=selected);alerts=alerts.filter(client=selected)
    config=DeliverySettings.objects.filter(pk=1).first()
    cutoff=timezone.now()-timedelta(minutes=config.ack_minutes if config else 30)
    pending=alerts.filter(acknowledged_at=None)
    state=request.GET.get('state','all')
    failures=rows.filter(status__in=('bounce','dropped','failed','uncertain'))
    waiting=rows.filter(status__in=('sending','accepted','processed','deferred'))
    totals={'failed':failures.count(),'waiting':waiting.count(),'delivered':rows.filter(status='delivered').count(),
        'overdue':waiting.filter(created_at__lt=timezone.now()-timedelta(hours=24)).count()}
    if state=='failed':rows=failures
    elif state=='waiting':rows=waiting
    elif state=='delivered':rows=rows.filter(status='delivered')
    else:state='all'
    return render(request,'delivery_status.html',{'dispatches':rows.prefetch_related('events')[:100],'alerts':pending.order_by('observed_at')[:100],
        'late_count':pending.filter(created_at__lt=cutoff).count(),'cutoff':cutoff,'config':config,
        'clients':Client.objects.all(),'selected_client':client,'state':state,'totals':totals})

def escalate_unacknowledged(now=None):
    now=now or timezone.now();config=DeliverySettings.objects.filter(pk=1).first()
    cutoff=now-timedelta(minutes=config.ack_minutes if config else 30)
    from .operations import set_issue
    overdue=UrgentAlert.objects.filter(acknowledged_at=None,created_at__lt=cutoff,created_at__gte=now-timedelta(days=7),client__active=True).exclude(status__in=('suppressed','expired'))
    ids=list(overdue.values_list('pk',flat=True)[:200])
    for alert in overdue.filter(pk__in=ids):
        # Keep this escalation internal; no second automatic email campaign.
        key='urgent-ack:'+str(alert.pk)
        set_issue(key,'Aviso urgente pendiente de atención SOC',details='Revisar Entrega y avisos; confirmar recepción y asignar investigación.',severity='critical',now=now)
    for issue in OperationalIssue.objects.filter(key__startswith='urgent-ack:',active=True):
        try:pk=int(issue.key.split(':')[1])
        except ValueError:continue
        if not overdue.filter(pk=pk).exists():
            issue.active=False;issue.resolved_at=now;issue.save(update_fields=['active','resolved_at'])

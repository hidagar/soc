"""Acknowledged, replayable delivery through a dedicated native Wazuh analysisd.

Only authenticated HTTPS traffic enters this engine. Its archive is the native
processing receipt; alert documents use create-only stable IDs in the indexer.
The main manager, its rules and Filebeat continue their existing routes.
"""
import gzip
import copy
import hashlib
import json
import os
import re
import socket
import shutil
import time
import urllib.request
from datetime import timedelta, timezone as utc
from pathlib import Path
from cryptography.fernet import InvalidToken
from django.db import transaction
from django.db.models import F,Q
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from .models import SecureLogMessage,SecureLogReceipt,WorkerState
from .security import encrypt,decrypt

ENGINE_ROOT=Path('/var/lib/soc-wazuh-https/var/ossec')
SOCKET=ENGINE_ROOT/'queue/sockets/queue'
ARCHIVES=ENGINE_ROOT/'logs/archives'
HOST_RE=re.compile(r'^sr\.(\d{13})\.([0-9a-f]{32})\.([0-9a-f]{32})$')
MONTHS=('Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec')
FRAME_LIMIT=16*1024
INDEX_PREFIX='wazuh-alerts-4.x-'

def provision_pipeline(name='soc-https-wazuh-v1'):
    """Private copy; retain precise event time and surface errors instead of drop."""
    from .indexer_admin import admin_request
    if not re.fullmatch(r'soc-https-[A-Za-z0-9_-]{1,100}',name):raise ValueError('Invalid private pipeline name')
    pipelines=admin_request('/_ingest/pipeline')
    choices=[value for key,value in pipelines.items() if key.endswith('wazuh-alerts-pipeline')]
    if len(choices)!=1:raise ValueError('Native Wazuh pipeline is ambiguous')
    pipeline=copy.deepcopy(choices[0]);pipeline.pop('on_failure',None)
    found=False
    for processor in pipeline.get('processors',[]):
        if processor.get('date_index_name',{}).get('field')=='timestamp':
            processor['date_index_name']['date_formats']=['ISO8601'];found=True
    if not found:raise ValueError('Native Wazuh pipeline has no date index processor')
    pipeline['description']='ib-red acknowledged HTTPS native alerts; explicit failures, precise timestamps'
    admin_request('/_ingest/pipeline/'+name,pipeline,method='PUT')
    return name

def uid_for(receipt,position):
    return hashlib.sha256(f'{receipt.channel_id}:{receipt.batch_id}:{receipt.digest}:{position}'.encode()).hexdigest()

def hostname(receipt,uid):
    return f'sr.{int(receipt.received_at.timestamp()*1000):013d}.{uid[:32]}.{uid[32:]}'

def reframe(line,receipt,uid):
    # Replace only the transport header, retaining the native program/message.
    # This also turns Zenarmor's ISO envelope into a header Wazuh predecodes.
    line=re.sub(r'^<\d{1,3}>','',line)
    match=re.match(r'^(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d|\d{4}-\d\d-\d\d[T ]\S+)\s+\S+\s+(.*)$',line)
    if match:body=match.group(1)
    elif line.startswith('{'):body='soc-json: '+line
    else:body='soc-relay: '+line
    # RFC5424 is not silently interpreted as RFC3164. Keep it as an opaque
    # original message until a tested adapter exists.
    stamp=receipt.received_at.astimezone(utc.utc)
    result=f'{MONTHS[stamp.month-1]} {stamp.day:2d} {stamp:%H:%M:%S} {hostname(receipt,uid)} {body}'
    if len(result.encode())>FRAME_LIMIT:raise ValueError('Frame too large')
    return result

def prepare_messages(receipt):
    lines=json.loads(decrypt(receipt.encrypted_payload))
    encoded=json.dumps(lines,ensure_ascii=False,separators=(',',':')).encode()
    if not isinstance(lines,list) or len(lines)!=receipt.messages_count or hashlib.sha256(encoded).hexdigest()!=receipt.digest:
        raise ValueError('Stored payload integrity failed')
    if any(not isinstance(line,str) or not line or len(line.encode())>8192 or
           any(ord(c)<32 and c!='\t' for c in line) or '\x7f' in line for line in lines):
        raise ValueError('Invalid stored message')
    with transaction.atomic():
        SecureLogReceipt.objects.filter(pk=receipt.pk).update(attempts=F('attempts'))
        for position,line in enumerate(lines):
            uid=uid_for(receipt,position);frame=reframe(line,receipt,uid)
            SecureLogMessage.objects.get_or_create(uid=uid,defaults={'receipt':receipt,'position':position,
                'frame_digest':hashlib.sha256(frame.encode()).hexdigest()})
    return lines

def identify(source):
    header=source.get('predecoder') or {}
    if not isinstance(header,dict):return None
    match=HOST_RE.fullmatch(str(header.get('hostname','')))
    if not match:return None
    uid=match[2]+match[3]
    row=SecureLogMessage.objects.select_related('receipt__channel__device__site').filter(pk=uid).first()
    if not row or row.receipt.transport_version!=2:return None
    if str(source.get('location',''))!=row.receipt.channel.source_identity:return None
    if header['hostname']!=hostname(row.receipt,uid):return None
    raw=source.get('full_log')
    if not isinstance(raw,str) or hashlib.sha256(raw.encode()).hexdigest()!=row.frame_digest:return None
    return row

def canonical(source,row):
    result=dict(source)
    result['id']='soc-relay-'+row.uid
    result['timestamp']=row.receipt.received_at.isoformat()
    return result

def _record_ack(source,now):
    row=identify(source)
    if not row:return False
    if row.processed_at:return True
    rule=source.get('rule') or {}
    level=rule.get('level',0) if isinstance(rule,dict) else 0
    if isinstance(level,bool) or not isinstance(level,int) or not 0<=level<=16:return False
    decoder=source.get('decoder') or {}
    name=decoder.get('name','') if isinstance(decoder,dict) else ''
    event=canonical(source,row)
    with transaction.atomic():
        SecureLogMessage.objects.filter(pk=row.pk).update(attempts=F('attempts'))
        row.refresh_from_db()
        if row.processed_at:return True
        row.processed_at=now;row.rule_level=level;row.decoder=str(name)[:120]
        row.status='processed';row.error=''
        row.next_attempt_at=None
        # Level threshold is pinned in the isolated engine configuration at 3.
        # Unknown/suppressed logs get a receipt, never an invented threat alert.
        row.encrypted_event=encrypt(json.dumps(event,ensure_ascii=False)) if level>=3 else ''
        row.save()
    return True

def read_native_receipts(paths=None,max_bytes=32*1024*1024,max_seconds=20):
    """Bounded archive reader, inode cursor, gzip rotation and fsync-before-ACK."""
    now=timezone.now();started=time.monotonic();used=accepted=0
    if paths is None:
        paths=[ARCHIVES/'archives.json']
        paths+=sorted((p for p in ARCHIVES.glob('*/*/*.json*') if p.is_file() and not p.name.endswith('.sum')),
            key=lambda p:p.stat().st_mtime,reverse=True)[:48]
    seen=set()
    for path in paths:
        path=Path(path)
        if not path.exists():continue
        stat=path.stat();identity=f'{stat.st_dev}:{stat.st_ino}'
        if identity in seen:continue
        seen.add(identity)
        key='https-archive:'+hashlib.sha256(identity.encode()).hexdigest()[:40]
        state,_=WorkerState.objects.get_or_create(name=key)
        opener=gzip.open if path.suffix=='.gz' else open
        with path.open('rb') as probe:
            head_hash=hashlib.sha256(probe.read(256)).hexdigest()
            end=stat.st_size if path.suffix=='.gz' else min(state.offset,stat.st_size)
            probe.seek(max(0,end-256));cursor_hash=hashlib.sha256(probe.read(min(256,end))).hexdigest()
        # An inode can be reused or a file truncated and filled past the old
        # offset between runs. Verify its content generation before skipping.
        if ((state.details.get('head_hash') and state.details['head_hash']!=head_hash) or
            (state.details.get('cursor_hash') and state.details['cursor_hash']!=cursor_hash)):
            state.offset=0;state.details={}
        if path.suffix!='.gz' and state.offset==stat.st_size and not state.error:continue
        if state.details.get('compressed_done') and path.suffix=='.gz' and state.details.get('file_size')==stat.st_size:continue
        offset=state.offset
        if path.suffix!='.gz' and offset>stat.st_size:offset=0
        with opener(path,'rb') as stream:
            stream.seek(offset)
            while used<max_bytes and time.monotonic()-started<max_seconds:
                start=stream.tell();line=stream.readline(1024*1024+1)
                if not line:break
                used+=len(line)
                if len(line)>1024*1024 or not line.endswith(b'\n'):
                    # Stop rather than confirming a truncated or corrupt record.
                    state.error='Archivo incompleto o demasiado grande; se conserva el cursor.';break
                try:source=json.loads(line)
                except (ValueError,UnicodeError):
                    state.error='JSON nativo no válido; se conserva el cursor.';break
                # fsync on the real native output, including a compressed file,
                # precedes committing confirmation to the durable SQL inbox.
                with path.open('rb') as durable:os.fsync(durable.fileno())
                if isinstance(source,dict):accepted+=int(_record_ack(source,now))
                state.offset=stream.tell();state.last_run_at=state.last_success_at=now;state.error=''
            with path.open('rb') as probe:
                end=stat.st_size if path.suffix=='.gz' else state.offset
                probe.seek(max(0,end-256));cursor_hash=hashlib.sha256(probe.read(min(256,end))).hexdigest()
            state.details={'head_hash':head_hash,'cursor_hash':cursor_hash,'file_size':stat.st_size,'compressed_done':path.suffix=='.gz' and not stream.peek(1) if hasattr(stream,'peek') else False}
            state.save()
        if used>=max_bytes or time.monotonic()-started>=max_seconds:break
    return accepted

def send_due(limit=256,max_seconds=60,now=None):
    from .secure_logs import active_channels
    now=now or timezone.now();started=time.monotonic();sent=0
    channels=active_channels().filter(receiver_ready=True).values_list('pk',flat=True)
    batches=SecureLogReceipt.objects.filter(channel_id__in=channels,transport_version=2,status__in=['queued','awaiting']).filter(
        Q(delivery_messages=None)|Q(delivery_messages__processed_at=None,delivery_messages__next_attempt_at=None)|
        Q(delivery_messages__processed_at=None,delivery_messages__next_attempt_at__lte=now)).distinct().order_by('received_at','pk')
    for receipt in list(batches[:limit]):
        if time.monotonic()-started>=max_seconds:break
        try:lines=prepare_messages(receipt)
        except (ValueError,TypeError,InvalidToken):
            SecureLogReceipt.objects.filter(pk=receipt.pk).update(status='failed',error='El lote no supera la comprobación de integridad.');continue
        for row in receipt.delivery_messages.filter(processed_at=None).filter(Q(next_attempt_at=None)|Q(next_attempt_at__lte=now)).order_by('position'):
            if sent>=limit or time.monotonic()-started>=max_seconds:return sent
            if row.attempts>=8:
                row.status='failed';row.error='Sin confirmación tras ocho envíos; revisar motor y archivo.';row.save();continue
            if not active_channels().filter(pk=receipt.channel_id,receiver_ready=True).exists():break
            frame=reframe(lines[row.position],receipt,row.uid)
            # A crash here is safe to retry: UID, timestamp, native receipt and
            # create-only document/evidence identities do not change.
            try:
                with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as sender:
                    sender.settimeout(1);sender.connect(str(SOCKET))
                    data=f'1:{receipt.channel.source_identity}:{frame}'.encode()
                    if sender.send(data)!=len(data):raise OSError
                row.sent_at=now;row.status='awaiting';row.error='';sent+=1
            except OSError:row.error='Motor local no disponible; mensaje conservado.'
            row.attempts+=1;row.next_attempt_at=now+timedelta(seconds=min(900,30*2**min(row.attempts-1,5)));row.save()
        SecureLogReceipt.objects.filter(pk=receipt.pk).update(status='awaiting',attempted_at=now)
    return sent

def native_bulk(rows,pipeline):
    from .indexer_tls import context as tls_context
    body=[]
    for row,source,index in rows:
        body.extend((json.dumps({'create':{'_index':index,'_id':source['id']}}),
            json.dumps({'message':json.dumps(source,ensure_ascii=False),'fields':{'index_prefix':INDEX_PREFIX}},ensure_ascii=False)))
    context=tls_context();context.load_cert_chain('/etc/wazuh-indexer/certs/admin.pem','/etc/wazuh-indexer/certs/admin-key.pem')
    request=urllib.request.Request('https://127.0.0.1:9200/_bulk?refresh=wait_for&pipeline='+pipeline,
        data=('\n'.join(body)+'\n').encode(),headers={'Content-Type':'application/x-ndjson'},method='POST')
    with urllib.request.urlopen(request,context=context,timeout=10) as response:raw=response.read(2*1024*1024+1)
    if len(raw)>2*1024*1024:raise ValueError('Oversized native bulk response')
    result=json.loads(raw);items=result.get('items')
    if not isinstance(items,list) or len(items)!=len(rows):raise ValueError('Incomplete native bulk response')
    return [item.get('create',{}).get('status') in (201,409) for item in items]

def publish_due(limit=1024,max_seconds=20):
    """Persist authentic native alerts with immutable, create-only physical IDs."""
    from .indexer_admin import admin_request
    from .operations import ingest_events,normalize
    now=timezone.now();done=0;started=time.monotonic()
    candidates=list(SecureLogMessage.objects.filter(processed_at__isnull=False,indexed_at=None,rule_level__gte=3).filter(Q(next_attempt_at=None)|Q(next_attempt_at__lte=now)).exclude(encrypted_event='').select_related('receipt__channel__device__site').order_by('processed_at','uid')[:limit])
    if not candidates:return 0
    config=json.loads((ENGINE_ROOT/'etc/soc-delivery.json').read_text());pipeline=config['pipeline']
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,180}',pipeline):raise ValueError('Invalid pipeline')
    for start in range(0,len(candidates),128):
        if time.monotonic()-started>=max_seconds:break
        batch=[]
        for row in candidates[start:start+128]:
            if row.receipt.channel.client_scope_id!=row.receipt.channel.device.site.client_id:
                SecureLogReceipt.objects.filter(pk=row.receipt_id).update(status='failed',error='El equipo cambió de cliente; revisar el lote conservado antes de publicarlo.');continue
            source=json.loads(decrypt(row.encrypted_event))
            if not identify(source) or source.get('id')!='soc-relay-'+row.uid:raise ValueError('Native event integrity failed')
            stamp=parse_datetime(source['timestamp']);index=INDEX_PREFIX+stamp.strftime('%Y.%m.%d')
            batch.append((row,source,index))
        if not batch:continue
        # Back off before network I/O, including a crash after an ambiguous success.
        SecureLogMessage.objects.filter(pk__in=[r.pk for r,_,_ in batch]).update(
            next_attempt_at=now+timedelta(seconds=60),error='Publicación pendiente de confirmar; mensaje conservado.')
        accepted=native_bulk(batch,pipeline)
        eligible=[entry for entry,ok in zip(batch,accepted) if ok]
        if not eligible:continue
        result=admin_request('/_mget',{'docs':[{'_index':index,'_id':source['id']} for _,source,index in eligible]},method='POST',timeout=5)
        documents=result.get('docs')
        if not isinstance(documents,list) or len(documents)!=len(eligible):raise ValueError('Incomplete native confirmation')
        with transaction.atomic():
            SecureLogMessage.objects.filter(pk=eligible[0][0].pk).update(attempts=F('attempts'))
            for (row,source,index),indexed in zip(eligible,documents):
                actual=indexed.get('_source') or {}
                owner=identify(actual)
                if (not indexed.get('found') or indexed.get('_id')!=source['id'] or not owner or owner.uid!=row.uid or
                    actual.get('id')!=source['id'] or parse_datetime(str(actual.get('timestamp','')))!=parse_datetime(source['timestamp']) or
                    normalize(actual)!=normalize(source)):
                    SecureLogMessage.objects.filter(pk=row.pk).update(error='El documento indexado no coincide con el mensaje confirmado.');continue
                ingest_events([actual])
                SecureLogMessage.objects.filter(pk=row.pk).update(indexed_at=timezone.now(),status='indexed',error='',next_attempt_at=None);done+=1
    return done

def finish_batches():
    count=0
    for receipt in SecureLogReceipt.objects.filter(transport_version=2,status__in=['queued','awaiting']).select_related('channel__device__site').prefetch_related('delivery_messages'):
        if receipt.channel.client_scope_id!=receipt.channel.device.site.client_id:
            receipt.status='failed';receipt.error='El equipo cambió de cliente; revisar el lote conservado.'
            receipt.save(update_fields=['status','error']);continue
        rows=list(receipt.delivery_messages.all())
        confirmed=sum(bool(r.processed_at and (r.rule_level<3 or r.indexed_at)) for r in rows)
        if len(rows)==receipt.messages_count and confirmed==receipt.messages_count:
            receipt.status='confirmed';receipt.confirmed_at=timezone.now();receipt.error='';count+=1
        elif any(r.status=='failed' for r in rows):
            receipt.status='failed';receipt.error='Hay mensajes sin confirmar; se conserva el lote.'
        receipt.forwarded_count=confirmed;receipt.save(update_fields=['status','confirmed_at','error','forwarded_count'])
    return count

def run_cycle():
    check_profile()
    read_native_receipts(max_seconds=10);publish_due();finish_batches()
    prune_logs()
    usage=shutil.disk_usage(ENGINE_ROOT)
    logs={}
    for path in (ENGINE_ROOT/'logs').rglob('*'):
        if path.is_file():
            stat=path.stat();logs[(stat.st_dev,stat.st_ino)]=stat.st_size
    if sum(logs.values())>512*1024*1024 or usage.free<max(512*1024*1024,usage.total*.15):
        raise OSError('Native log storage budget exceeded; durable inbox retained')
    sent=send_due(max_seconds=45)
    read_native_receipts(max_seconds=5);publish_due();finish_batches()
    return sent

def check_profile():
    state,_=WorkerState.objects.get_or_create(name='https-engine-profile')
    now=timezone.now()
    if state.last_success_at and now-state.last_success_at<timedelta(minutes=1):return
    config=json.loads((ENGINE_ROOT/'etc/soc-delivery.json').read_text())
    for name,key in (('wazuh-analysisd','binary_sha256'),('wazuh-db','db_sha256')):
        if hashlib.sha256(Path('/var/ossec/bin',name).read_bytes()).hexdigest()!=config[key]:
            raise ValueError('Native engine changed; verify and synchronize the private profile')
    for name,digest in config['profile_files'].items():
        if name=='etc/decoders/soc_https_json_decoder.xml':continue
        source=Path('/var/ossec')/name
        if not source.is_file() or hashlib.sha256(source.read_bytes()).hexdigest()!=digest:
            raise ValueError('Native rules changed; verify and synchronize the private profile')
    state.last_success_at=state.last_run_at=now;state.error='';state.save()

def prune_logs(now=None):
    """Only this private engine's closed logs; no main-manager archive changes."""
    now=now or timezone.now();removed=0;active_inodes=set();files={}
    for directory,stem in ((ARCHIVES,'archives'),(ENGINE_ROOT/'logs/alerts','alerts')):
        for suffix in ('json','log'):
            active=directory/f'{stem}.{suffix}'
            if active.exists():active_inodes.add((active.stat().st_dev,active.stat().st_ino))
        for path in directory.glob('*/*/*'):
            if not path.is_file() or path.is_symlink():continue
            stat=path.stat();identity=(stat.st_dev,stat.st_ino)
            if identity not in active_inodes and now.timestamp()-stat.st_mtime>86400:
                removed+=stat.st_size;path.unlink()
    return removed

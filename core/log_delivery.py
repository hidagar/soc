"""Durable inbox summaries and retained v1 UDP forwarding/recovery.

The inflight marker is committed before each network operation. A process death
between send and cursor commit is quarantined for v1. Acknowledged v2 delivery
is implemented separately in wazuh_delivery.
"""
import hashlib
import json
import socket
import time
from datetime import timedelta
from django.db import transaction
from django.db.models import Count, F, Min, Sum
from django.utils import timezone
from .models import SecureLogChannel, SecureLogReceipt
from .security import decrypt

PENDING=('queued','retry')
REVIEW=('failed','uncertain')
LEASE=timedelta(minutes=5)

def queue_summary(channel=None):
    rows=SecureLogReceipt.objects.all()
    if channel is not None:rows=rows.filter(channel=channel)
    counts={r['status']:r['n'] for r in rows.values('status').annotate(n=Count('pk'))}
    pending=rows.exclude(status__in=['forwarded','legacy','confirmed'])
    return {'pending':sum(counts.get(s,0) for s in (*PENDING,'delivering','awaiting')),
        'review':sum(counts.get(s,0) for s in REVIEW),'forwarded':counts.get('forwarded',0),
        'confirmed':counts.get('confirmed',0),
        'oldest':pending.aggregate(t=Min('received_at'))['t'],
        'bytes':pending.aggregate(n=Sum('bytes_count'))['n'] or 0}

def recover_interrupted(now=None):
    now=now or timezone.now()
    # A restarted process must not race a still-live sender; systemd's hard
    # runtime is shorter than this lease. The command also holds its job lock.
    stale=SecureLogReceipt.objects.filter(transport_version=1,status='delivering',attempted_at__lt=now-LEASE)
    ambiguous=stale.exclude(inflight_index=None).update(status='uncertain',error='Proceso interrumpido durante un envío. Revisar antes de repetir.')
    safe=stale.filter(inflight_index=None).update(status='retry',next_attempt_at=now,error='Proceso interrumpido antes del siguiente envío; reintento seguro.')
    return ambiguous+safe

def retry_reviewed(channel,receipt_id):
    if not str(receipt_id).isdigit():return False
    with transaction.atomic():
        # Reserve the writer before reading on SQLite as well as PostgreSQL.
        SecureLogChannel.objects.filter(pk=channel.pk).update(last_received_at=F('last_received_at'))
        row=SecureLogReceipt.objects.filter(pk=receipt_id,channel=channel,status__in=REVIEW).exclude(encrypted_payload='').first()
        if not row:return False
        row.status='queued';row.next_attempt_at=timezone.now();row.inflight_index=None;row.error='';row.attempts=0
        row.save(update_fields=['status','next_attempt_at','inflight_index','error','attempts'])
        if row.transport_version==2:
            row.delivery_messages.filter(processed_at=None).update(status='queued',attempts=0,next_attempt_at=None,error='')
    return True

def _claim(channel,now):
    from .secure_logs import active_channels
    with transaction.atomic():
        SecureLogChannel.objects.filter(pk=channel.pk).update(last_received_at=F('last_received_at'))
        if not active_channels().filter(pk=channel.pk,receiver_ready=True).exists():return None
        # Preserve FIFO within a channel: an ambiguous batch blocks later ones.
        row=SecureLogReceipt.objects.filter(channel=channel,transport_version=1).exclude(status__in=['legacy','forwarded']).order_by('received_at','pk').first()
        if not row or row.status not in PENDING or (row.next_attempt_at and row.next_attempt_at>now):return None
        row.status='delivering';row.attempted_at=now;row.attempts+=1;row.error=''
        row.save(update_fields=['status','attempted_at','attempts','error'])
        return row

def _fail(row,message,now,uncertain=False):
    state='uncertain' if uncertain else ('failed' if row.attempts>=8 else 'retry')
    SecureLogReceipt.objects.filter(pk=row.pk,status='delivering').update(status=state,error=message,
        next_attempt_at=now+timedelta(seconds=min(900,15*2**min(row.attempts-1,6))),
        inflight_index=row.inflight_index if uncertain else None)

def forward_batch(row,now=None):
    now=now or timezone.now()
    try:
        content=decrypt(row.encrypted_payload)
        lines=json.loads(content)
        if (not isinstance(lines,list) or len(lines)!=row.messages_count or
            not all(isinstance(line,str) and line and len(line.encode())<=8192 and
                not any(ord(c)<32 and c!='\t' for c in line) and '\x7f' not in line for line in lines) or
            hashlib.sha256(json.dumps(lines,ensure_ascii=False,separators=(',',':')).encode()).hexdigest()!=row.digest):
            raise ValueError
    except Exception:
        SecureLogReceipt.objects.filter(pk=row.pk,status='delivering').update(status='failed',error='El lote guardado no supera la comprobación de integridad.')
        return False
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sender:
            sender.bind((row.channel.source_identity,0));sender.settimeout(1)
            for index in range(row.forwarded_count,len(lines)):
                # Disable/reassignment takes effect before the next message.
                from .secure_logs import active_channels
                if not active_channels().filter(pk=row.channel_id,receiver_ready=True).exists():
                    _fail(row,'Canal desactivado o reasignado; se conserva el lote.',now);return False
                row.inflight_index=index
                SecureLogReceipt.objects.filter(pk=row.pk,status='delivering').update(inflight_index=index)
                try:
                    data=lines[index].encode('utf-8')
                    sent=sender.sendto(data,('172.20.10.20',5514))
                except OSError:
                    _fail(row,'El sistema local rechazó el envío; reintento programado.',now);return False
                if sent!=len(data):
                    _fail(row,'No se pudo confirmar el datagrama completo.',now,uncertain=True);return False
                # If the commit fails, leave the inflight marker for recovery.
                SecureLogReceipt.objects.filter(pk=row.pk,status='delivering').update(forwarded_count=index+1,inflight_index=None)
                row.forwarded_count=index+1;row.inflight_index=None
    except OSError:
        _fail(row,'Receptor local no disponible; se conserva el lote.',now);return False
    SecureLogReceipt.objects.filter(pk=row.pk,status='delivering').update(status='forwarded',forwarded_at=timezone.now(),next_attempt_at=None,error='')
    return True

def deliver_due(limit=256,now=None,max_seconds=90):
    from .secure_logs import active_channels
    now=now or timezone.now();recover_interrupted(now)
    # Round-robin batches across channels, with a hard wall-time budget. One
    # batch/minute would never keep up with the HTTP admission limit.
    channels=active_channels().filter(receiver_ready=True,securelogreceipt__status__in=PENDING).exclude(
        securelogreceipt__status__in=(*REVIEW,'delivering')).annotate(
        oldest=Min('securelogreceipt__received_at')).order_by('oldest','pk')
    sent=0;claimed=0;started=time.monotonic();channels=list(channels)
    while claimed<limit and time.monotonic()-started<max_seconds:
        progress=False
        for channel in channels:
            if claimed>=limit or time.monotonic()-started>=max_seconds:break
            row=_claim(channel,now)
            if row:
                progress=True;claimed+=1
                if forward_batch(row,now):sent+=1
        if not progress:break
    return sent

def cleanup(now=None):
    now=now or timezone.now()
    # Unsent and ambiguous payloads never expire automatically. Compact dedup
    # tombstones remain, so a long-offline relay cannot replay an old batch.
    SecureLogReceipt.objects.filter(status='forwarded',forwarded_at__lt=now-timedelta(days=7)).exclude(encrypted_payload='').update(encrypted_payload='')
    SecureLogReceipt.objects.filter(status='confirmed',confirmed_at__lt=now-timedelta(days=7)).exclude(encrypted_payload='').update(encrypted_payload='')
    from .models import SecureLogMessage
    SecureLogMessage.objects.filter(indexed_at__lt=now-timedelta(days=7)).exclude(encrypted_event='').update(encrypted_event='')
    return SecureLogReceipt.objects.filter(status='legacy',received_at__lt=now-timedelta(days=90)).delete()[0]

"""Near-real-time, customer-scoped alerts from verified Wazuh event sources."""

import hashlib
import ipaddress
import logging
import re
from datetime import timedelta, timezone as datetime_timezone
from urllib import error as url_error

from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.db import transaction
from django.db.models import F, Q
from django.template.loader import render_to_string
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from .findings import inventories_for_sources
from .mail_delivery import MailConfigurationError, MailDeliveryError, send_customer_email
from .models import Client, MailSettings, UrgentAlert, UrgentMonitorCursor
from .reporting import _search, indexer_authorization, report_sources,security_filter


OVERLAP = timedelta(minutes=15)
INDEXING_DELAY = timedelta(seconds=15)
MAX_AGE = timedelta(hours=2)
COOLDOWN = timedelta(hours=1)
PAGE_SIZE = 500
MAX_PAGES = 4
logger = logging.getLogger(__name__)


def _clean_text(value, limit):
    return re.sub(r"[\x00-\x1f\x7f]+", " ", str(value or "")).strip()[:limit]


def _ip(value):
    try:
        return str(ipaddress.ip_address(value))
    except (TypeError, ValueError):
        return None


def _event_kind(source, client):
    from .operations import normalize
    event=normalize(source)
    data = source.get("data") or {}
    unifi = data.get("unifi") or {}
    name = str(unifi.get("event_name") or "")
    category = str(unifi.get("category") or "")
    action = str(unifi.get("action") or "").lower()
    try:
        level = int((source.get("rule") or {}).get("level") or 0)
    except (ValueError, TypeError):
        level = 0
    if name == "Internet Down":
        return (UrgentAlert.Kind.AVAILABILITY, level) if client.urgent_availability_enabled else (None, level)
    if event['security'] and event['category']!='application_policy' and event['action']=='allowed':
        return UrgentAlert.Kind.SECURITY_ALLOWED, level
    if event['security'] and event['soc_priority'] in ('high','critical'):
        return UrgentAlert.Kind.SECURITY_CRITICAL,level
    if level >= 12 and category != "Audit" and event['category'] != 'application_policy':
        return UrgentAlert.Kind.SECURITY_CRITICAL, level
    return None, level


def _source_owners():
    owners = {}
    for client in Client.objects.all():
        for source in report_sources(client):
            owners[source] = client if source not in owners else None
    return owners


def _candidate_query(sources, start, end, after=None):
    query = {
        "size": PAGE_SIZE, "track_total_hits": False,
        "query": {"bool": {
            "filter": [
                {"terms": {"location": sources}},
                {"range": {"timestamp": {"gte": start.isoformat(), "lt": end.isoformat()}}},
            ],
            "should": [
                security_filter(),
                {"bool": {"filter": [
                    {"term": {"data.unifi.category": "Security"}},
                    {"term": {"data.unifi.action": "allowed"}},
                ]}},
                {"range": {"rule.level": {"gte": 12}}},
                {"term": {"data.unifi.event_name": "Internet Down"}},
            ],
            "minimum_should_match": 1,
        }},
        "sort": [{"timestamp":"asc"},{"id":{"order":"asc","unmapped_type":"keyword"}},{"_index":"asc"}],
        "_source": ['id','timestamp','location','rule','decoder','data'],
    }
    if after is not None:query["search_after"]=after
    return query


def _record_event(hit, owners, inventory_cache, now):
    source = hit.get("_source") or {}
    location = _ip(source.get("location"))
    client = owners.get(location)
    if client is None or not client.active or not client.urgent_alerts_enabled:
        return False
    recipient = client.urgent_email or client.report_email
    try:
        validate_email(recipient)
    except ValidationError:
        return False
    kind, level = _event_kind(source, client)
    if kind is None:
        return False
    raw_timestamp = source.get("timestamp")
    observed = parse_datetime(str(raw_timestamp or ""))
    if observed is None:
        return False
    if timezone.is_naive(observed):
        observed = observed.replace(tzinfo=datetime_timezone.utc)
    from .source_ownership import owns_at
    if not owns_at(location,client.pk,observed):return False
    index = str(hit.get("_index") or "")
    event_id = str(hit.get("_id") or "")
    if not index or not event_id:
        return False
    data = source.get("data") or {}
    unifi = data.get("unifi") or {}
    from .operations import normalize
    event=normalize(source)
    destination = event['affected_ip'] or event['destination_ip']
    external = event['source_ip']
    port = event['destination_port']
    signature = event['signature']
    if location not in inventory_cache:
        try:
            inventory_cache[location] = inventories_for_sources(client, [location]).get(location, {})
        except Exception:
            # An enrichment/API failure must not prevent a verified security event from being queued.
            inventory_cache[location] = {}
    inventory = inventory_cache[location]
    from .findings import _asset
    from .event_contract import snapshot
    affected=_asset(source,{location:inventory})
    asset=_clean_text(affected["name"],160)
    site=_clean_text(affected["site"],160)
    uid = hashlib.sha256(f"{index}\x00{event_id}".encode()).hexdigest()
    import json
    fingerprint = hashlib.sha256(json.dumps([client.pk,location,destination,kind,event['engine'],event['category'],event['signature'],event['action']],ensure_ascii=False).encode()).hexdigest()
    _, created = UrgentAlert.objects.get_or_create(event_uid=uid, defaults={
        "client": client, "fingerprint": fingerprint, "kind": kind,
        "status": UrgentAlert.Status.EXPIRED if now - observed > MAX_AGE else UrgentAlert.Status.PENDING,
        "observed_at": observed, "source_ip": location,
        "external_ip": external, "destination_ip": destination,
        "destination_port": port, "site_name": site, "asset_name": asset,
        "signature": signature, "action": event['action'],
        "interpretation": {**snapshot(event), "asset_confirmed":affected["confirmed"]},
        "rule_level": max(0, min(level, 65535)), "recipient": recipient,
    })
    return created


def scan_events(now=None,pages=MAX_PAGES):
    """Fixed windows and stable per-page checkpoints, independent of delivery."""
    from .indexer_results import complete,hits as checked_hits
    now=now or timezone.now()
    cursor,created=UrgentMonitorCursor.objects.get_or_create(pk=1,defaults={'last_checked_at':now})
    if created:return 0
    expected=dict(cursor.checkpoint)
    checkpoint=dict(expected)
    end=now-INDEXING_DELAY
    if not checkpoint and end<=cursor.last_checked_at:return 0
    owners=_source_owners()
    ambiguous=[s for s,c in owners.items() if c is None]
    if ambiguous:logger.warning('Fuentes ambiguas excluidas de avisos urgentes: %s',', '.join(ambiguous))
    if not checkpoint:
        sources=sorted(s for s,c in owners.items() if c is not None and c.active and c.urgent_alerts_enabled and (c.urgent_email or c.report_email))
        checkpoint={'start':(cursor.last_checked_at-OVERLAP).isoformat(),'end':end.isoformat(),'sources':sources}
    start=parse_datetime(checkpoint['start']);finish=parse_datetime(checkpoint['end'])
    if not start or not finish or start>=finish:raise ValueError('Checkpoint urgente no válido.')
    authorization=indexer_authorization() if checkpoint['sources'] else None
    recorded=0;inventory_cache={}
    for _ in range(pages):
        hits=[]
        if checkpoint['sources']:
            result=complete(_search(_candidate_query(checkpoint['sources'],start,finish,checkpoint.get('after')),authorization))
            hits=checked_hits(result)
            if len(hits)>PAGE_SIZE:raise ValueError('Página urgente excesiva.')
        after=hits[-1].get('sort') if hits else None
        if len(hits)==PAGE_SIZE and (not isinstance(after,list) or len(after)!=3 or after==checkpoint.get('after')):
            raise ValueError('Falta un cursor estable en Wazuh.')
        with transaction.atomic():
            # Reserve SQLite's writer, then compare the checkpoint. A concurrent
            # poll cannot commit a page based on an obsolete cursor.
            UrgentMonitorCursor.objects.filter(pk=1).update(last_checked_at=F('last_checked_at'))
            locked=UrgentMonitorCursor.objects.get(pk=1)
            if locked.checkpoint!=expected or locked.last_checked_at!=cursor.last_checked_at:return recorded
            for hit in hits:recorded+=int(_record_event(hit,owners,inventory_cache,now))
            if len(hits)<PAGE_SIZE:
                locked.last_checked_at=finish;locked.checkpoint={}
            else:locked.checkpoint={**checkpoint,'after':after}
            locked.save(update_fields=['last_checked_at','checkpoint'])
        if not locked.checkpoint:return recorded
        checkpoint=dict(locked.checkpoint);expected=dict(checkpoint)
    return recorded


def _message(alert):
    client = alert.client
    if alert.kind == UrgentAlert.Kind.SECURITY_ALLOWED:
        headline = "Detección de seguridad no bloqueada"
        meaning = "El firewall registró una detección cuya acción fue permitir el tráfico. Esto no confirma que se haya accedido al equipo."
        actions = [
            "Revisar los registros del equipo a la hora indicada para descartar accesos no autorizados.",
            "Confirmar con el proveedor si el servicio debe estar publicado y qué orígenes necesitan acceso.",
            "Acordar restricciones de origen o VPN sin interrumpir el servicio.",
        ]
    elif alert.kind == UrgentAlert.Kind.AVAILABILITY:
        headline = "Aviso de caída de Internet"
        meaning = "El gateway notificó una interrupción. La duración y el impacto necesitan comprobación."
        actions = [
            "Comprobar qué línea WAN se interrumpió y si entró la conexión de respaldo.",
            "Si hubo impacto o se repite, abrir incidencia con el operador y registrar la duración.",
        ]
    else:
        headline = "Evento de seguridad prioritario"
        meaning = "La política del SOC considera prioritario revisar este evento. El nivel Wazuh, la acción del motor y el impacto deben comprobarse en la evidencia."
        actions = [
            "Revisar el evento completo y los registros del equipo a la hora indicada.",
            "Confirmar si el tráfico fue bloqueado y si hay indicios de acceso no autorizado.",
        ]
    if alert.interpretation.get("contract_version"):
        from .event_contract import recommendation
        actions.insert(0,recommendation(alert.interpretation))
    action_label = {"allowed": "permitida", "blocked": "bloqueada"}.get(alert.action, "sin confirmar")
    context = {"alert": alert, "client": client, "headline": headline, "meaning": meaning,
               "actions": actions, "action_label": action_label}
    subject = f"[Centro SOC] Aviso urgente · {_clean_text(client.name, 80)} · {_clean_text(alert.asset_name, 80)}"
    return subject, render_to_string("urgent_email.txt", context), render_to_string("urgent_email.html", context)


def deliver_pending(now=None):
    now = now or timezone.now()
    stale = UrgentAlert.objects.filter(status__in=[UrgentAlert.Status.PENDING, UrgentAlert.Status.FAILED], observed_at__lt=now - MAX_AGE)
    stale.update(status=UrgentAlert.Status.EXPIRED, last_error="Aviso fuera del plazo de envío inmediato; requiere revisión interna.")
    UrgentAlert.objects.filter(status=UrgentAlert.Status.SENDING, last_attempt_at__lt=now - timedelta(minutes=5)).update(
        status=UrgentAlert.Status.UNCERTAIN, last_error="El proceso terminó durante el envío; comprobar en SendGrid antes de reenviar."
    )
    config = MailSettings.objects.filter(pk=1, enabled=True, last_test_ok=True).first()
    if config is None:
        return 0
    sent = 0
    queue = UrgentAlert.objects.filter(status__in=[UrgentAlert.Status.PENDING, UrgentAlert.Status.FAILED], attempts__lt=3).filter(
        Q(next_retry_at__isnull=True) | Q(next_retry_at__lte=now)
    ).select_related("client").order_by("observed_at", "pk")[:100]
    for alert in queue:
        client = alert.client
        recipient = client.urgent_email or client.report_email
        if not client.active or not client.urgent_alerts_enabled or (alert.kind == UrgentAlert.Kind.AVAILABILITY and not client.urgent_availability_enabled) or not recipient:
            alert.status = UrgentAlert.Status.SUPPRESSED
            alert.last_error = "El cliente desactivó este tipo de aviso o no tiene destinatario."
            alert.save(update_fields=["status", "last_error"])
            continue
        if UrgentAlert.objects.filter(client=client, fingerprint=alert.fingerprint, status__in=[UrgentAlert.Status.ACCEPTED, UrgentAlert.Status.SENDING, UrgentAlert.Status.UNCERTAIN], last_attempt_at__gte=now - COOLDOWN).exclude(pk=alert.pk).exists():
            alert.status = UrgentAlert.Status.SUPPRESSED
            alert.last_error = "Agrupado con un aviso de la última hora para evitar correos repetidos."
            alert.save(update_fields=["status", "last_error"])
            continue
        if not UrgentAlert.objects.filter(pk=alert.pk, status__in=[UrgentAlert.Status.PENDING, UrgentAlert.Status.FAILED]).update(
            status=UrgentAlert.Status.SENDING, attempts=F("attempts") + 1, last_attempt_at=now, recipient=recipient
        ):
            continue
        alert.refresh_from_db()
        subject, plain, html = _message(alert)
        try:
            message_id = send_customer_email(recipient, subject, plain, html,delivery_context={'client':client,'urgent':alert,'kind':'urgent'})
        except MailConfigurationError as exc:
            alert.status = UrgentAlert.Status.FAILED
            alert.last_error = str(exc)[:250]
            alert.next_retry_at = now + timedelta(minutes=15)
        except MailDeliveryError as exc:
            ambiguous = isinstance(exc.__cause__, (url_error.URLError, TimeoutError, OSError))
            alert.status = UrgentAlert.Status.UNCERTAIN if ambiguous else UrgentAlert.Status.FAILED
            alert.last_error = str(exc)[:250]
            alert.next_retry_at = None if ambiguous else now + timedelta(minutes=5 * alert.attempts)
        else:
            alert.status = UrgentAlert.Status.ACCEPTED
            alert.sent_at = now
            alert.provider_message_id = message_id
            alert.last_error = ""
            alert.next_retry_at = None
            sent += 1
        alert.save(update_fields=["status", "last_error", "next_retry_at", "sent_at", "provider_message_id"])
    return sent

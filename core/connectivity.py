"""Conexión a Internet por sede: caídas que notifica el propio firewall.

Comprobado con los datos reales (noviembre de 2026): UniFi envía «Internet Down», «Multiple Internet
Disconnections» y «Device Offline», pero **no la recuperación**; OPNsense no envía las alarmas de su
gateway al SOC. Por eso se registran y cuentan las caídas, sin inventar su duración ni un porcentaje de
disponibilidad.

- El trabajo `connectivity` (cada 15 minutos) lee esos eventos del índice de Wazuh desde un cursor. Una
  consulta incompleta no avanza el cursor (invariante 5) y cada evento se guarda una sola vez.
- Cada evento se asigna al cliente propietario de su origen en ese momento (`owns_at`) y, si se conoce,
  al firewall que lo envió.
- Solo los firewalls UniFi informan de caídas: los demás se muestran como «no informa», no como «sin caídas».
"""
import hashlib
from datetime import datetime, timedelta
from datetime import timezone as datetime_timezone

from django.db import IntegrityError, transaction
from django.db.models import Count, Max
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from .models import ConnectivityEvent, Device, ExportConfiguration, WorkerState

STATE = 'connectivity'
EVENTS = {'Internet Down': 'internet_down', 'Multiple Internet Disconnections': 'repeated', 'Device Offline': 'device_offline'}
INTERNET = ('internet_down', 'repeated')
BACKFILL = timedelta(days=35)
OVERLAP = timedelta(minutes=30)  # los eventos pueden indexarse con retraso: se repasa un margen (sin duplicar)
PAGE = 500
REPORTING_VENDORS = ('unifi',)


def _query(sources, start, end, after=None):
    body = {'size': PAGE, 'track_total_hits': False,
            'query': {'bool': {'filter': [{'terms': {'location': sources}},
                                          {'range': {'timestamp': {'gte': start.isoformat(), 'lt': end.isoformat()}}},
                                          {'terms': {'data.unifi.event_name': list(EVENTS)}}]}},
            'sort': [{'timestamp': 'asc'}, {'id': {'order': 'asc', 'unmapped_type': 'keyword'}}, {'_index': 'asc'}],
            '_source': ['id', 'timestamp', 'location', 'data.unifi.event_name']}
    if after is not None:
        body['search_after'] = after
    return body


def _devices_by_source():
    return dict(ExportConfiguration._base_manager.exclude(source_ip=None).values_list('source_ip', 'device_id'))


def collect(now=None, search=None):
    """Lee las caídas nuevas del índice. Devuelve cuántas se han guardado."""
    from .indexer_results import complete, hits
    from .reporting import _search, indexer_authorization
    from .source_ownership import owns_at
    from .urgent_alerts import _ip, _source_owners
    now = now or timezone.now()
    state = WorkerState.objects.filter(name=STATE).first()
    cursor = parse_datetime((state.details if state else {}).get('cursor') or '')
    start = (cursor - OVERLAP) if cursor else now - BACKFILL
    owners = {source: client for source, client in _source_owners().items() if client is not None}
    if not owners:
        return 0
    search = search or (lambda body: _search(body, indexer_authorization()))
    devices = _devices_by_source()
    saved, after = 0, None
    while True:
        rows = hits(complete(search(_query(sorted(owners), start, now, after))))
        for hit in rows:
            source = hit['_source']
            location = _ip(source.get('location'))
            client = owners.get(location)
            kind = EVENTS.get(str(((source.get('data') or {}).get('unifi') or {}).get('event_name') or ''))
            observed = parse_datetime(str(source.get('timestamp') or ''))
            if not client or not kind or not observed:
                continue
            if timezone.is_naive(observed):
                observed = observed.replace(tzinfo=datetime_timezone.utc)
            if not owns_at(location, client.pk, observed):
                continue  # el origen era de otro cliente en esa fecha (invariante 2)
            key = hashlib.sha256(f"{hit.get('_index', '')}|{hit.get('_id', '')}".encode()).hexdigest()
            try:
                with transaction.atomic():
                    ConnectivityEvent._base_manager.create(client=client, device_id=devices.get(location), kind=kind,
                                                           observed_at=observed, event_key=key)
                saved += 1
            except IntegrityError:
                continue
        if len(rows) < PAGE:
            break
        after = rows[-1].get('sort')
        if not after:
            break
    with transaction.atomic():
        WorkerState.reserve(STATE)
        WorkerState.objects.filter(name=STATE).update(details={'cursor': now.isoformat(), 'saved': saved})
    return saved


def summary(client, start, end):
    """Por firewall del cliente: caídas de Internet en el periodo, la última y si ese firewall informa de ellas."""
    devices = list(Device.objects.filter(site__client=client, active=True, site__active=True).select_related('site')
                   .order_by('site__name', 'name'))
    events = (ConnectivityEvent.objects.filter(client=client, kind__in=INTERNET, observed_at__gte=start, observed_at__lt=end)
              .values('device_id').annotate(n=Count('id'), last=Max('observed_at')))
    by_device = {row['device_id']: row for row in events}
    offline = dict(ConnectivityEvent.objects.filter(client=client, kind='device_offline', observed_at__gte=start, observed_at__lt=end)
                   .values('device_id').annotate(n=Count('id')).values_list('device_id', 'n'))
    rows = []
    for device in devices:
        item = by_device.get(device.pk, {})
        rows.append({'site': device.site.name, 'firewall': device.name, 'reports': device.vendor in REPORTING_VENDORS,
                     'outages': item.get('n', 0), 'last': item.get('last'), 'offline': offline.get(device.pk, 0)})
    unassigned = by_device.get(None)
    return {'rows': rows, 'total': sum(r['outages'] for r in rows) + (unassigned['n'] if unassigned else 0),
            'reporting': sum(1 for r in rows if r['reports']), 'firewalls': len(rows),
            'recent': list(ConnectivityEvent.objects.filter(client=client, kind__in=INTERNET, observed_at__gte=start,
                                                            observed_at__lt=end).select_related('device__site')[:10])}


def last_days(client, days=30, now=None):
    now = now or timezone.now()
    return summary(client, now - timedelta(days=days), now)


def month(client, first, following):
    start = timezone.make_aware(datetime.combine(first, datetime.min.time()))
    end = timezone.make_aware(datetime.combine(following, datetime.min.time()))
    return summary(client, start, end)

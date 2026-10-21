"""Portal del cliente: firewalls y detecciones con proyección explícita (invariante 3).

Solo se muestra a un usuario con rol `customer` de un único cliente activo que tenga
activado `customer_portal_detail_enabled`. Las plantillas reciben diccionarios con
campos permitidos, nunca modelos: nada de notas internas, recomendaciones del SOC,
identificadores de Wazuh, identidades de equipos, incidencias no publicadas, errores
de gestión ni reputación. Los campos de detección son los mismos que la proyección
sanitizada del índice Wazuh del cliente (`wazuh_scoped.document`) más el país.
"""
import ipaddress
from collections import Counter
from datetime import timedelta

from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db.models import Count, Max, Q
from django.http import Http404
from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET

from .event_contract import family
from .investigation import evidence_queryset
from .models import Device
from .protection import snapshot
from .service_development import customer_client

ACTIONS = {'blocked': 'Bloqueada', 'allowed': 'Permitida', 'unknown': 'Sin confirmar'}
FAMILIES = {'malware': 'Malware o control remoto', 'credential_theft': 'Robo de credenciales', 'phishing': 'Phishing',
            'scan': 'Escaneo o reconocimiento', 'intrusion': 'Intento de intrusión', 'system': 'Evento del sistema'}
STATUS = {'observed': ('Protegido y monitorizado', 'ok'), 'partial': ('Comprobaciones en curso', 'pending'),
          'attention': ('En revisión por el SOC', 'attention'), 'maintenance': ('En mantenimiento', 'paused'),
          'paused': ('Monitorización en pausa', 'paused')}
ENGINE_STATES = {'running': 'Activo', 'configured': 'Configurado', 'disabled': 'Desactivado', 'stopped': 'Detenido',
                 'bypass': 'En bypass', 'unknown': 'Pendiente de comprobar'}
MODES = {'ips': 'bloqueo (IPS)', 'ids': 'solo detección (IDS)'}
VENDORS = {'opnsense': 'OPNsense', 'unifi': 'UniFi', 'hillstone': 'Hillstone', 'grandstream_gcc': 'Grandstream GCC'}
FIELDS = ('uid', 'observed_at', 'device__name', 'device__site__name', 'engine', 'category', 'signature', 'action',
          'source_ip', 'destination_ip', 'destination_port', 'geography', 'interpretation')
PAGE = 25


def wazuh_ready(client):
    """El panel Wazuh del cliente solo se enlaza si su rol y aislamiento están verificados."""
    from .wazuh_scoped import binding_ready
    return binding_ready(client.pk)


def portal_client(request):
    client = customer_client(request)
    if not client.customer_portal_detail_enabled:
        raise Http404
    return client


def _public(ip):
    try:
        return bool(ip) and ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def detection_row(row):
    """Una detección tal como la ve el cliente: solo campos permitidos, en español."""
    geo = row['geography'] if isinstance(row['geography'], dict) else {}
    kind = (row['interpretation'] or {}).get('event_family') if isinstance(row['interpretation'], dict) else None
    kind = kind or family({'category': row['category'], 'signature': row['signature'], 'engine': row['engine'], 'security': True})
    inbound = geo.get('direction') == 'inbound'
    return {'observed_at': row['observed_at'], 'firewall': row['device__name'], 'site': row['device__site__name'],
            'signature': row['signature'], 'category': row['category'], 'family': FAMILIES.get(kind, FAMILIES['intrusion']),
            'action': row['action'] if row['action'] in ACTIONS else 'unknown',
            'action_label': ACTIONS.get(row['action'], ACTIONS['unknown']),
            'source': row['source_ip'] or '', 'destination': row['destination_ip'] or '',
            'port': row['destination_port'], 'country': geo.get('country', '') if inbound and geo.get('status') == 'located' else ''}


def firewall_rows(client, now=None):
    """Estado de cada firewall activo del cliente, sin textos internos del SOC."""
    now = now or timezone.now()
    devices = (Device.objects.filter(site__client=client, active=True, site__active=True)
               .select_related('site__client', 'health', 'protection_policy').prefetch_related('feeds')
               .order_by('site__name', 'name'))
    week = evidence_queryset(client, 7)
    counts = {row['device_id']: row for row in week.values('device_id').annotate(
        total=Count('uid'), blocked=Count('uid', filter=Q(action='blocked')), allowed=Count('uid', filter=Q(action='allowed')))}
    rows = []
    for device in devices:
        item = snapshot(device, now)
        label, css = STATUS[item['status']]
        health = item['health']
        silent = any(gap['code'] == 'silence' for gap in item['gaps'])
        rows.append({
            'name': device.name, 'site': device.site.name, 'vendor': VENDORS.get(device.vendor, device.get_vendor_display()),
            'model': device.model, 'version': device.software_version, 'status': label, 'status_class': css,
            'last_log_at': health.last_log_at if health else None, 'silent': silent,
            'engines': [{'name': c['name'], 'state': ENGINE_STATES.get(c['state'], ENGINE_STATES['unknown']),
                         'ok': c['state'] in ('running', 'configured'), 'mode': MODES.get(c['mode'], '') if c['current'] else ''}
                        for c in item['controls']],
            'checked_at': health.protection_checked_at if health else None,
            'updates': item['firmware'].get('updates_available') is True and item['current'],
            'week': counts.get(device.pk, {'total': 0, 'blocked': 0, 'allowed': 0}),
        })
    return rows


def detection_summary(qs, days, now=None):
    now = now or timezone.now()
    totals = qs.aggregate(total=Count('uid'), blocked=Count('uid', filter=Q(action='blocked')),
                          allowed=Count('uid', filter=Q(action='allowed')), last=Max('observed_at'))
    totals['unknown'] = totals['total'] - totals['blocked'] - totals['allowed']
    days_count = Counter()
    families, signatures, countries, origins, firewalls = Counter(), Counter(), Counter(), Counter(), Counter()
    signature_actions = {}
    for row in qs.values(*FIELDS).order_by().iterator(chunk_size=2000):
        item = detection_row(row)
        days_count[timezone.localtime(item['observed_at']).date()] += 1
        families[item['family']] += 1
        signatures[item['signature']] += 1
        signature_actions.setdefault(item['signature'], Counter())[item['action']] += 1
        firewalls[item['firewall']] += 1
        if item['country']:
            countries[item['country']] += 1
            if _public(item['source']):
                origins[item['source']] += 1
    today = timezone.localtime(now).date()
    timeline = [{'date': today - timedelta(days=offset), 'count': days_count[today - timedelta(days=offset)]}
                for offset in range(days - 1, -1, -1)]
    peak = max([day['count'] for day in timeline] + [1])
    for day in timeline:
        day['height'] = max(2, round(100 * day['count'] / peak)) if day['count'] else 0
    return {'totals': totals, 'timeline': timeline, 'families': families.most_common(),
            'signatures': [{'signature': name, 'count': count, 'blocked': signature_actions[name]['blocked'],
                            'allowed': signature_actions[name]['allowed']} for name, count in signatures.most_common(10)],
            'countries': countries.most_common(10), 'origins': origins.most_common(10), 'firewalls': firewalls.most_common()}


def _selection(request):
    raw = request.GET.get('days', '7')
    days = int(raw) if raw in ('1', '7', '30') else 7
    action = request.GET.get('action', 'all')
    if action not in ('all', *ACTIONS):
        action = 'all'
    return days, action


@login_required
@never_cache
@require_GET
def firewalls(request):
    client = portal_client(request)
    rows = firewall_rows(client)
    return render(request, 'customer_firewalls.html', {'client': client, 'rows': rows, 'portal_section': 'firewalls',
                                                       'wazuh_ready': wazuh_ready(client),
                                                       'attention': sum(r['status_class'] == 'attention' for r in rows)})


@login_required
@never_cache
@require_GET
def detections(request):
    client = portal_client(request)
    days, action = _selection(request)
    qs = evidence_queryset(client, days)
    names = list(Device.objects.filter(site__client=client).order_by('name').values_list('name', flat=True).distinct())
    firewall = request.GET.get('firewall', '')
    if firewall:
        if firewall not in names:
            raise Http404
        qs = qs.filter(device__name=firewall)
    summary = detection_summary(qs, days)
    listed = qs.filter(action=action) if action != 'all' else qs
    page = Paginator(listed.values(*FIELDS).order_by('-observed_at', 'uid'), PAGE).get_page(request.GET.get('page'))
    page.object_list = [detection_row(row) for row in page.object_list]
    params = request.GET.copy()
    params.pop('page', None)
    return render(request, 'customer_detections.html', {
        'client': client, 'days': days, 'action': action, 'actions': ACTIONS, 'firewall': firewall, 'firewalls': names,
        'summary': summary, 'page': page, 'query': params.urlencode(), 'portal_section': 'detections',
        'wazuh_ready': wazuh_ready(client)})

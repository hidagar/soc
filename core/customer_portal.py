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
from django.db.models.fields.json import KT
from django.db.models.functions import Length, TruncDate
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


def portal_links(client, preview=False):
    """Direcciones del portal: las del cliente o, en la vista previa del SOC, las de solo lectura."""
    from django.urls import reverse
    if preview:
        return {'preview': True, 'home': reverse('customer_preview', args=[client.pk]),
                'firewalls': reverse('customer_preview_firewalls', args=[client.pk]),
                'detections': reverse('customer_preview_detections', args=[client.pk]),
                'map': reverse('customer_preview_map', args=[client.pk]),
                'map_data': reverse('customer_preview_map_data', args=[client.pk]),
                'reports': reverse('customer_preview_reports', args=[client.pk]),
                'tasks': reverse('customer_preview_tasks', args=[client.pk]),
                'index': reverse('customer_preview_index', args=[client.pk]),
                'vulnerabilities': reverse('customer_preview_vulnerabilities', args=[client.pk]),
                'requests': reverse('customer_preview_requests', args=[client.pk]),
                'policies': reverse('customer_preview_policies', args=[client.pk]),
                'endpoints': reverse('customer_preview_endpoints', args=[client.pk]),
                'help': reverse('customer_preview_help', args=[client.pk])}
    return {'preview': False, 'home': reverse('customer_home'), 'firewalls': reverse('customer_firewalls'),
            'detections': reverse('customer_detections'), 'map': reverse('customer_map'),
            'map_data': reverse('customer_map_data'), 'reports': reverse('customer_reports'),
            'tasks': reverse('customer_tasks'), 'index': reverse('customer_index'),
            'vulnerabilities': reverse('customer_vulnerabilities'), 'requests': reverse('customer_requests'),
            'policies': reverse('customer_policies'), 'endpoints': reverse('customer_endpoints'), 'help': reverse('customer_help')}


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


# Reputación de los orígenes que ve el cliente (proyección explícita, invariante 3): solo estas etiquetas, nunca
# escenarios, comportamientos, listas concretas, otros clientes ni cifras de otros clientes.
REPUTATION = {
    'crowdsec': ('Maliciosa según CrowdSec', 'warn'),
    'listed': ('En listas de bloqueo de CrowdSec', 'warn'),
    'suspicious': ('Sospechosa según CrowdSec', 'info'),
    'qfeeds': ('En listas de amenazas de Q-Feeds', 'warn'),
    'soc': ('Ataca también a otras empresas del servicio', 'warn'),
    'noise': ('Escaneo masivo de Internet', 'muted'),
}


def reputation_labels(client, ips, now=None):
    """{IP: [(etiqueta, tono)]} con datos vigentes del SOC. Una IP marcada como posible falso positivo por la CTI no
    lleva etiquetas de CrowdSec. Estar en una lista es contexto: no prueba un ataque dirigido ni un compromiso."""
    from .models import IpReputation, SocReputation, ThreatIntelMatch
    from .reputation import TTL
    from .soc_reputation import BLOCKABLE
    now = now or timezone.now()
    ips = sorted({ip for ip in ips if _public(ip)})
    found = {ip: [] for ip in ips}
    if not ips:
        return {}
    for row in IpReputation.objects.filter(ip__in=ips):
        if row.cti_found and row.false_positives:
            continue
        cti = bool(row.cti_found and row.cti_checked_at and now - row.cti_checked_at <= TTL)
        if cti and row.reputation == 'malicious':
            found[row.ip].append('crowdsec')
        elif row.listed and row.lists_checked_at and now - row.lists_checked_at <= timedelta(hours=24):
            found[row.ip].append('listed')
        elif cti and row.reputation == 'suspicious':
            found[row.ip].append('suspicious')
        if cti and row.background_noise == 'high':
            found[row.ip].append('noise')
    for ip in ThreatIntelMatch.objects.filter(client=client, role='source', ip__in=ips).values_list('ip', flat=True):
        found[ip].append('qfeeds')
    for ip in SocReputation.objects.filter(ip__in=ips, level__in=BLOCKABLE,
                                           updated_at__gte=now - timedelta(hours=2)).values_list('ip', flat=True):
        found[ip].append('soc')
    return {ip: [REPUTATION[code] for code in codes] for ip, codes in found.items() if codes}


def firewall_rows(client, now=None):
    """Estado de cada firewall activo del cliente, sin textos internos del SOC."""
    now = now or timezone.now()
    devices = (Device.objects.filter(site__client=client, active=True, site__active=True)
               .select_related('site__client', 'health', 'protection_policy', 'attribution_catalog', 'zenarmor_export_request')
               .prefetch_related('feeds')
               .order_by('site__name', 'name'))
    week = evidence_queryset(client, 7)
    counts = {row['device_id']: row for row in week.values('device_id').annotate(
        total=Count('uid'), blocked=Count('uid', filter=Q(action='blocked')), allowed=Count('uid', filter=Q(action='allowed')))}
    rows = []
    for device in devices:
        item = snapshot(device, now, incidents=False)  # el cliente no ve los casos internos vinculados
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


def _family(kind, category, signature, engine):
    kind = kind or family({'category': category, 'signature': signature, 'engine': engine, 'security': True})
    return FAMILIES.get(kind, FAMILIES['intrusion'])


def _top(rows, limit, name, count='n', keep=None):
    """Los `limit` primeros de filas ya ordenadas por recuento descendente; los empates se
    resuelven en Python por nombre, igual en SQLite y PostgreSQL (inet y colaciones ordenan distinto)."""
    chosen = []
    for row in rows:
        if limit and len(chosen) >= limit and row[count] < chosen[limit - 1][count]:
            break
        if keep is None or keep(row):
            chosen.append(row)
    chosen.sort(key=lambda row: (-row[count], str(row[name])))
    return chosen[:limit] if limit else chosen


def detection_summary(qs, days, now=None):
    """Resumen del periodo con agregados en la base de datos: no recorre cada detección en Python.

    Mismo resultado que aplicar `detection_row` a cada fila (familia, país de origen solo si es
    entrante y está ubicado, orígenes públicos); los empates se ordenan por nombre.
    """
    now = now or timezone.now()
    qs = qs.order_by()
    totals = qs.aggregate(total=Count('uid'), blocked=Count('uid', filter=Q(action='blocked')),
                          allowed=Count('uid', filter=Q(action='allowed')), last=Max('observed_at'))
    totals['unknown'] = totals['total'] - totals['blocked'] - totals['allowed']
    # TruncDate usa la zona horaria activa (Europe/Madrid), igual que timezone.localtime.
    days_count = {row['day']: row['n'] for row in qs.annotate(day=TruncDate('observed_at')).values('day').annotate(n=Count('uid'))}
    families = Counter()
    for row in qs.values('category', 'signature', 'engine', kind=KT('interpretation__event_family')).annotate(n=Count('uid')):
        families[_family(row['kind'], row['category'], row['signature'], row['engine'])] += row['n']
    signatures = _top(qs.values('signature').annotate(
        count=Count('uid'), blocked=Count('uid', filter=Q(action='blocked')),
        allowed=Count('uid', filter=Q(action='allowed'))).order_by('-count').iterator(chunk_size=500), 10, 'signature', 'count')
    firewalls = [(row['device__name'], row['n']) for row in
                 _top(qs.values('device__name').annotate(n=Count('uid')).order_by('-n'), None, 'device__name')]
    # Las comparaciones usan las búsquedas JSON de Django (KT = valor exacto falla en SQLite).
    located = qs.filter(geography__direction='inbound', geography__status='located').annotate(
        country=KT('geography__country')).annotate(country_length=Length('country')).filter(country_length__gt=0)
    countries = [(row['country'], row['n']) for row in
                 _top(located.values('country').annotate(n=Count('uid')).order_by('-n'), 10, 'country')]
    origins = [(row['source_ip'], row['n']) for row in
               _top(located.values('source_ip').annotate(n=Count('uid')).order_by('-n').iterator(chunk_size=500), 10,
                    'source_ip', keep=lambda row: _public(row['source_ip']))]
    today = timezone.localtime(now).date()
    timeline = [{'date': today - timedelta(days=offset), 'count': days_count.get(today - timedelta(days=offset), 0)}
                for offset in range(days, -1, -1)]  # incluye el día parcial en que empieza la ventana
    peak = max([day['count'] for day in timeline] + [1])
    for day in timeline:
        day['height'] = max(2, round(100 * day['count'] / peak)) if day['count'] else 0
    return {'totals': totals, 'timeline': timeline, 'families': sorted(families.items(), key=lambda item: (-item[1], item[0])),
            'signatures': signatures, 'countries': countries, 'origins': origins, 'firewalls': firewalls}


def _selection(request):
    raw = request.GET.get('days', '7')
    days = int(raw) if raw in ('1', '7', '30') else 7
    action = request.GET.get('action', 'all')
    if action not in ('all', *ACTIONS):
        action = 'all'
    return days, action


def firewalls_context(client, preview=False):
    from .blocklist_efficacy import client_protection
    rows = firewall_rows(client)
    return {'client': client, 'rows': rows, 'portal_section': 'firewalls', 'wazuh_ready': wazuh_ready(client),
            'proactive': client_protection(client),
            'portal': portal_links(client, preview), 'attention': sum(r['status_class'] == 'attention' for r in rows)}


@login_required
@never_cache
@require_GET
def firewalls(request):
    return render(request, 'customer_firewalls.html', firewalls_context(portal_client(request)))


@login_required
@never_cache
@require_GET
def detections(request):
    return render(request, 'customer_detections.html', detections_context(request, portal_client(request)))


def detections_context(request, client, preview=False):
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
    labels = reputation_labels(client, [d['source'] for d in page.object_list] + [ip for ip, _ in summary['origins']])
    for row in page.object_list:
        row['reputation'] = labels.get(row['source'], [])
    summary['origins'] = [(ip, count, labels.get(ip, [])) for ip, count in summary['origins']]
    params = request.GET.copy()
    params.pop('page', None)
    return {'client': client, 'days': days, 'action': action, 'actions': ACTIONS, 'firewall': firewall, 'firewalls': names,
            'summary': summary, 'page': page, 'query': params.urlencode(), 'portal_section': 'detections',
            'wazuh_ready': wazuh_ready(client), 'portal': portal_links(client, preview)}

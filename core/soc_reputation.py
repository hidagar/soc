"""Reputación propia del SOC (observación): IPs que atacan a varios clientes, con los datos de todos.

Cada hora (trabajo `soc_reputation`) se agrupan las detecciones de los últimos 30 días por IP de origen
y cliente, con el propietario histórico de la evidencia igual al cliente actual del equipo:
- **Propia**: ataques a varios clientes en días distintos: 2 o más clientes con intrusión, robo de
  credenciales, malware o phishing, o 3 o más clientes con cualquier tipo (también escaneos).
- **Confirmada**: lo anterior y además CrowdSec (listas o CTI) o Q-Feeds la tienen.
- **En observación**: ataca a 2 o más clientes sin llegar a lo anterior, lleva 14 días sin actividad o la
  CTI la marca como ruido de fondo o posible falso positivo.
Frenos: solo IPs públicas que no sean de clientes ni del SOC ni excepciones (`protected_addresses`); un
cliente solo cuenta si hay tráfico no UDP (el origen UDP se puede falsificar); un mínimo de detecciones.

Esta fase no distribuye nada. Mide si la lista habría protegido: cuando una IP alcanza un nivel
bloqueable se anotan la fecha y los clientes atacados, y después los clientes nuevos a los que ataca.
Atacar a varios clientes no acredita un compromiso (invariante 4). Las IPs son datos personales: uso
interno del SOC para proteger a sus clientes, sin compartirlas fuera.
"""
import ipaddress
from collections import defaultdict
from datetime import timedelta

from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.db.models import Count, F, Max, Min, Q
from django.db.models.functions import TruncDate
from django.http import HttpResponseForbidden
from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET

from .models import IpReputation, SecurityEvidence, SocReputation, ThreatIndicator, WorkerState

STATE = 'soc-reputation'
WINDOW = timedelta(days=30)
ACTIVE = timedelta(days=14)
LISTS_FRESH = timedelta(hours=24)
MIN_EVENTS = 3
MAX_ROWS = 5000
CHUNK = 1000
STRONG = ('intrusion', 'credential_theft', 'malware', 'phishing')
FAMILIES = {'intrusion': 'Intrusión', 'credential_theft': 'Robo de credenciales', 'malware': 'Malware',
            'phishing': 'Phishing', 'scan': 'Escaneo'}
SOURCES = {'crowdsec': 'Listas de CrowdSec', 'cti': 'CTI de CrowdSec', 'qfeeds': 'Q-Feeds'}
BLOCKABLE = ('confirmed', 'own')


def _chunks(items):
    items = sorted(items)
    for start in range(0, len(items), CHUNK):
        yield items[start:start + CHUNK]


def external(ips, now):
    """({ip: fuentes externas que la tienen}, {ips ruidosas según la CTI}) con datos vigentes y locales."""
    from .reputation import TTL
    from .threat_intel import _network_index, _networks_for, usable_feeds
    found, noisy = defaultdict(set), set()
    for batch in _chunks(ips):
        for ip, listed, lists_at, cti, verdict, cti_at, noise, fps in IpReputation.objects.filter(ip__in=batch).values_list(
                'ip', 'listed', 'lists_checked_at', 'cti_found', 'reputation', 'cti_checked_at', 'background_noise', 'false_positives'):
            if listed and lists_at and lists_at >= now - LISTS_FRESH:
                found[ip].add('crowdsec')
            if cti and verdict == 'malicious' and cti_at and cti_at >= now - TTL:
                found[ip].add('cti')
            if cti and (noise == 'high' or fps):
                noisy.add(ip)
    feeds = usable_feeds(now=now)
    if feeds:
        for batch in _chunks(ips):
            for ip in ThreatIndicator.objects.filter(feed__in=feeds, kind='ip', value__in=batch).values_list('value', flat=True):
                found[ip].add('qfeeds')
        networks = _network_index(feeds)
        if networks:
            for ip in ips:
                if _networks_for(ipaddress.ip_address(ip), networks):
                    found[ip].add('qfeeds')
    return found, noisy


def classify(item, sources, noisy, now):
    """(nivel, nota) de una IP que ataca a 2 o más clientes."""
    blockable = item['days'] >= 2 and (item['strong_clients'] >= 2 or item['clients'] >= 3)
    if not blockable:
        return 'watch', ''
    if item['last'] < now - ACTIVE:
        return 'watch', 'Sin actividad en los últimos 14 días.'
    if noisy:
        return 'watch', 'Ruido de fondo o posible falso positivo según la CTI.'
    return ('confirmed' if sources else 'own'), ''


def score(item, sources):
    return (item['clients'] * 10 + item['strong_clients'] * 10 + item['days'] * 2 + min(item['allowed'], 50) // 5
            + (15 if sources else 0))


def refresh(now=None):
    """Recalcula la reputación propia. Devuelve el número de IPs con nivel bloqueable."""
    from .reputation import protected_addresses
    now = now or timezone.now()
    base = (SecurityEvidence._base_manager
            .filter(observed_at__gte=now - WINDOW, observed_at__lte=now, client_scope_id__isnull=False,
                    client_scope_id=F('device__site__client_id'))
            .exclude(category='application_policy').exclude(source_ip=None))
    per_ip = defaultdict(dict)
    for row in (base.order_by().values('source_ip', 'client_scope_id')
                .annotate(events=Count('uid'), udp=Count('uid', filter=Q(flow__protocol='UDP')),
                          strong=Count('uid', filter=Q(interpretation__event_family__in=STRONG)),
                          allowed=Count('uid', filter=Q(action='allowed')), first=Min('observed_at'), last=Max('observed_at'))):
        if row['events'] > row['udp']:  # un cliente solo cuenta con tráfico no UDP
            per_ip[row['source_ip']][row['client_scope_id']] = row
    protected = protected_addresses()
    candidates = {}
    for ip, clients in per_ip.items():
        if len(clients) < 2 or sum(r['events'] - r['udp'] for r in clients.values()) < MIN_EVENTS:
            continue
        try:
            if not ipaddress.ip_address(ip).is_global or ip in protected:
                continue
        except ValueError:
            continue
        candidates[ip] = clients
    days, families = {}, defaultdict(set)
    for batch in _chunks(candidates):
        rows = base.filter(source_ip__in=batch).order_by()
        days.update(rows.values('source_ip').annotate(n=Count(TruncDate('observed_at'), distinct=True)).values_list('source_ip', 'n'))
        for ip, family in rows.values_list('source_ip', 'interpretation__event_family').distinct():
            if family in FAMILIES:
                families[ip].add(family)
    found, noisy = external(candidates, now)
    previous = {r.ip: r for r in SocReputation.objects.all()}
    result = []
    for ip, clients in candidates.items():
        item = {'clients': len(clients), 'strong_clients': sum(1 for r in clients.values() if r['strong']),
                'days': days.get(ip, 0), 'events': sum(r['events'] for r in clients.values()),
                'allowed': sum(r['allowed'] for r in clients.values()),
                'first': min(r['first'] for r in clients.values()), 'last': max(r['last'] for r in clients.values())}
        sources = sorted(found.get(ip, ()))
        level, note = classify(item, sources, ip in noisy, now)
        old = previous.get(ip)
        flagged_at = old.flagged_at if old else None
        flagged_clients = list(old.flagged_clients) if old else []
        later = set(old.later_clients) if old else set()
        if level in BLOCKABLE and not flagged_at:
            flagged_at, flagged_clients = now, sorted(clients)
        if flagged_at:
            # Un cliente del periodo actual que no estaba al marcarla solo puede haber sido atacado después.
            later |= set(clients) - set(flagged_clients)
        result.append(SocReputation(ip=ip, level=level, score=score(item, sources), clients=item['clients'],
                                    strong_clients=item['strong_clients'], days=item['days'], events=item['events'],
                                    allowed=item['allowed'], families=sorted(families.get(ip, ())), sources=sources, note=note,
                                    first_seen=item['first'], last_seen=item['last'], flagged_at=flagged_at,
                                    flagged_clients=flagged_clients, later_clients=sorted(later), updated_at=now))
    result.sort(key=lambda r: (-r.score, r.ip))
    result = result[:MAX_ROWS]
    counts = {level: sum(1 for r in result if r.level == level) for level, _ in SocReputation.LEVELS}
    with transaction.atomic():
        WorkerState.reserve(STATE)
        SocReputation.objects.all().delete()
        SocReputation.objects.bulk_create(result)
        WorkerState.objects.filter(name=STATE).update(details={'at': now.isoformat(), 'counts': counts})
    return counts['confirmed'] + counts['own']


def lookup(ip):
    return SocReputation.objects.filter(ip=ip).first()


def describe(row):
    row.family_labels = [FAMILIES[f] for f in row.families if f in FAMILIES]
    row.source_labels = [SOURCES.get(s, s) for s in row.sources]
    return row


@login_required
@never_cache
@require_GET
def overview(request):
    from .blocklist import global_access
    if not request.user.has_perm('core.manage_operations') or not global_access(request.user):
        return HttpResponseForbidden('Requiere permiso de operaciones y acceso a todos los clientes.')
    from django.utils.dateparse import parse_datetime
    from .investigation import ip_url
    state = WorkerState.objects.filter(name=STATE).first()
    details = state.details if state else {}
    level = request.GET.get('nivel', 'blockable')
    if level not in ('blockable', 'confirmed', 'own', 'watch', 'all'):
        level = 'blockable'
    rows = SocReputation.objects.all()
    flagged = [r for r in rows.exclude(flagged_at=None).only('flagged_at', 'later_clients')]
    mature = [r for r in flagged if r.flagged_at <= timezone.now() - timedelta(days=1)]
    shown = rows.filter(level__in=BLOCKABLE) if level == 'blockable' else rows if level == 'all' else rows.filter(level=level)
    table = [describe(r) for r in shown[:200]]
    for row in table:
        row.url = ip_url(row.ip)
    counts = details.get('counts') or {}
    return render(request, 'soc_reputation.html', {
        'at': parse_datetime(details.get('at') or ''), 'counts': counts, 'blockable': counts.get('confirmed', 0) + counts.get('own', 0),
        'level': level, 'rows': table, 'total_shown': shown.count(),
        'flagged': len(mature), 'predicted': sum(1 for r in mature if r.later_clients),
        'predicted_pct': round(100 * sum(1 for r in mature if r.later_clients) / len(mature)) if mature else None})

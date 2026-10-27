"""Listas de bloqueo del SOC para los firewalls de cada cliente (hoja de ruta 7A/C2, fase 1).

El SOC hace de puente entre CrowdSec y los firewalls, con frenos:
- Solo entran IPs que han atacado a algún cliente del SOC en los últimos 7 días y que
  CrowdSec tiene en una lista (dato de menos de 24 h) o califica de maliciosas en la CTI
  (dato vigente). Nunca ruido de fondo, posibles falsos positivos, IPs no públicas, IPs
  de clientes o del SOC, ni las excepciones del cliente. Con un máximo de entradas.
- Observación: sin tocar el firewall, se calcula qué habría bloqueado con las detecciones
  reales del cliente.
- El firewall descarga la lista con un token propio del cliente. El freno de emergencia
  sirve una lista vacía. La regla de bloqueo se crea con el control de cambios (borrador
  desactivado, aprobación, savepoint y reversión), nunca desde esta página directamente.

Fase 2: el SOC orquesta también decisiones propias, siempre con las mismas excepciones:
- Bloqueos manuales del analista (`ManualBlock`): IP o red pública acotada, motivo y caducidad.
- Atacantes detectados por el motor CrowdSec del propio SOC (opcional por cliente).
- Lista de salida (C2): destinos a los que los equipos del cliente no deben conectarse, con su
  propia URL y plantilla (regla de salida en WAN). Fuentes: bloqueos manuales de salida y destinos
  de detecciones salientes de malware/control remoto que se repiten (2 días o 2 clientes). Por
  privacidad no se consulta a CrowdSec por destinos de conexiones salientes (docs/security.md).
"""
import hashlib
import hmac
import ipaddress
import os
import secrets
from datetime import timedelta

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.db.models import Count, Q
from django.db.models.functions import TruncDate
from django.http import Http404, HttpResponse, HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET, require_http_methods

from .models import BlocklistFeed, ChangePlan, Client, Device, IpReputation, ManualBlock, SecurityEvidence, WorkerState
from .reputation import TTL, protected_addresses
from .security import audit, decrypt, encrypt

WINDOW = timedelta(days=7)
LISTS_FRESH = timedelta(hours=24)
FEED_MAX_AGE = timedelta(hours=24)  # una lista sin recalcular más tiempo se sirve vacía (estado seguro)
FETCH_STALE = timedelta(hours=2)
MAX_ALLOWLIST = 200
TEMPLATE = 'crowdsec'
TEMPLATE_OUT = 'crowdsec_out'
TEMPLATES = (TEMPLATE, TEMPLATE_OUT)
TITLE_OUT = 'Bloqueo de salida (C2) del SOC'
C2_MIN_DAYS = 2      # un destino visto un solo día en un solo cliente puede ser un falso positivo de firma
C2_MIN_CLIENTS = 2
MANUAL_MAX_DAYS = 90
MANUAL_LIMIT = 500  # bloqueos manuales vigentes por alcance
MIN_PREFIX = {4: 24, 6: 48}  # una red más amplia bloquearía a demasiada gente por error
SOC_STATE = 'soc-detections'
SOC_STALE = timedelta(hours=1)  # si el motor no responde, la última lectura vale una hora
SOC_LIMIT = 5000
TITLE = 'Bloqueo CrowdSec del SOC'
VERSION = '1.0'


def parse_allowlist(text):
    """Excepciones del cliente: IPs o redes CIDR, una por línea. ValueError si alguna no es válida."""
    networks = []
    for line in (text or '').splitlines():
        value = line.split('#', 1)[0].strip()
        if not value:
            continue
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError:
            raise ValueError(f'Excepción no válida: {value[:60]}') from None
    if len(networks) > MAX_ALLOWLIST:
        raise ValueError(f'Como máximo {MAX_ALLOWLIST} excepciones.')
    return networks


def parse_manual(value):
    """Red de un bloqueo manual: pública y no más amplia que /24 (IPv4) o /48 (IPv6)."""
    try:
        network = ipaddress.ip_network((value or '').strip(), strict=False)
    except ValueError:
        raise ValueError('Indica una IP o una red CIDR válida.') from None
    if not network.is_global:
        raise ValueError('Solo se pueden bloquear direcciones públicas.')
    if network.prefixlen < MIN_PREFIX[network.version]:
        raise ValueError(f'Red demasiado amplia: como máximo /{MIN_PREFIX[4]} en IPv4 y /{MIN_PREFIX[6]} en IPv6.')
    return network


def _label(network):
    """IP sola si es una dirección; CIDR si es una red. Es lo que descarga el firewall."""
    return str(network.network_address) if network.num_addresses == 1 else str(network)


def conflict(network, allow, protected):
    """Motivo por el que no se puede bloquear esa red; '' si se puede."""
    if any(network.version == item.version and network.overlaps(item) for item in allow):
        return 'coincide con una excepción del cliente'
    if any(network.version == item.version and network.overlaps(item) for item in getattr(protected, 'networks', [])):
        return 'coincide con una excepción de un cliente'
    if network.num_addresses == 1:
        if str(network.network_address) in protected:
            return 'es una IP de un cliente o del SOC'
    elif any(address.version == network.version and address in network
             for address in (ipaddress.ip_address(ip) for ip in protected)):
        return 'contiene una IP de un cliente o del SOC'
    return ''


def active_manual(client, now, direction=None):
    """Bloqueos manuales vigentes que afectan a un cliente: los suyos y los de todos los clientes.

    `direction` 'in' o 'out' filtra los que aplican a esa lista ('both' aplica a las dos).
    """
    rows = ManualBlock._base_manager.filter(Q(client=client) | Q(client=None), revoked_at=None, expires_at__gt=now)
    if direction:
        rows = rows.filter(direction__in=(direction, 'both'))
    return rows.order_by('created_at', 'pk')


def manual_entries(feed, now, allow, protected, direction):
    """Entradas de los bloqueos manuales de una dirección y las redes que cubren."""
    manual, covered = [], []
    for block in active_manual(feed.client, now, direction):
        network = ipaddress.ip_network(block.network, strict=False)
        if conflict(network, allow, protected) or any(network.subnet_of(n) for n in covered if n.version == network.version):
            continue
        covered.append(network)
        manual.append({'ip': _label(network), 'reasons': ['Bloqueo manual: ' + block.reason[:80]], 'manual': block.pk,
                       'scope': 'todos' if block.client_id is None else 'cliente', 'until': block.expires_at.isoformat(),
                       'clients': 0, 'events': 0, 'here': 0, 'here_allowed': 0})
    return manual, covered


def c2_destinations(now):
    """Destinos externos de detecciones salientes de malware o control remoto (7 días), con su recurrencia.

    Solo datos del propio SOC: no se consulta a terceros por destinos de conexiones salientes.
    """
    rows = (SecurityEvidence._base_manager.filter(observed_at__gte=now - WINDOW, client_scope_id__isnull=False,
                                                  destination_ip__isnull=False, geography__direction='outbound',
                                                  interpretation__event_family='malware')
            .values('destination_ip')
            .annotate(events=Count('uid'), days=Count(TruncDate('observed_at'), distinct=True),
                      clients=Count('client_scope_id', distinct=True)))
    result = {}
    for row in rows.order_by().iterator(chunk_size=1000):
        if row['days'] >= C2_MIN_DAYS or row['clients'] >= C2_MIN_CLIENTS:
            result[row['destination_ip']] = row
    return result


def build_outbound(feed, c2, protected, now):
    """Lista de salida de un cliente: bloqueos manuales de salida y, si se activa, destinos C2 recurrentes."""
    allow = parse_allowlist(feed.allowlist)
    manual, covered = manual_entries(feed, now, allow, protected, 'out')
    automatic = []
    if feed.include_c2_detections:
        for ip, row in c2.items():
            address = ipaddress.ip_address(ip)
            if not address.is_global or conflict(ipaddress.ip_network(ip), allow, protected) or any(
                    address.version == n.version and address in n for n in covered):
                continue
            automatic.append({'ip': ip, 'reasons': [f'Destino C2/malware: {row["events"]} detecciones en {row["days"]} días'],
                              'c2': True, 'clients': row['clients'], 'events': row['events'], 'here': 0, 'here_allowed': 0})
        automatic.sort(key=lambda e: (-e['clients'], -e['events'], e['ip']))
    return manual + automatic[:feed.max_entries]


def soc_detections(now):
    """{IP o red: escenario} detectados por el motor CrowdSec del propio SOC (origen `crowdsec`).

    Si el motor no responde, se usa la última lectura correcta durante una hora; después no se
    incluye nada (estado seguro: dejar de bloquear antes que bloquear con datos viejos).
    """
    from django.utils.dateparse import parse_datetime
    from .reputation import EngineUnavailable, KeyRejected, _read, lapi_url
    from urllib import error as urlerror, parse as urlparse, request as urlrequest
    state = WorkerState.objects.filter(name=SOC_STATE).first()
    previous = state.details if state else {}
    key = os.environ.get('SOC_PORTAL_CROWDSEC_LAPI_KEY', '').strip()
    items, error = None, ''
    if not key:
        error = 'Falta SOC_PORTAL_CROWDSEC_LAPI_KEY: no se pueden leer las detecciones del motor del SOC.'
    else:
        try:
            req = urlrequest.Request(lapi_url() + '/v1/decisions?' + urlparse.urlencode({'origins': 'crowdsec'}),
                                     headers={'X-Api-Key': key, 'User-Agent': 'ib-red-SOC/1'})
            try:
                data = _read(req, 'LAPI')
            except urlerror.HTTPError as exc:
                raise KeyRejected() if exc.code in (401, 403) else exc
            except (urlerror.URLError, ConnectionError, TimeoutError):
                raise EngineUnavailable() from None
            if data is not None and not isinstance(data, list):
                raise ValueError('Respuesta no válida')
            items = {}
            for decision in (data or [])[:SOC_LIMIT]:
                if not isinstance(decision, dict) or str(decision.get('type', 'ban')).lower() != 'ban':
                    continue
                try:
                    network = ipaddress.ip_network(str(decision.get('value', '')), strict=False)
                except ValueError:
                    continue
                if network.is_global and network.prefixlen >= MIN_PREFIX[network.version]:
                    items[_label(network)] = str(decision.get('scenario') or 'detección local')[:120]
        except KeyRejected:
            error = 'El motor CrowdSec del SOC rechazó la clave.'
        except (EngineUnavailable, ValueError, OSError):
            error = 'El motor CrowdSec del SOC no responde.'
    if items is None:
        at = parse_datetime(previous.get('at') or '')
        items = previous.get('items', {}) if at and now - at <= SOC_STALE else {}
        details = {**previous, 'error': error}
    else:
        details = {'at': now.isoformat(), 'items': items, 'error': ''}
    with transaction.atomic():
        WorkerState.reserve(SOC_STATE)
        WorkerState.objects.filter(name=SOC_STATE).update(details=details)
    return items


def qualifying(now):
    """IPs con motivo vigente para bloquear y su motivo. La reputación sola no basta: ver `build`."""
    rows = IpReputation.objects.filter(
        Q(listed=True, lists_checked_at__gte=now - LISTS_FRESH) |
        Q(cti_found=True, reputation='malicious', cti_checked_at__gte=now - TTL))
    result = {}
    for row in rows.iterator(chunk_size=1000):
        if row.cti_found and (row.background_noise == 'high' or row.false_positives):
            continue  # Ruido de fondo de Internet o posible falso positivo: nunca se bloquea.
        # Cada fuente cuenta solo con su dato vigente: un dato caducado no es motivo para bloquear.
        listed = bool(row.listed and row.lists_checked_at and row.lists_checked_at >= now - LISTS_FRESH)
        malicious = bool(row.cti_found and row.reputation == 'malicious' and row.cti_checked_at
                         and row.cti_checked_at >= now - TTL)
        reasons = list(row.list_origins or ['Lista CrowdSec']) if listed else []
        if malicious:
            reasons.append('CTI: maliciosa')
        if reasons:
            result[row.ip] = {'reasons': reasons[:4], 'listed': listed, 'cti': malicious}
    return result


def activity(ips, now):
    """Detecciones de los últimos 7 días de esas IPs, por cliente (propietario histórico)."""
    stats = {}
    wanted = sorted(ips)
    for start in range(0, len(wanted), 1000):
        rows = (SecurityEvidence._base_manager.filter(observed_at__gte=now - WINDOW, source_ip__in=wanted[start:start + 1000],
                                                      client_scope_id__isnull=False)
                .values('source_ip', 'client_scope_id')
                .annotate(count=Count('uid'), allowed=Count('uid', filter=Q(action='allowed'))))
        for row in rows.order_by():
            item = stats.setdefault(row['source_ip'], {'count': 0, 'clients': {}})
            item['count'] += row['count']
            item['clients'][row['client_scope_id']] = (row['count'], row['allowed'])
    return stats


def build(feed, candidates, stats, protected, now, soc=None):
    """Entradas de un cliente: primero los bloqueos manuales vigentes, después lo detectado por el
    propio SOC y lo que atacó a algún cliente (le atacaron a él, a más clientes, más veces), hasta el máximo."""
    allow = parse_allowlist(feed.allowlist)
    manual, covered = manual_entries(feed, now, allow, protected, 'in')

    def inside(ip):
        address = ipaddress.ip_address(ip)
        return any(address.version == n.version and address in n for n in covered)

    detected = []
    if feed.include_soc_detections:
        for value, scenario in sorted((soc or {}).items()):
            network = ipaddress.ip_network(value, strict=False)
            if conflict(network, allow, protected) or any(network.subnet_of(n) for n in covered if n.version == network.version):
                continue
            item = stats.get(value, {'count': 0, 'clients': {}})
            here = item['clients'].get(feed.client_id, (0, 0))
            detected.append({'ip': value, 'reasons': ['Detectado por el SOC: ' + scenario], 'soc': True,
                             'clients': len(item['clients']), 'events': item['count'], 'here': here[0], 'here_allowed': here[1]})
    seen = {e['ip'] for e in detected}
    entries = []
    for ip, info in candidates.items():
        if ip in seen or inside(ip):
            continue
        if not (feed.include_lists and info['listed']) and not (feed.include_cti and info['cti']):
            continue
        item = stats.get(ip)
        address = ipaddress.ip_address(ip)
        if not item or not address.is_global or ip in protected or any(address in network for network in allow):
            continue
        here = item['clients'].get(feed.client_id, (0, 0))
        entries.append({'ip': ip, 'reasons': info['reasons'], 'clients': len(item['clients']), 'events': item['count'],
                        'here': here[0], 'here_allowed': here[1]})
    entries.sort(key=lambda e: (-e['here'], -e['clients'], -e['events'], e['ip']))
    # Los manuales no cuentan para el máximo: son decisiones explícitas y con caducidad.
    return manual + (detected + entries)[:feed.max_entries]


def observation(entries, now):
    """Qué habría bloqueado la lista: detecciones del propio cliente desde esas IPs en 7 días."""
    hits = [e for e in entries if e['here']]
    return {'at': now.isoformat(), 'ips': len(hits), 'events': sum(e['here'] for e in hits),
            'allowed': sum(e['here_allowed'] for e in hits), 'protective': sum(1 for e in entries if not e['here'])}


def refresh_feeds(now=None):
    """Trabajo `blocklists`: recalcula la lista de cada cliente con la lista activada."""
    now = now or timezone.now()
    feeds = list(BlocklistFeed.objects.filter(enabled=True, client__active=True))
    if not feeds:
        return 0
    candidates = qualifying(now)
    soc = soc_detections(now) if any(f.include_soc_detections for f in feeds) else {}
    c2 = c2_destinations(now) if any(f.outbound_enabled for f in feeds) else {}
    stats = activity(set(candidates) | {ip for ip in soc if '/' not in ip}, now)
    protected = protected_addresses()
    for feed in feeds:
        try:
            entries = build(feed, candidates, stats, protected, now, soc)
            outbound = build_outbound(feed, c2, protected, now) if feed.outbound_enabled else []
        except ValueError:
            continue  # Excepciones no válidas: se conserva la última lista buena y se avisa en su página.
        before = {e['ip'] for e in feed.entries}
        after = {e['ip'] for e in entries}
        # Solo si la configuración no cambió mientras se calculaba; si cambió, se recalcula en la próxima pasada.
        if not BlocklistFeed.objects.filter(pk=feed.pk, updated_at=feed.updated_at).update(
                entries=entries, outbound_entries=outbound, generated_at=now, observation=observation(entries, now)):
            continue
        if before != after:
            audit('blocklist.generated', feed.client, {'count': len(after),
                                                       'status': f'+{len(after - before)} -{len(before - after)}'})
    return len(feeds)


def _hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def rotate_token(feed):
    token = secrets.token_urlsafe(32)
    if feed.token_hash:
        feed.previous_token_hash, feed.token_rotated_at, feed.previous_token_fetch_at = feed.token_hash, timezone.now(), None
    feed.token_hash, feed.encrypted_token = _hash(token), encrypt(token)
    feed.save(update_fields=['token_hash', 'encrypted_token', 'previous_token_hash', 'token_rotated_at',
                             'previous_token_fetch_at', 'updated_at'])
    return token


def servable(feed, now=None, outbound=False):
    """IPs que se sirven ahora: vacía si está desactivada, detenida o sin recalcular; sin excepciones ni protegidas.

    Las excepciones y las IPs protegidas se vuelven a aplicar al servir: un cambio del operador
    surte efecto en la siguiente descarga aunque la lista aún no se haya recalculado.
    """
    now = now or timezone.now()
    if not (feed.enabled and not feed.stopped and feed.client.active and feed.generated_at
            and now - feed.generated_at <= FEED_MAX_AGE) or (outbound and not feed.outbound_enabled):
        return []
    try:
        allow = parse_allowlist(feed.allowlist)
    except ValueError:
        allow = []  # La lista guardada ya se calculó con las últimas excepciones válidas.
    protected = protected_addresses()
    stamp = now.isoformat()
    result = []
    for entry in (feed.outbound_entries if outbound else feed.entries):
        if entry.get('until') and entry['until'] <= stamp:
            continue  # Bloqueo manual caducado desde el último recálculo.
        if not conflict(ipaddress.ip_network(entry['ip'], strict=False), allow, protected):
            result.append(entry['ip'])
    return result


def feed_url(feed, outbound=False):
    """URL completa con el token, para el firewall. Solo se construye para quien gestiona conexiones."""
    from .invitations import origin
    if not feed.encrypted_token:
        return ''
    return origin() + reverse('blocklist_serve_out' if outbound else 'blocklist_serve',
                              args=[feed.client_id, decrypt(feed.encrypted_token)])


@never_cache
@require_GET
def serve(request, client_pk, token, outbound=False):
    """Descarga del firewall: una IP por línea. Vacía si la lista está desactivada o detenida.

    La lista de salida usa el mismo token y el mismo freno de emergencia.
    """
    feed = BlocklistFeed._base_manager.filter(client_id=client_pk).select_related('client').first()
    digest = _hash(token)
    if feed and feed.previous_token_hash and hmac.compare_digest(feed.previous_token_hash, digest):
        # URL anterior a una rotación: lista vacía, para que ese firewall deje de bloquear y se vea en la página.
        BlocklistFeed._base_manager.filter(pk=feed.pk).update(previous_token_fetch_at=timezone.now())
        body = ''
    elif not feed or not feed.token_hash or not hmac.compare_digest(feed.token_hash, digest):
        raise Http404
    else:
        BlocklistFeed._base_manager.filter(pk=feed.pk).update(last_fetch_at=timezone.now())
        body = ''.join(ip + '\n' for ip in servable(feed, outbound=outbound))
    response = HttpResponse(body, content_type='text/plain; charset=utf-8')
    response['X-Content-Type-Options'] = 'nosniff'
    return response


@never_cache
@require_GET
def serve_outbound(request, client_pk, token):
    return serve(request, client_pk, token, outbound=True)


def alias_name(plan):
    if plan.template == TEMPLATE_OUT:
        return f'SOC_C2_{plan.pk}'
    return f'SOC_CROWDSEC_{plan.pk}'


def plan_preview(device):
    """Vista previa de la plantilla: tabla de IPs descargada del SOC y regla de bloqueo de entrada en WAN."""
    return {'profile': TITLE, 'version': VERSION, 'networks': [], 'interface': 'wan',
            'alias': {'type': 'urltable', 'updatefreq': '0.04', 'description': 'Lista de bloqueo del SOC (CrowdSec)'},
            'rules': [{'enabled': '0', 'sequence': '1', 'action': 'block', 'quick': '1', 'interface': 'wan',
                       'direction': 'in', 'ipprotocol': 'inet46', 'protocol': 'any', 'source_net': 'Lista del SOC',
                       'destination_net': 'any', 'destination_port': '', 'log': '1'}],
            'checks': ['Revisar en «Listas de bloqueo» la observación: qué habría bloqueado y si incluye algún proveedor o socio.',
                       'Completar las excepciones del cliente (oficinas remotas, proveedores, servicios en la nube) antes de activar.',
                       'La regla bloquea conexiones entrantes en WAN desde las IPs de la lista; no afecta al tráfico saliente.',
                       'El firewall debe poder descargar la URL del SOC por HTTPS; la tabla se actualiza aproximadamente cada hora.',
                       'Freno de emergencia: detener la lista en el SOC vacía la tabla en la siguiente descarga; revertir la regla la retira.'],
            'zenarmor': [], 'suricata': []}


def plan_preview_outbound(device):
    """Plantilla de salida: tabla de destinos del SOC y regla que bloquea conexiones salientes hacia ellos."""
    return {'profile': TITLE_OUT, 'version': VERSION, 'networks': [], 'interface': 'wan',
            'alias': {'type': 'urltable', 'updatefreq': '0.04', 'description': 'Lista de salida del SOC (C2)'},
            'rules': [{'enabled': '0', 'sequence': '1', 'action': 'block', 'quick': '1', 'interface': 'wan',
                       'direction': 'out', 'ipprotocol': 'inet46', 'protocol': 'any', 'source_net': 'any',
                       'destination_net': 'Lista de salida del SOC', 'destination_port': '', 'log': '1'}],
            'checks': ['Revisar en la lista de salida cada destino: un servidor compartido (CDN, nube) puede alojar también servicios legítimos.',
                       'Añadir a las excepciones del cliente los proveedores, servicios en la nube y socios imprescindibles.',
                       'La regla bloquea conexiones salientes por WAN hacia las IPs de la lista, desde cualquier red interna.',
                       'Un equipo que intente conectar con un destino bloqueado puede estar infectado: revisar la detección asociada.',
                       'Freno de emergencia: detener la lista en el SOC vacía también la tabla de salida; revertir la regla la retira.'],
            'zenarmor': [], 'suricata': []}


def _devices(client):
    return Device.objects.filter(site__client=client, active=True, vendor=Device.Vendor.OPNSENSE,
                                 management_method='api').select_related('site')


def global_access(user):
    """Bloqueos para todos los clientes: solo quien tiene acceso global al SOC."""
    from .models import StaffAccess
    access = StaffAccess.objects.filter(user=user).first()
    return user.is_superuser or bool(access and access.all_clients and access.role != 'customer')


def add_manual(request, client):
    """Crea un bloqueo manual desde el formulario. Devuelve un error legible o ''."""
    try:
        network = parse_manual(request.POST.get('network', ''))
        days = int(request.POST.get('days', '7'))
        if not 1 <= days <= MANUAL_MAX_DAYS:
            raise ValueError(f'La caducidad debe estar entre 1 y {MANUAL_MAX_DAYS} días.')
    except ValueError as exc:
        return str(exc)
    reason = ' '.join(request.POST.get('reason', '').split())[:300]
    if len(reason) < 5:
        return 'Indica el motivo del bloqueo (se mostrará en la lista y en la auditoría del SOC).'
    target = None if request.POST.get('scope') == 'all' else client
    if target is None and not global_access(request.user):
        return 'Bloquear para todos los clientes requiere acceso global al SOC.'
    now = timezone.now()
    current = ManualBlock._base_manager.filter(client=target, revoked_at=None, expires_at__gt=now)
    if current.count() >= MANUAL_LIMIT:
        return f'Hay {MANUAL_LIMIT} bloqueos manuales vigentes en este alcance; retira alguno antes de añadir otro.'
    # Las excepciones de este cliente (y las IPs protegidas) mandan: se avisa en lugar de crear un bloqueo inútil.
    problem = conflict(network, parse_allowlist(client.blocklist_feed.allowlist) if target else [], protected_addresses())
    if problem:
        return f'No se puede bloquear {_label(network)}: {problem}.'
    direction = request.POST.get('direction', 'in')
    if direction not in ('in', 'out', 'both'):
        return 'Dirección no válida.'
    block = ManualBlock.objects.create(client=target, network=_label(network), reason=reason, created_by=request.user,
                                       direction=direction, expires_at=now + timedelta(days=days))
    audit('blocklist.manual_add', block, {'status': 'todos' if target is None else 'cliente',
                                          'until': block.expires_at.isoformat()})
    return ''


def revoke_manual(request, client):
    block = get_object_or_404(ManualBlock._base_manager.filter(Q(client=client) | Q(client=None), revoked_at=None),
                              pk=request.POST.get('block', '0') or 0)
    if block.client_id is None and not global_access(request.user):
        return HttpResponseForbidden('Retirar un bloqueo de todos los clientes requiere acceso global al SOC.')
    ManualBlock._base_manager.filter(pk=block.pk, revoked_at=None).update(revoked_at=timezone.now(), revoked_by=request.user)
    audit('blocklist.manual_revoke', block, {'status': 'todos' if block.client_id is None else 'cliente'})
    return None


@login_required
@require_GET
def overview(request):
    if not request.user.has_perm('core.manage_operations'):
        return HttpResponseForbidden('Permiso de operaciones requerido.')
    from .blocklist_efficacy import summary
    feeds = {f.client_id: f for f in BlocklistFeed.objects.all()}
    now = timezone.now()
    blocked = {}
    for plan in ChangePlan.objects.filter(template__in=TEMPLATES, status='active').select_related('device__site'):
        measured = summary(plan, now)
        if measured:
            blocked[plan.device.site.client_id] = blocked.get(plan.device.site.client_id, 0) + measured['week']
    rows = [{'client': c, 'feed': feeds.get(c.pk), 'blocked_week': blocked.get(c.pk)}
            for c in Client.objects.filter(active=True).order_by('name')]
    shared = ManualBlock._base_manager.filter(client=None, revoked_at=None, expires_at__gt=now).select_related('created_by')
    return render(request, 'blocklists.html', {'rows': rows, 'shared_blocks': shared})


@login_required
@require_http_methods(['GET', 'POST'])
def detail(request, client_pk):
    from .security import mfa_fresh
    if not request.user.has_perm('core.manage_operations'):
        return HttpResponseForbidden('Permiso de operaciones requerido.')
    client = get_object_or_404(Client, pk=client_pk, active=True)
    feed, _ = BlocklistFeed.objects.get_or_create(client=client)
    error = ''
    if request.method == 'POST':
        action = request.POST.get('action', '')
        # Detener o retirar un bloqueo solo deja de bloquear: no exige repetir el MFA para no retrasar una emergencia.
        if action not in ('stop', 'manual_revoke') and not mfa_fresh(request):
            return redirect('mfa_challenge')
        if action == 'settings':
            try:
                parse_allowlist(request.POST.get('allowlist', ''))
                maximum = int(request.POST.get('max_entries', '2000'))
                if not 1 <= maximum <= 20000:
                    raise ValueError('El máximo de entradas debe estar entre 1 y 20000.')
            except ValueError as exc:
                error = str(exc)
            else:
                feed.allowlist = request.POST.get('allowlist', '').strip()[:20000]
                feed.max_entries = maximum
                feed.include_lists = request.POST.get('include_lists') == 'on'
                feed.include_cti = request.POST.get('include_cti') == 'on'
                feed.include_soc_detections = request.POST.get('include_soc_detections') == 'on'
                feed.outbound_enabled = request.POST.get('outbound_enabled') == 'on'
                feed.include_c2_detections = request.POST.get('include_c2_detections') == 'on'
                feed.enabled = request.POST.get('enabled') == 'on'
                feed.save(update_fields=['allowlist', 'max_entries', 'include_lists', 'include_cti', 'include_soc_detections',
                                         'outbound_enabled', 'include_c2_detections', 'enabled', 'updated_at'])
                if feed.enabled and not feed.token_hash:
                    rotate_token(feed)
                audit('blocklist.settings', client, {'status': 'enabled' if feed.enabled else 'disabled',
                                                     'count': feed.max_entries})
                refresh_feeds()
                messages.success(request, 'Configuración guardada y lista recalculada.')
                return redirect('blocklist_detail', client_pk=client.pk)
        elif action == 'manual_add':
            error = add_manual(request, client)
            if not error:
                refresh_feeds()
                messages.success(request, 'Bloqueo añadido. Los firewalls lo aplicarán en su próxima descarga (aprox. 1 h).')
                return redirect('blocklist_detail', client_pk=client.pk)
        elif action == 'manual_revoke':
            denied = revoke_manual(request, client)
            if denied:
                return denied
            refresh_feeds()
            messages.success(request, 'Bloqueo retirado. Los firewalls dejarán de aplicarlo en su próxima descarga.')
            return redirect('blocklist_detail', client_pk=client.pk)
        elif action in ('stop', 'resume'):
            with transaction.atomic():
                stopped = action == 'stop'
                BlocklistFeed.objects.filter(pk=feed.pk).update(stopped=stopped, stopped_at=timezone.now() if stopped else None)
            audit('blocklist.' + action, client)
            messages.success(request, 'Lista detenida: los firewalls recibirán una lista vacía en su próxima descarga.'
                             if action == 'stop' else 'Lista reanudada.')
            return redirect('blocklist_detail', client_pk=client.pk)
        elif action == 'rotate':
            if not request.user.has_perm('core.manage_connections'):
                return HttpResponseForbidden('Permiso de conexiones requerido.')
            rotate_token(feed)
            audit('blocklist.token_rotated', client)
            messages.success(request, 'Token nuevo. Actualiza la URL en los firewalls: la anterior deja de funcionar.')
            return redirect('blocklist_detail', client_pk=client.pk)
        elif action in ('plan', 'plan_out'):
            if not request.user.has_perm('core.manage_connections'):
                return HttpResponseForbidden('Permiso de conexiones requerido.')
            device = get_object_or_404(_devices(client), pk=request.POST.get('device', '0') or 0)
            outbound = action == 'plan_out'
            if not feed.enabled or not feed.token_hash or (outbound and not feed.outbound_enabled):
                messages.error(request, 'Activa primero la lista (y la de salida, para el bloqueo C2) y revisa sus entradas.')
                return redirect('blocklist_detail', client_pk=client.pk)
            template = TEMPLATE_OUT if outbound else TEMPLATE
            plan = ChangePlan.objects.create(device=device, template=template, template_version=VERSION,
                                             title=TITLE_OUT if outbound else TITLE, parameters={'client': client.pk},
                                             preview=plan_preview_outbound(device) if outbound else plan_preview(device),
                                             requested_by=request.user)
            audit('change.draft', plan, {'template': template})
            return redirect('change_detail', pk=plan.pk)
        else:
            raise Http404
    feed.refresh_from_db()
    show_url = request.user.has_perm('core.manage_connections')
    try:
        parse_allowlist(feed.allowlist)
        allowlist_error = ''
    except ValueError as exc:
        allowlist_error = str(exc)
    from .blocklist_efficacy import summary
    plans = list(ChangePlan.objects.filter(template__in=TEMPLATES, device__site__client=client).select_related('device').order_by('-pk')[:10])
    now = timezone.now()
    warnings = []
    for plan in plans:
        plan.efficacy = summary(plan, now) if plan.status == 'active' else None
        if plan.efficacy and plan.efficacy['loaded'] == 0 and feed.entries and not feed.stopped:
            warnings.append(f'{plan.device.name} tiene la regla activa pero su tabla del SOC está vacía: '
                            'revisa que el firewall descarga la URL de la lista.')
    if feed.enabled and feed.generated_at and now - feed.generated_at > FEED_MAX_AGE:
        warnings.append('La lista no se recalcula desde el ' + timezone.localtime(feed.generated_at).strftime('%d/%m %H:%M')
                        + ': se sirve vacía hasta que el trabajo «Listas de bloqueo del SOC» vuelva a funcionar.')
    if feed.previous_token_fetch_at:
        warnings.append('Un firewall sigue usando la URL anterior al cambio de token (última descarga el '
                        + timezone.localtime(feed.previous_token_fetch_at).strftime('%d/%m %H:%M')
                        + '): recibe una lista vacía hasta que se actualice su URL.')
    if (feed.enabled and any(p.status == 'active' for p in plans)
            and (not feed.last_fetch_at or now - feed.last_fetch_at > FETCH_STALE)):
        warnings.append('Hay una regla activa, pero ningún firewall ha descargado la lista en las últimas 2 horas. '
                        'Revisa la conexión del firewall con el SOC.')
    if feed.include_soc_detections:
        state = WorkerState.objects.filter(name=SOC_STATE).first()
        if state and state.details.get('error'):
            warnings.append(state.details['error'] + ' Las detecciones del SOC se dejan de incluir una hora después de la última lectura correcta.')
    manual = active_manual(client, now).select_related('created_by')
    return render(request, 'blocklist_detail.html', {
        'warnings': warnings, 'manual_blocks': manual, 'global_access': global_access(request.user),
        'manual_max_days': MANUAL_MAX_DAYS,
        'client': client, 'feed': feed, 'entries': feed.entries[:300], 'count': len(feed.entries),
        'url': feed_url(feed) if show_url and feed.enabled else '', 'error': error or allowlist_error,
        'url_out': feed_url(feed, outbound=True) if show_url and feed.enabled and feed.outbound_enabled else '',
        'outbound': feed.outbound_entries[:300], 'outbound_count': len(feed.outbound_entries),
        'devices': _devices(client), 'plans': plans, 'observation': feed.observation})

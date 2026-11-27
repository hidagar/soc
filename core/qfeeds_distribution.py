"""Q-Feeds para los clientes: lista preventiva de IPs, dominios para el DNS, medición por fuente y activación masiva.

El acuerdo con Q-Feeds es equivalente al de CrowdSec: el SOC redistribuye sus listas a los firewalls de los
clientes. Además de las IPs que ya han atacado a algún cliente (ver `blocklist`), cada cliente puede recibir:

- **Lista preventiva**: las IPs y redes de las listas vigentes de Q-Feeds aunque aún no hayan atacado a nadie,
  con URL propia (tabla por URL de OPNsense, plantillas `qfeeds` de entrada y `qfeeds_out` de salida) o escrita
  en UniFi (solo IPv4 y con su tope). Primero las que ya atacaron a algún cliente; después las más recientes.
  Nunca entran IPs de clientes o del SOC, las excepciones de cualquier cliente, los destinos revisados
  «Sin riesgo» ni redes más amplias que /24 (IPv4) o /48 (IPv6).
- **Dominios** para la lista de bloqueo de Unbound (DNS de OPNsense) por URL, con excepciones por cliente que
  incluyen sus subdominios. El dominio del propio SOC nunca se publica.

Ambas listas usan el token y el freno de emergencia de la lista del cliente y se sirven vacías si la lista está
desactivada o detenida, si el cliente está inactivo o si las listas de Q-Feeds no están vigentes (36 horas).
Se calculan al servirlas: una excepción nueva surte efecto en la siguiente descarga.

Medición: los contadores de las reglas del SOC se leen por separado (`blocklist_efficacy`), así que el panel, el
informe y el portal del cliente distinguen lo que cortó la lista del SOC (CrowdSec y detecciones propias) de lo
que cortó la lista preventiva de Q-Feeds. Al cliente solo llegan cifras agregadas (invariante 3).
"""
import bisect
import copy
import hashlib
import ipaddress
from urllib.parse import urlsplit

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden
from django.shortcuts import redirect, render
from django.utils import timezone
from django.views.decorators.http import require_http_methods

from .models import BlocklistFeed, ChangePlan, Client, Device, ThreatIndicator, ThreatIntelMatch, ThreatIntelReview
from .security import audit, mfa_fresh, mfa_redirect

PREVENTIVE_DEFAULT = 50_000
PREVENTIVE_LIMIT = 200_000
DNS_MAX = 250_000
MAX_DNS_ALLOWLIST = 500
MIN_PREFIX = {4: 24, 6: 48}  # como los bloqueos manuales: una red más amplia bloquearía a demasiada gente
TEMPLATE = 'qfeeds'
TEMPLATE_OUT = 'qfeeds_out'
TEMPLATES = (TEMPLATE, TEMPLATE_OUT)
TITLE = 'Bloqueo preventivo Q-Feeds del SOC'
TITLE_OUT = 'Bloqueo preventivo de salida Q-Feeds del SOC'
DNS_TEMPLATE = 'qfeeds_dns'
DNS_TITLE = 'Bloqueo DNS Q-Feeds del SOC'
DNS_CACHE_TTL = 900  # segundos que Unbound reutiliza la lista descargada antes de pedirla de nuevo (1.1; antes 3600)
URL_UPDATEFREQ = '0.01'  # días: ~14 minutos (versión 1.1)
DNS_CONFIRM_MINUTES = 10  # el DNS no corta la gestión del firewall: hay tiempo para probar antes de confirmar
VERSION = '1.1'  # 1.1: tabla por URL cada ~15 min y copia de la lista DNS de 15 min (antes ~1 h)
# Lo que se puede activar o desactivar a la vez en varios clientes.
OPTIONS = (
    ('include_qfeeds', 'Atacantes que figuran en Q-Feeds (lista de entrada)'),
    ('include_qfeeds_c2', 'Destinos de Q-Feeds contactados por clientes (lista de salida)'),
    ('qfeeds_preventive', 'Lista preventiva de Q-Feeds'),
    ('qfeeds_dns', 'Dominios de Q-Feeds para el DNS'),
)
SOURCE_LABELS = {'crowdsec': 'CrowdSec', 'qfeeds': 'Q-Feeds', 'soc': 'Detecciones del SOC', 'manual': 'Bloqueos manuales'}


class Ranges:
    """Rangos de direcciones que no se pueden bloquear, para comprobar listas grandes sin recorrerlos por entrada."""

    def __init__(self, networks=(), addresses=()):
        spans = {4: [], 6: []}
        for network in networks:
            spans[network.version].append((int(network.network_address), int(network.broadcast_address)))
        for value in addresses:
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                continue
            spans[address.version].append((int(address), int(address)))
        self.starts, self.ends = {}, {}
        for version, items in spans.items():
            merged = []
            for low, high in sorted(items):
                if merged and low <= merged[-1][1] + 1:
                    merged[-1][1] = max(merged[-1][1], high)
                else:
                    merged.append([low, high])
            self.starts[version] = [m[0] for m in merged]
            self.ends[version] = [m[1] for m in merged]

    def overlaps(self, network):
        low, high = int(network.network_address), int(network.broadcast_address)
        index = bisect.bisect_right(self.starts[network.version], high) - 1
        return index >= 0 and self.ends[network.version][index] >= low


def exclusions(feed=None):
    """IPs de clientes y del SOC, excepciones de todos los clientes (y las del cliente, aunque haya otras no válidas)."""
    from .blocklist import parse_allowlist
    from .reputation import protected_addresses
    protected = protected_addresses()
    networks = list(protected.networks)
    if feed is not None:
        try:
            networks += parse_allowlist(feed.allowlist)
        except ValueError:
            pass  # ya se avisa en la página del cliente; las demás excepciones siguen aplicándose
    return Ranges(networks, set(protected))


def _usable():
    from .threat_intel import usable_feeds
    return sorted(usable_feeds())


def preventive_values(limit, ranges=None, stats=None):
    """Lista preventiva común a todos los clientes, hasta `limit` entradas.

    Primero las IPs que ya atacaron a algún cliente (coinciden con las listas), después las más recientes de la
    copia local. `stats` (dict) recibe cuántas se descartaron por cada motivo.
    """
    feeds = _usable()
    if not feeds or limit <= 0:
        return []
    ranges = ranges or exclusions()
    dismissed = set(ThreatIntelReview._base_manager.filter(decision='dismissed').values_list('ip', flat=True))
    counts = stats if stats is not None else {}
    for key in ('protected', 'broad', 'dismissed'):
        counts.setdefault(key, 0)
    result, seen = [], set()

    def take(value):
        if value in seen:
            return
        seen.add(value)
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return
        if network.prefixlen < MIN_PREFIX[network.version]:
            counts['broad'] += 1
        elif not network.is_global or ranges.overlaps(network):
            counts['protected'] += 1
        elif value in dismissed:
            counts['dismissed'] += 1
        else:
            result.append(value)

    for ip in sorted(set(ThreatIntelMatch._base_manager.filter(role='source').values_list('ip', flat=True))):
        take(ip)
        if len(result) >= limit:
            return result
    rows = (ThreatIndicator.objects.filter(feed__in=feeds, kind__in=('ip', 'net')).order_by('-pk')
            .values_list('value', flat=True))
    for value in rows.iterator(chunk_size=5000):
        take(value)
        if len(result) >= limit:
            break
    return result


def _domain(value):
    from .threat_intel import DOMAIN
    text = (value or '').strip().lower().rstrip('.')
    for prefix in ('*.', '.'):
        if text.startswith(prefix):
            text = text[len(prefix):]
    return text if DOMAIN.match(text) else ''


def parse_domains(text):
    """Excepciones de dominios: uno por línea, con # comentario. ValueError si alguno no es válido."""
    result = []
    for line in (text or '').splitlines():
        value = line.split('#', 1)[0].strip()
        if not value:
            continue
        domain = _domain(value)
        if not domain:
            raise ValueError(f'Dominio no válido: {value[:60]}')
        result.append(domain)
    if len(result) > MAX_DNS_ALLOWLIST:
        raise ValueError(f'Como máximo {MAX_DNS_ALLOWLIST} dominios en las excepciones.')
    return result


def protected_domains():
    """Dominios que nunca se publican: el del propio portal del SOC (los firewalls lo necesitan para descargar)."""
    from .invitations import origin
    try:
        host = urlsplit(origin()).hostname or ''
    except ValueError:
        return []
    try:
        ipaddress.ip_address(host)
        return []
    except ValueError:
        return [host.lower()] if _domain(host) else []


def _parents(domain):
    labels = domain.split('.')
    return ['.'.join(labels[i:]) for i in range(len(labels))]


def dns_values(feed, limit=DNS_MAX):
    """Dominios de Q-Feeds para el DNS del cliente, sin sus excepciones (y sus subdominios) ni los protegidos.

    Si una excepción es un subdominio de un dominio de la lista, se retira también ese dominio: una lista de
    bloqueo de Unbound no puede desbloquear un subdominio de lo que bloquea.
    """
    feeds = _usable()
    if not feeds:
        return []
    try:
        allowed = parse_domains(feed.dns_allowlist)
    except ValueError:
        allowed = []
    allowed = set(allowed) | set(protected_domains())
    ancestors = {parent for domain in allowed for parent in _parents(domain)}
    result, seen = [], set()
    rows = ThreatIndicator.objects.filter(feed__in=feeds, kind='domain').order_by('-pk').values_list('value', flat=True)
    for value in rows.iterator(chunk_size=5000):
        if value in seen:
            continue
        seen.add(value)
        if value in ancestors or any(parent in allowed for parent in _parents(value)):
            continue
        result.append(value)
        if len(result) >= limit:
            break
    return result


def publishing(feed):
    """La lista del cliente está publicada y en marcha (mismo freno de emergencia que la lista principal)."""
    return bool(feed.enabled and not feed.stopped and feed.client.active)


def servable_preventive(feed):
    if not (publishing(feed) and feed.qfeeds_preventive):
        return []
    return preventive_values(min(feed.preventive_max, PREVENTIVE_LIMIT), exclusions(feed))


def servable_dns(feed):
    if not (publishing(feed) and feed.qfeeds_dns):
        return []
    return dns_values(feed)


def refresh_counts(feeds):
    """Recuentos para los paneles (trabajo «Listas de bloqueo del SOC»): {feed_pk: (preventiva, dominios)}.

    La lista preventiva es común salvo el tope, así que se calcula una vez con el mayor tope.
    """
    preventive = [f for f in feeds if f.qfeeds_preventive]
    base = preventive_values(max(min(f.preventive_max, PREVENTIVE_LIMIT) for f in preventive)) if preventive else []
    result = {}
    for feed in feeds:
        # Las excepciones de cada cliente ya están entre las de todos (`protected_addresses`): solo cambia el tope.
        count = min(len(base), feed.preventive_max) if feed.qfeeds_preventive else 0
        result[feed.pk] = (count, len(dns_values(feed)) if feed.qfeeds_dns else 0)
    return result


def entry_sources(entry):
    """Fuentes que justifican una entrada de las listas del SOC (las antiguas no guardan `sources`)."""
    if not isinstance(entry, dict):
        return set()
    if entry.get('sources'):
        return set(entry['sources'])
    if entry.get('manual'):
        return {'manual'}
    if entry.get('qfeeds_only'):
        return {'qfeeds'}
    found = set()
    if entry.get('soc') or entry.get('repeat') or entry.get('c2'):
        found.add('soc')
    for reason in entry.get('reasons', []):
        if reason.startswith('Q-Feeds'):
            found.add('qfeeds')
        elif reason.startswith(('Ataques repetidos', 'Detectado por el SOC', 'Destino C2', 'Bloqueo manual')):
            found.add('soc')
        else:
            found.add('crowdsec')
    return found


def source_counts(entries):
    """Entradas por fuente. Una entrada puede contar en varias; `both` son las que confirman CrowdSec y Q-Feeds."""
    counts = {'crowdsec': 0, 'qfeeds': 0, 'both': 0, 'soc': 0, 'manual': 0, 'only_qfeeds': 0}
    for entry in entries:
        sources = entry_sources(entry)
        for name in ('crowdsec', 'qfeeds', 'soc', 'manual'):
            counts[name] += name in sources
        counts['both'] += {'crowdsec', 'qfeeds'} <= sources
        counts['only_qfeeds'] += sources == {'qfeeds'}
    return counts


def plan_preview(device, outbound=False):
    """Plantilla preventiva: tabla de IPs de Q-Feeds descargada del SOC y regla de bloqueo desactivada en WAN."""
    rule = {'enabled': '0', 'sequence': '1', 'action': 'block', 'quick': '1', 'interface': 'wan',
            'direction': 'out' if outbound else 'in', 'ipprotocol': 'inet46', 'protocol': 'any',
            'source_net': 'any' if outbound else 'Lista preventiva Q-Feeds', 'destination_net': 'Lista preventiva Q-Feeds'
            if outbound else 'any', 'destination_port': '', 'log': '1'}
    checks = ['La lista contiene IPs que aún no han atacado a ningún cliente: revisar con el cliente sus proveedores, '
              'socios y servicios en la nube y añadirlos a las excepciones antes de activar.',
              'Si la lista supera el máximo de entradas de tablas del firewall (Firewall › Ajustes › Avanzado), OPNsense '
              'no la carga: comprobar «IPs cargadas» tras la primera medición y ajustar el máximo de la lista preventiva.',
              'El firewall descarga la URL del SOC por HTTPS; la tabla se actualiza aproximadamente cada 15 minutos.',
              'Freno de emergencia: detener la lista en el SOC vacía también esta tabla; revertir la regla la retira.']
    if outbound:
        checks.insert(1, 'Bloquea conexiones salientes hacia las IPs de la lista: un servidor compartido puede alojar '
                         'también servicios legítimos. Empezar por la regla de entrada.')
    return {'profile': TITLE_OUT if outbound else TITLE, 'version': VERSION, 'networks': [], 'interface': 'wan',
            'alias': {'type': 'urltable', 'updatefreq': URL_UPDATEFREQ, 'description': 'Lista preventiva del SOC (Q-Feeds)'},
            'rules': [rule], 'checks': checks, 'zenarmor': [], 'suricata': []}


def dns_plan_preview(device):
    """Plantilla DNS: lista de bloqueo propia en Unbound (OPNsense 25.7 o posterior), desactivada hasta activarla."""
    return {'profile': DNS_TITLE, 'version': VERSION, 'networks': [], 'interface': '', 'rules': [],
            'dnsbl': {'cache_ttl': str(DNS_CACHE_TTL), 'nxdomain': '1',
                      'description': 'Dominios de Q-Feeds descargados del SOC; respuesta NXDOMAIN'},
            'checks': ['Comprobar que los equipos del cliente usan el DNS del firewall (Unbound); si usan otro DNS, la lista no les afecta.',
                       'Añadir antes a «Dominios que nunca se bloquean» los dominios de proveedores y servicios que el cliente necesita.',
                       'Requiere OPNsense 25.7 o posterior con Unbound activo. En versiones anteriores la lista se añade a mano.',
                       f'Tras activarla, probar que un dominio habitual resuelve y confirmar en {DNS_CONFIRM_MINUTES} minutos; si no se confirma, se desactiva sola.',
                       'Unbound vuelve a descargar la lista al aplicar los cambios si su copia tiene más de 15 minutos. El SOC '
                       'pide esa recarga cuando la lista cambia (trabajo «Propagación a los firewalls»).',
                       'Freno de emergencia: detener la lista en el SOC la vacía en la siguiente descarga; revertir retira la lista de Unbound.'],
            'zenarmor': [], 'suricata': []}


def create_dns_draft(feed, device, user):
    plan = ChangePlan.objects.create(device=device, template=DNS_TEMPLATE, template_version=VERSION, title=DNS_TITLE,
                                     parameters={'client': feed.client_id}, preview=dns_plan_preview(device), requested_by=user)
    audit('change.draft', plan, {'template': plan.template})
    return plan


def _opnsense(client):
    return Device.objects.filter(site__client=client, active=True, vendor=Device.Vendor.OPNSENSE,
                                 management_method='api').select_related('site').order_by('name')


def open_plans(device_ids, template):
    """Dispositivos que ya tienen una propuesta de esa plantilla sin revertir ni fallida."""
    return set(ChangePlan._base_manager.filter(device_id__in=device_ids, template=template)
               .exclude(status__in=('rolled_back', 'failed')).values_list('device_id', flat=True))


def create_draft(feed, device, user, outbound=False):
    plan = ChangePlan.objects.create(device=device, template=TEMPLATE_OUT if outbound else TEMPLATE, template_version=VERSION,
                                     title=TITLE_OUT if outbound else TITLE, parameters={'client': feed.client_id},
                                     preview=plan_preview(device, outbound), requested_by=user)
    audit('change.draft', plan, {'template': plan.template})
    return plan


def _week(plans, now):
    from .blocklist_efficacy import summary
    total, measured = 0, False
    for plan in plans:
        result = summary(plan, now)
        if result and result.get('checked_at'):
            total += result['week']
            measured = True
    return total if measured else None


def status_rows(clients, now=None):
    """Estado de Q-Feeds en cada cliente para la tabla del SOC."""
    from .blocklist import TEMPLATES as MAIN
    from .models import UnifiBlocklistBinding
    now = now or timezone.now()
    clients = list(clients)
    feeds = {f.client_id: f for f in BlocklistFeed.objects.filter(client__in=clients)}
    plans = {}
    for plan in ChangePlan._base_manager.filter(device__site__client__in=clients, template__in=MAIN + TEMPLATES + (DNS_TEMPLATE,),
                                                device__active=True).select_related('device__site'):
        plans.setdefault(plan.device.site.client_id, []).append(plan)
    unifi = {}
    for binding in UnifiBlocklistBinding._base_manager.filter(device__site__client__in=clients, direction__in=('qfeeds', 'dns'),
                                                              device__active=True).select_related('device__site'):
        unifi.setdefault(binding.device.site.client_id, []).append(binding)
    devices = {}
    for client_id, vendor in Device.objects.filter(site__client__in=clients, active=True).values_list('site__client_id', 'vendor'):
        devices.setdefault(client_id, set()).add(vendor)
    rows = []
    for client in clients:
        feed = feeds.get(client.pk)
        own = plans.get(client.pk, [])
        active_main = [p for p in own if p.template in MAIN and p.status == 'active']
        active_q = [p for p in own if p.template in TEMPLATES and p.status == 'active']
        active_dns = [p for p in own if p.template == DNS_TEMPLATE and p.status == 'active']
        pending_q = [p for p in own if p.template in TEMPLATES and p.status not in ('active', 'rolled_back', 'failed')]
        bindings = unifi.get(client.pk, [])
        rows.append({
            'client': client, 'feed': feed,
            'sources': source_counts(feed.entries) if feed else None,
            'out_qfeeds': sum(1 for e in feed.outbound_entries if 'qfeeds' in entry_sources(e)) if feed else 0,
            'rules_main': len(active_main), 'rules_q': len(active_q), 'rules_q_pending': len(pending_q),
            'unifi_q': sum(1 for b in bindings if b.direction == 'qfeeds' and b.policies_enabled),
            'unifi_q_pending': sum(1 for b in bindings if b.direction == 'qfeeds' and not b.policies_enabled),
            'unifi_dns': sum(1 for b in bindings if b.direction == 'dns' and b.policies_enabled),
            'unifi_dns_pending': sum(1 for b in bindings if b.direction == 'dns' and not b.policies_enabled),
            'week_main': _week(active_main, now), 'week_q': _week(active_q, now), 'week_dns': _week(active_dns, now),
            'rules_dns': len(active_dns),
            'vendors': sorted(devices.get(client.pk, set())),
        })
    return rows


def _selected(request, clients):
    wanted = {value for value in request.POST.getlist('client') if value.isascii() and value.isdigit() and len(value) <= 18}
    return [c for c in clients if str(c.pk) in wanted]


def _options(request):
    return [name for name, _ in OPTIONS if request.POST.get('opt_' + name) == 'on']


def signature(form):
    """Huella de la selección de la vista previa: «Aplicar» solo vale para lo que se ha previsualizado."""
    text = '|'.join([','.join(sorted(form['clients'], key=int)), ','.join(form['options']),
                     str(form['activate']), str(form['publish']), str(form['drafts'])])
    return hashlib.sha256(text.encode()).hexdigest()[:32]


def preview_rows(clients, options, activate, publish, drafts):
    """Qué cambiaría en cada cliente marcado, sin guardar nada (vista previa de la activación masiva)."""
    from .blocklist import activity, build, build_outbound, c2_destinations, parse_allowlist, qfeeds_destinations, qualifying
    from .reputation import protected_addresses
    now = timezone.now()
    feeds = {f.client_id: f for f in BlocklistFeed.objects.filter(client__in=clients).select_related('client')}
    candidates = stats = c2 = destinations = protected = None
    base = None
    labels = dict(OPTIONS)
    rows = []
    for client in clients:
        feed = feeds.get(client.pk) or BlocklistFeed(client=client)
        changes = [labels[name] for name in options if getattr(feed, name) != activate]
        warnings, counts = [], {}
        will_publish = feed.enabled or (activate and publish)
        if activate and not will_publish:
            warnings.append('La lista del cliente no está publicada: no tendrá efecto hasta publicarla.')
        if activate and publish and not feed.enabled:
            changes.append('Publicar la lista del cliente')
        if activate and 'include_qfeeds_c2' in options and not feed.outbound_enabled:
            warnings.append('Sin lista de salida (C2): los destinos de Q-Feeds no se publican hasta activarla.')
        try:
            parse_allowlist(feed.allowlist)
        except ValueError as exc:
            warnings.append(f'Excepciones no válidas: {exc}')
        if activate and will_publish and ('include_qfeeds' in options or 'include_qfeeds_c2' in options):
            if candidates is None:
                candidates = qualifying(now, True)
                stats = activity(set(candidates), now)
                protected = protected_addresses()
                c2 = destinations = {}
            trial = copy.copy(feed)
            for name in options:
                setattr(trial, name, True)
            try:
                if 'include_qfeeds' in options:
                    counts['inbound'] = sum(1 for e in build(trial, candidates, stats, protected, now) if e.get('qfeeds_only'))
                if 'include_qfeeds_c2' in options and feed.outbound_enabled:
                    if not destinations:
                        destinations = qfeeds_destinations()
                        c2 = c2_destinations(now) if feed.include_c2_detections else {}
                    counts['outbound'] = sum(1 for e in build_outbound(trial, c2, protected, now, destinations)
                                             if e.get('qfeeds_only'))
            except ValueError:
                pass
        if activate and 'qfeeds_preventive' in options:
            if base is None:
                base = preventive_values(PREVENTIVE_LIMIT)
            counts['preventive'] = min(len(base), feed.preventive_max)
        if activate and 'qfeeds_dns' in options:
            counts['dns'] = len(dns_values(feed))
        devices = list(_opnsense(client))
        planned = []
        for option, template, _, label in (DRAFTABLE if activate and drafts else ()):
            if option in options:
                busy = open_plans([d.pk for d in devices], template)
                free = [d for d in devices if d.pk not in busy]
                if free:
                    planned.append({'label': label, 'devices': free})
        if activate and 'qfeeds_preventive' in options and not devices:
            warnings.append('Sin OPNsense por API: la lista preventiva se configura a mano (URL) o en UniFi desde la lista del cliente.')
        if activate and 'qfeeds_dns' in options and not devices:
            warnings.append('Sin OPNsense por API: los dominios se añaden a mano en el DNS del firewall (URL), si lo admite.')
        rows.append({'client': client, 'changes': changes, 'counts': counts, 'warnings': warnings, 'drafts': planned})
    return rows


DRAFTABLE = (('qfeeds_preventive', TEMPLATE, lambda feed, device, user: create_draft(feed, device, user), 'regla preventiva'),
             ('qfeeds_dns', DNS_TEMPLATE, lambda feed, device, user: create_dns_draft(feed, device, user), 'lista DNS'))


def apply(request, clients, options, activate, publish, drafts):
    """Guarda las opciones en cada cliente marcado, recalcula las listas y prepara los borradores pedidos."""
    from .blocklist import refresh_feeds, rotate_token
    changed = created = 0
    labels = dict(OPTIONS)
    for client in clients:
        feed, _ = BlocklistFeed.objects.get_or_create(client=client)
        fields = []
        for name in options:
            if getattr(feed, name) != activate:
                setattr(feed, name, activate)
                fields.append(name)
        if activate and publish and not feed.enabled:
            feed.enabled = True
            fields.append('enabled')
        if fields:
            feed.save(update_fields=fields + ['updated_at'])
            changed += 1
            audit('blocklist.qfeeds_bulk', client, {'status': 'enabled' if activate else 'disabled',
                                                    'fields': [labels.get(f, 'Publicar la lista') for f in fields]})
        if feed.enabled and not feed.token_hash:
            rotate_token(feed)
        for option, template, make, _ in (DRAFTABLE if activate and drafts and feed.enabled else ()):
            if option not in options:
                continue
            devices = list(_opnsense(client))
            busy = open_plans([d.pk for d in devices], template)
            for device in devices:
                if device.pk not in busy:
                    make(feed, device, request.user)
                    created += 1
    refresh_feeds()
    if not activate:
        from .blocklist import sync_unifi
        for client in clients:
            sync_unifi(client)  # UniFi no descarga: se escribe ya lo que deja de servirse
    return changed, created


@login_required
@require_http_methods(['GET', 'POST'])
def overview(request):
    """Q-Feeds en los clientes: estado de despliegue de todos y activación masiva con vista previa."""
    from .blocklist import qfeeds_configured
    from .threat_intel import usable_feeds
    if not request.user.has_perm('core.manage_operations'):
        return HttpResponseForbidden('Permiso de operaciones requerido.')
    clients = list(Client.objects.filter(active=True).order_by('name'))
    preview = None
    form = {'options': [], 'activate': True, 'publish': False, 'drafts': False, 'clients': []}
    if request.method == 'POST':
        selected = _selected(request, clients)
        options = _options(request)
        activate = request.POST.get('mode', 'on') != 'off'
        publish = activate and request.POST.get('publish') == 'on'
        drafts = activate and request.POST.get('drafts') == 'on'
        if drafts and not request.user.has_perm('core.manage_connections'):
            return HttpResponseForbidden('Preparar borradores requiere el permiso de gestión de conexiones.')
        form = {'options': options, 'activate': activate, 'publish': publish, 'drafts': drafts,
                'clients': [str(c.pk) for c in selected]}
        if not selected or not (options or publish):
            messages.error(request, 'Marca al menos un cliente y una opción.')
        elif request.POST.get('action') == 'apply' and request.POST.get('previewed') != signature(form):
            messages.error(request, 'La selección ha cambiado desde la vista previa: revísala de nuevo antes de aplicar.')
            preview = preview_rows(selected, options, activate, publish, drafts)
        elif request.POST.get('action') == 'apply':
            # Desactivar solo deja de bloquear: como el freno de emergencia, no exige repetir el MFA.
            if activate and not mfa_fresh(request):
                return mfa_redirect(request)
            changed, created = apply(request, selected, options, activate, publish, drafts)
            text = f'{changed} cliente{"s" if changed != 1 else ""} actualizado{"s" if changed != 1 else ""} y listas recalculadas.'
            if created:
                text += f' {created} borrador{"es" if created != 1 else ""} en el control de cambios (desactivados hasta aprobarlos).'
            messages.success(request, text)
            return redirect('blocklist_qfeeds')
        else:
            preview = preview_rows(selected, options, activate, publish, drafts)
    feeds = sorted(usable_feeds())
    counts = {}
    if feeds:
        for kind in ('ip', 'net', 'domain'):
            counts[kind] = ThreatIndicator.objects.filter(feed__in=feeds, kind=kind).count()
    return render(request, 'blocklist_qfeeds.html', {
        'rows': status_rows(clients), 'options': OPTIONS, 'form': form, 'preview': preview,
        'previewed': signature(form) if preview is not None else '',
        'configured': qfeeds_configured(), 'usable': feeds, 'indicator_counts': counts,
        'can_draft': request.user.has_perm('core.manage_connections'),
        'preventive_limit': PREVENTIVE_LIMIT})

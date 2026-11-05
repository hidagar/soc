"""Inteligencia de amenazas Q-Feeds: fuente de inteligencia del SOC (fase 1, observación).

- Solo el trabajo protegido `threat_intel` usa la clave (`SOC_PORTAL_QFEEDS_KEY`, en el archivo protegido).
  Descarga las listas completas (`malware_ip` y `malware_domains` por defecto) con autenticación Basic,
  igual que el plugin oficial de OPNsense: índice en `/licenses.php` y cada lista en `/api.php`.
  Solo descarga: a Q-Feeds no se le envía ninguna IP, dominio ni dato de clientes.
- La copia local se sustituye con cada versión publicada (las entradas que desaparecen se borran) y solo
  se usa mientras esté vigente: si no se ha podido comprobar en 36 horas, deja de usarse (estado seguro)
  y se avisa en «Salud del SOC»; a los 7 días se borra.
- Como la búsqueda es local, el SOC puede revisar también los **destinos** de las conexiones salientes de
  los clientes, que nunca se consultan a terceros. Coincidir con la lista es contexto para investigar:
  no acredita ataque, infección ni compromiso (invariante 4).
- Licencia: uso interno del SOC. Esta fase no distribuye nada a firewalls de clientes.
"""
import base64
import ipaddress
import json
import os
import re
from collections import defaultdict
from datetime import timedelta
from urllib import error as urlerror
from urllib import parse as urlparse
from urllib import request as urlrequest

from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.db.models import Count, Max, Min, Q
from django.http import HttpResponseForbidden
from django.shortcuts import render
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET

from .models import Client, IpReputation, OperationalIssue, SecurityEvidence, ThreatIndicator, ThreatIntelMatch, WorkerState

API = 'https://api.qfeeds.com'
STATE = 'threat-intel'
ISSUE = 'platform:threat-intel'
DEFAULT_FEEDS = ('malware_ip', 'malware_domains')
LABELS = {'malware_ip': 'IPs maliciosas', 'malware_domains': 'Dominios maliciosos'}
MAX_INDEX = 1024 * 1024
MAX_FEED = 64 * 1024 * 1024
MAX_ENTRIES = 500_000
MAX_CATEGORIES = 8
MAX_CATEGORY_NAMES = 500
MAX_MATCHES = 2000
FRESH = timedelta(hours=36)  # el plan gratuito publica cada 24 horas
PURGE_AFTER = timedelta(days=7)
PAUSE = timedelta(hours=1)  # tras rechazar la clave o limitar peticiones, como el plugin oficial
WINDOW = timedelta(days=7)
LISTS_FRESH = timedelta(hours=24)
MIN_PREFIX = {4: 16, 6: 32}  # una red más amplia en una lista de amenazas no aporta contexto útil
BUCKET = {4: 16, 6: 32}
CHUNK = 2000
FEED_NAME = re.compile(r'^[a-z0-9_]{1,32}$')
DOMAIN = re.compile(r'^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$')


class FeedError(Exception):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


class _NoRedirect(urlrequest.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def api_key():
    return os.environ.get('SOC_PORTAL_QFEEDS_KEY', '').strip()


def wanted_feeds():
    """Listas a descargar (`SOC_PORTAL_QFEEDS_FEEDS`, separadas por comas); por defecto IPs y dominios."""
    names = [n.strip() for n in os.environ.get('SOC_PORTAL_QFEEDS_FEEDS', '').split(',') if FEED_NAME.match(n.strip())]
    return tuple(names) or DEFAULT_FEEDS


def _open(req):
    return urlrequest.build_opener(_NoRedirect()).open(req, timeout=60)


def _get(path, params, key, limit):
    """GET con la clave en la cabecera (nunca en la URL, que puede acabar en registros). Errores sin
    contenido del proveedor ni la clave."""
    url = API + path + ('?' + urlparse.urlencode(params) if params else '')
    token = base64.b64encode(f'api_token:{key}'.encode()).decode()
    req = urlrequest.Request(url, headers={'Authorization': 'Basic ' + token, 'User-Agent': 'ib-red-SOC/1',
                                           'Accept': 'application/json'})
    try:
        response = _open(req)
    except urlerror.HTTPError as exc:
        raise FeedError({401: 'clave rechazada', 403: 'clave rechazada o lista fuera de la licencia',
                         404: 'lista no encontrada', 429: 'límite de peticiones de Q-Feeds'}.get(exc.code, f'HTTP {exc.code}'),
                        exc.code) from None
    except (urlerror.URLError, TimeoutError, ConnectionError, OSError):
        raise FeedError('sin conexión con Q-Feeds') from None
    chunks, size = [], 0
    with response:
        while True:
            block = response.read(1024 * 1024)
            if not block:
                break
            size += len(block)
            if size > limit:
                raise FeedError('respuesta demasiado grande')
            chunks.append(block)
    try:
        return json.loads(b''.join(chunks))
    except ValueError:
        raise FeedError('respuesta no válida') from None


def normalize(raw, kind):
    """(valor, tipo) de un indicador, o (None, None) si no es una IP o red pública acotada o un dominio válido."""
    if not isinstance(raw, str) or len(raw) > 253:
        return None, None
    text = raw.strip().lower()
    if kind == 'ip':
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError:
            return None, None
        if not network.is_global or network.prefixlen < MIN_PREFIX[network.version]:
            return None, None
        if network.num_addresses == 1:
            return str(network.network_address), 'ip'
        return str(network), 'net'
    text = text.rstrip('.')
    return (text, 'domain') if DOMAIN.match(text) else (None, None)


def parse_feed(payload, kind):
    """Lista descargada → ({valor: (tipo, categorías)}, rechazados, {código: nombre}, tipo)."""
    if not isinstance(payload, dict) or not isinstance(payload.get('iocs'), dict):
        raise FeedError('lista no válida')
    kind = payload.get('kind') or kind
    if kind not in ('ip', 'domain'):
        raise FeedError('tipo de lista no admitido')
    names, ids = {}, {}
    meta = payload.get('meta')
    for items in (meta.values() if isinstance(meta, dict) else ()):
        for code, options in (items.items() if isinstance(items, dict) else ()):
            if isinstance(code, str) and isinstance(options, dict) and isinstance(options.get('id'), int):
                ids[options['id']] = code[:64]
                names[code[:64]] = str(options.get('name') or code)[:120]
    entries, rejected = {}, 0
    for raw, data in payload['iocs'].items():
        value, item_kind = normalize(raw, kind)
        if not value:
            rejected += 1
            continue
        if len(entries) >= MAX_ENTRIES:
            raise FeedError('lista demasiado grande')
        marks = data.get('m') if isinstance(data, dict) else None
        codes = sorted({ids[i] for i in marks if isinstance(i, int) and i in ids}) if isinstance(marks, list) else []
        entries[value] = (item_kind, codes[:MAX_CATEGORIES])
    return entries, rejected, names, kind


def _chunks(items):
    for start in range(0, len(items), CHUNK):
        yield items[start:start + CHUNK]


def apply(feed, entries):
    """Lleva la copia local de una lista a `entries` en transacciones cortas: borra lo que ya no está,
    añade lo nuevo y rehace lo que cambió de categorías. Devuelve (añadidos, borrados)."""
    existing = dict(ThreatIndicator.objects.filter(feed=feed).values_list('value', 'categories').iterator(chunk_size=5000))
    changed = [v for v, (_, codes) in entries.items() if v in existing and existing[v] != codes]
    removed = [v for v in existing if v not in entries]
    added = [v for v in entries if v not in existing]
    for batch in _chunks(removed + changed):
        with transaction.atomic():
            WorkerState.reserve(STATE)
            ThreatIndicator.objects.filter(feed=feed, value__in=batch).delete()
    for batch in _chunks(added + changed):
        with transaction.atomic():
            WorkerState.reserve(STATE)
            ThreatIndicator.objects.bulk_create([ThreatIndicator(feed=feed, kind=entries[v][0], value=v, categories=entries[v][1])
                                                 for v in batch], ignore_conflicts=True)
    return len(added), len(removed)


def _drop(feed):
    while True:
        batch = list(ThreatIndicator.objects.filter(feed=feed).values_list('pk', flat=True)[:CHUNK])
        if not batch:
            return
        with transaction.atomic():
            WorkerState.reserve(STATE)
            ThreatIndicator.objects.filter(pk__in=batch).delete()


def _iso(value):
    text = str(value or '')[:40]
    try:
        return text if parse_datetime(text) else ''
    except ValueError:
        return ''


def details():
    state = WorkerState.objects.filter(name=STATE).first()
    return dict(state.details) if state else {}


def _save(values):
    with transaction.atomic():
        WorkerState.reserve(STATE)
        WorkerState.objects.filter(name=STATE).update(details=values)


def usable_feeds(values=None, now=None):
    """Listas que se pueden usar: con clave, descargadas por completo y comprobadas hace menos de 36 horas."""
    values = details() if values is None else values
    now = now or timezone.now()
    if not values.get('configured'):
        return set()
    result = set()
    for name, row in (values.get('feeds') or {}).items():
        checked = parse_datetime(row.get('checked_at') or '')
        if row.get('licensed') and row.get('ready') and checked and now - checked <= FRESH:
            result.add(name)
    return result


def sync(now=None):
    """Descarga las listas con versión nueva. Devuelve cuántas se han descargado."""
    now = now or timezone.now()
    values = details()
    feeds = values.get('feeds') or {}
    key = api_key()
    values['configured'] = bool(key)
    downloaded = 0
    paused = parse_datetime(values.get('paused_until') or '')
    if key and not (paused and paused > now):
        try:
            index = _get('/licenses.php', None, key, MAX_INDEX)
            listed = index.get('feeds') if isinstance(index, dict) else None
            if not isinstance(listed, list):
                raise FeedError('índice no válido')
            wanted, seen = wanted_feeds(), set()
            for item in listed:
                name = str(item.get('feed_type') or '') if isinstance(item, dict) else ''
                if name not in wanted:
                    continue
                seen.add(name)
                row = feeds.setdefault(name, {})
                row['licensed'] = bool(item.get('licensed'))
                row['next_update'] = _iso(item.get('next_update'))
                if not row['licensed']:
                    continue
                updated = _iso(item.get('updated_at'))
                if row.get('ready') and updated and row.get('updated_at') == updated:
                    row['checked_at'] = now.isoformat()
                    continue
                payload = _get('/api.php', {'feed_type': name, 'type': 'opnsense'}, key, MAX_FEED)
                entries, rejected, names, kind = parse_feed(payload, str(item.get('type') or ''))
                added, removed = apply(name, entries)
                row.update(ready=True, kind=kind, updated_at=updated, generated_at=_iso(payload.get('generated_at')),
                           checked_at=now.isoformat(), count=len(entries), rejected=rejected, added=added, removed=removed)
                categories = values.setdefault('categories', {})
                for code, label in names.items():
                    if code in categories or len(categories) < MAX_CATEGORY_NAMES:
                        categories[code] = label
                downloaded += 1
                _save({**values, 'feeds': feeds})  # una lista ya cargada no se repite si la siguiente falla
            for name in [n for n in feeds if n not in seen]:
                _drop(name)  # ya no se pide o el índice ya no la ofrece: no se conserva
                feeds.pop(name)
            for name, row in feeds.items():
                if not row['licensed'] and row.get('ready'):
                    _drop(name)  # fuera de la licencia: se borra la copia y se deja la fila para explicarlo
                    row.update(ready=False, count=0)
            values.update(error='', error_status=None, last_ok_at=now.isoformat())
            values.pop('paused_until', None)
        except FeedError as exc:
            values.update(error=str(exc)[:120], error_status=exc.status)
            if exc.status in (401, 403, 429):
                values['paused_until'] = (now + PAUSE).isoformat()
    for name in list(feeds):
        checked = parse_datetime(feeds[name].get('checked_at') or '')
        if (checked and now - checked > PURGE_AFTER) or (not key and not checked):
            _drop(name)  # sin comprobar en 7 días: datos de licencia que ya no se usan
            feeds.pop(name)
    values.update(feeds=feeds, checked_at=now.isoformat())
    _save(values)
    _health(values, now)
    return downloaded


def _health(values, now):
    from .operations import set_issue
    usable = usable_feeds(values, now)
    licensed = [n for n, row in (values.get('feeds') or {}).items() if row.get('licensed')]
    problem = ''
    if values.get('configured') and values.get('error_status') in (401, 403):
        problem = 'Q-Feeds ha rechazado la clave o la licencia.'
    elif values.get('configured') and values.get('error') and not usable:
        problem = 'No se ha podido descargar: ' + values['error'] + '.'
    elif values.get('configured') and any(n not in usable for n in licensed if (values['feeds'][n].get('ready'))):
        problem = 'Alguna lista lleva más de 36 horas sin comprobarse y ha dejado de usarse.'
    if problem:
        set_issue(ISSUE, 'Inteligencia Q-Feeds sin actualizar', now=now,
                  details=problem + ' Revisar la clave y la licencia en el portal de Q-Feeds y el trabajo «Inteligencia Q-Feeds».')
    else:
        OperationalIssue.objects.filter(key=ISSUE, active=True).update(active=False, resolved_at=now)


def _network_index(feeds):
    index = defaultdict(list)
    for value, feed, codes in ThreatIndicator.objects.filter(feed__in=feeds, kind='net').values_list('value', 'feed', 'categories'):
        network = ipaddress.ip_network(value)
        index[(network.version, int(network.network_address) >> (network.max_prefixlen - BUCKET[network.version]))].append(
            (network, feed, codes))
    return index


def _networks_for(address, index):
    if not index:
        return []
    return [item for item in index.get((address.version, int(address) >> (address.max_prefixlen - BUCKET[address.version])), ())
            if address in item[0]]


def _label(codes, names):
    return [names.get(code, code) for code in codes]


def lookup(value, now=None):
    """Consulta local de una IP o un dominio: {'status': ok|not_configured|unavailable, 'hits': [...]}"""
    values = details()
    feeds = usable_feeds(values, now)
    if not values.get('configured'):
        return {'status': 'not_configured', 'hits': []}
    if not feeds:
        return {'status': 'unavailable', 'hits': []}
    names = values.get('categories') or {}
    text = (value or '').strip().lower()
    hits = []
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        address = None
    if address:
        for feed, codes in ThreatIndicator.objects.filter(feed__in=feeds, kind='ip', value=str(address)).values_list('feed', 'categories'):
            hits.append({'feed': feed, 'label': LABELS.get(feed, feed), 'match': str(address), 'categories': _label(codes, names)})
        for network, feed, codes in _networks_for(address, _network_index(feeds)):
            hits.append({'feed': feed, 'label': LABELS.get(feed, feed), 'match': str(network), 'categories': _label(codes, names)})
    else:
        domain = text.rstrip('.')
        for feed, codes in ThreatIndicator.objects.filter(feed__in=feeds, kind='domain', value=domain).values_list('feed', 'categories'):
            hits.append({'feed': feed, 'label': LABELS.get(feed, feed), 'match': domain, 'categories': _label(codes, names)})
    checked = [parse_datetime(values['feeds'][f]['checked_at']) for f in feeds]
    return {'status': 'ok', 'hits': hits, 'checked_at': min(checked)}


def refresh_matches(now=None):
    """IPs públicas de las detecciones de los clientes (7 días) que figuran en las listas vigentes.

    Se recalcula entero cada vez: sin listas vigentes no queda ninguna coincidencia.
    """
    from .reputation import protected_addresses
    now = now or timezone.now()
    values = details()
    feeds = usable_feeds(values, now)
    rows = []
    if feeds:
        names = values.get('categories') or {}
        exact = set(ThreatIndicator.objects.filter(feed__in=feeds, kind='ip').values_list('value', flat=True).iterator(chunk_size=10000))
        networks = _network_index(feeds)
        protected = protected_addresses()
        base = SecurityEvidence._base_manager.filter(observed_at__gte=now - WINDOW, observed_at__lte=now, client_scope_id__isnull=False)
        for role, field in (('source', 'source_ip'), ('destination', 'destination_ip')):
            matched = set()
            for value in base.exclude(**{field: None}).order_by().values_list(field, flat=True).distinct().iterator(chunk_size=5000):
                if value in protected:
                    continue
                if value in exact or _networks_for(ipaddress.ip_address(value), networks):
                    matched.add(value)
            rows.extend(_aggregate(base, role, field, sorted(matched), feeds, networks, names))
    rows.sort(key=lambda r: (-r.allowed, -r.events, r.ip))
    rows = rows[:MAX_MATCHES]
    listed = set()
    sources = sorted({r.ip for r in rows if r.role == 'source'})
    for batch in _chunks(sources):
        listed |= set(IpReputation.objects.filter(ip__in=batch, listed=True, lists_checked_at__gte=now - LISTS_FRESH)
                      .values_list('ip', flat=True))
    for row in rows:
        row.crowdsec_listed = row.ip in listed
        row.updated_at = now
    with transaction.atomic():
        WorkerState.reserve(STATE)
        ThreatIntelMatch._base_manager.all().delete()
        ThreatIntelMatch._base_manager.bulk_create(rows)
    return len(rows)


def _aggregate(base, role, field, values, feeds, networks, names):
    clients = set(Client._base_manager.values_list('pk', flat=True))
    rows = []
    for batch in _chunks(values):
        hits = defaultdict(lambda: (set(), set()))
        for value, feed, codes in ThreatIndicator.objects.filter(feed__in=feeds, kind='ip', value__in=batch).values_list('value', 'feed', 'categories'):
            hits[value][0].add(feed)
            hits[value][1].update(codes)
        for value in batch:
            for _, feed, codes in _networks_for(ipaddress.ip_address(value), networks):
                hits[value][0].add(feed)
                hits[value][1].update(codes)
        peers = defaultdict(list)
        if role == 'destination':
            for item in (base.filter(destination_ip__in=batch).exclude(source_ip=None).order_by()
                         .values('client_scope_id', 'destination_ip', 'source_ip').annotate(n=Count('uid')).order_by('-n')):
                key = (item['client_scope_id'], item['destination_ip'])
                if len(peers[key]) < 3:
                    peers[key].append(item['source_ip'])
        for item in (base.filter(**{field + '__in': batch}).order_by().values('client_scope_id', field)
                     .annotate(events=Count('uid'), allowed=Count('uid', filter=Q(action='allowed')),
                               first=Min('observed_at'), last=Max('observed_at'))):
            if item['client_scope_id'] not in clients:
                continue
            ip = item[field]
            found_feeds, codes = hits[ip]
            rows.append(ThreatIntelMatch(client_id=item['client_scope_id'], ip=ip, role=role, feeds=sorted(found_feeds),
                                         categories=_label(sorted(codes), names)[:MAX_CATEGORIES], events=item['events'],
                                         allowed=item['allowed'], first_seen=item['first'], last_seen=item['last'],
                                         peers=peers.get((item['client_scope_id'], ip), [])))
    return rows


def refresh(now=None):
    """Trabajo `threat_intel`: descarga lo que haya cambiado y recalcula las coincidencias."""
    sync(now)
    return refresh_matches(now)


@login_required
@never_cache
@require_GET
def overview(request):
    if not request.user.has_perm('core.manage_operations'):
        return HttpResponseForbidden('Permiso de operaciones requerido.')
    from .investigation import ip_url
    values = details()
    now = timezone.now()
    usable = usable_feeds(values, now)
    feeds = [{'name': name, 'label': LABELS.get(name, name), 'usable': name in usable, **row,
              'checked': parse_datetime(row.get('checked_at') or ''), 'generated': parse_datetime(row.get('generated_at') or ''),
              'next': parse_datetime(row.get('next_update') or '')}
             for name, row in sorted((values.get('feeds') or {}).items())]
    query = request.GET.get('q', '').strip()[:253]
    result, invalid = None, False
    if query:
        try:
            ipaddress.ip_address(query)
            valid = True
        except ValueError:
            valid = bool(DOMAIN.match(query.lower().rstrip('.')))
        if valid:
            result = lookup(query, now)
        else:
            invalid = True
    matches = ThreatIntelMatch.objects.select_related('client')
    outbound = list(matches.filter(role='destination')[:200])
    inbound_qs = matches.filter(role='source')
    inbound = list(inbound_qs[:100])
    for row in outbound + inbound:
        row.url = ip_url(row.ip, row.client_id)
    summary = inbound_qs.aggregate(total=Count('id'), only_here=Count('id', filter=Q(crowdsec_listed=False)),
                                   allowed=Count('id', filter=Q(allowed__gt=0)))
    return render(request, 'threat_intel.html', {
        'values': values, 'feeds': feeds, 'configured': values.get('configured'), 'usable': bool(usable),
        'last_ok': parse_datetime(values.get('last_ok_at') or ''), 'checked': parse_datetime(values.get('checked_at') or ''),
        'query': query, 'result': result, 'invalid': invalid, 'outbound': outbound, 'inbound': inbound,
        'outbound_allowed': sum(1 for r in outbound if r.allowed), 'summary': summary})

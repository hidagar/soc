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

Plan A (uso central con un plan de pago): las conexiones salientes hacia destinos de las listas pasan a ser
trabajo del SOC. Cada una se revisa («Sin riesgo» o «Abrir incidencia»); la decisión se guarda en
`ThreatIntelReview` y el destino vuelve a la cola si hay tráfico nuevo después. Una evolución diaria permite
comparar planes (gratuito, prueba Premium) con los mismos clientes. Nada de esto llega al cliente salvo lo que
el SOC publique de una incidencia.
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

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.db.models import Count, Max, Min, Q
from django.http import Http404, HttpResponseForbidden
from django.shortcuts import redirect, render
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET, require_POST

from .models import (Client, Incident, IncidentUpdate, IpReputation, OperationalIssue, SecurityEvidence, ThreatIndicator,
                     ThreatIntelLookup, ThreatIntelMatch, ThreatIntelReview, WorkerState)
from .security import audit

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
HISTORY_DAYS = 120
LICENSE_ISSUE = 'platform:threat-intel-license'
LICENSE_NOTICE = timedelta(days=30)
USAGE_EVERY = timedelta(hours=24)  # consultar el cupo no gasta consultas
LOOKUP_REUSE = timedelta(days=7)
LOOKUPS_PER_RUN = 10
MAX_LOOKUP = 256 * 1024
MAX_OFFERED = 50
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
            company = index.get('company_info') if isinstance(index.get('company_info'), dict) else {}
            values['license'] = {'expires': _iso(company.get('token_expiration')), 'premium': bool(company.get('premium_access')),
                                 'features': [str(f.get('name'))[:60] for f in index.get('features') or []
                                              if isinstance(f, dict) and f.get('licensed')][:20]}
            _lookup_usage(key, values, now)
            wanted, seen = wanted_feeds(), set()
            # Lo que ofrece la licencia, aunque no se descargue: tras cambiar de plan se ve qué listas añadir.
            values['offered'] = [{'name': str(item.get('feed_type')), 'type': str(item.get('type') or '')[:16],
                                  'licensed': bool(item.get('licensed')), 'wanted': item.get('feed_type') in wanted}
                                 for item in listed[:MAX_OFFERED]
                                 if isinstance(item, dict) and FEED_NAME.match(str(item.get('feed_type') or ''))]
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
                    if 'categorized' not in row:  # copias anteriores a este dato: se calcula una vez
                        row['categorized'] = sum(1 for codes in ThreatIndicator.objects.filter(feed=name).values_list(
                            'categories', flat=True).iterator(chunk_size=5000) if codes)
                    continue
                payload = _get('/api.php', {'feed_type': name, 'type': 'opnsense'}, key, MAX_FEED)
                entries, rejected, names, kind = parse_feed(payload, str(item.get('type') or ''))
                added, removed = apply(name, entries)
                row.update(ready=True, kind=kind, updated_at=updated, generated_at=_iso(payload.get('generated_at')),
                           checked_at=now.isoformat(), count=len(entries), rejected=rejected, added=added, removed=removed,
                           categorized=sum(1 for _, codes in entries.values() if codes))
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
    _license_health(values, now)
    return downloaded


def _lookup_usage(key, values, now):
    """Cupo mensual de la API IOC Lookup (`action=usage`, no consume consultas), una vez al día.

    Un 403 significa que la licencia no la incluye. Va aparte de la descarga: un rechazo aquí no pausa las listas.
    """
    current = values.get('lookup') or {}
    checked = parse_datetime(current.get('checked_at') or '')
    if checked and now - checked < USAGE_EVERY:
        return
    try:
        usage = _get('/ioc_lookup.php', {'action': 'usage'}, key, MAX_INDEX)
    except FeedError as exc:
        if exc.status in (401, 403):
            values['lookup'] = {'available': False, 'checked_at': now.isoformat()}
        return
    values['lookup'] = {'available': True, 'checked_at': now.isoformat(), **_quota(usage)}


def _quota(data):
    def number(value):
        return value if isinstance(value, int) and value >= 0 else None
    data = data if isinstance(data, dict) else {}
    return {'limit': number(data.get('lookups_limit_month')), 'used': number(data.get('lookups_used_month')),
            'remaining': number(data.get('lookups_remaining_month')), 'reset': str(data.get('quota_reset_at') or '')[:20]}


def license_expiry(values=None):
    values = details() if values is None else values
    return parse_datetime((values.get('license') or {}).get('expires') or '')


def _license_health(values, now):
    from .operations import set_issue
    expires = license_expiry(values)
    if values.get('configured') and expires and expires - now <= LICENSE_NOTICE:
        text = ('La licencia de Q-Feeds del SOC caducó el ' if expires <= now else 'La licencia de Q-Feeds del SOC caduca el ')
        set_issue(LICENSE_ISSUE, 'Licencia de Q-Feeds del SOC', now=now, severity='critical' if expires <= now else 'warning',
                  details=text + timezone.localtime(expires).strftime('%d/%m/%Y') + '. Renovarla en el portal de Q-Feeds.')
    else:
        OperationalIssue.objects.filter(key=LICENSE_ISSUE, active=True).update(active=False, resolved_at=now)


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
    if values.get('configured'):
        _record_history(rows, feeds, now)
    return len(rows)


def _record_history(rows, feeds, now):
    """Una fila por día con lo que aportan las listas vigentes (ventana de 7 días): sirve para comparar planes."""
    values = details()
    states = values.get('feeds') or {}
    outbound = [r for r in rows if r.role == 'destination']
    inbound = [r for r in rows if r.role == 'source']
    reviews = ThreatIntelReview._base_manager.filter(ip__in=[r.ip for r in outbound]).select_related('incident')
    day = timezone.localdate(now).isoformat()
    entry = {'date': day, 'feeds': sorted(feeds), 'indicators': sum(states[f].get('count') or 0 for f in feeds),
             'categorized': sum(states[f].get('categorized') or 0 for f in feeds),
             'outbound': len(outbound), 'outbound_allowed': sum(1 for r in outbound if r.allowed),
             'pending': len(pending(outbound, reviews)), 'inbound': len(inbound),
             'inbound_only': sum(1 for r in inbound if not r.crowdsec_listed),
             'clients': len({r.client_id for r in rows})}
    history = [h for h in values.get('history') or [] if isinstance(h, dict) and h.get('date') != day] + [entry]
    values['history'] = history[-HISTORY_DAYS:]
    _save(values)


def needs_review(match, review):
    """Un destino saliente necesita revisión si nadie lo ha revisado o si hay tráfico nuevo tras la decisión."""
    if review is None:
        return True
    if review.decision == 'dismissed':
        return match.last_seen > review.reviewed_at
    incident = review.incident
    if incident is None:  # la incidencia ya no existe
        return match.last_seen > review.reviewed_at
    if incident.status != 'resolved':
        return False
    return match.last_seen > (incident.resolved_at or review.reviewed_at)


def pending(matches, reviews):
    """Destinos (ThreatIntelMatch) que esperan revisión; añade `.review` a cada uno. Permitidos primero."""
    index = {(r.client_id, r.ip): r for r in reviews}
    result = []
    for match in matches:
        match.review = index.get((match.client_id, match.ip))
        match.needs_review = needs_review(match, match.review)
        if match.needs_review:
            result.append(match)
    return sorted(result, key=lambda m: (-m.allowed, -m.events, m.ip))


def review_queue(client_id=None):
    """Destinos salientes por revisar dentro del ámbito del usuario (bandeja de trabajo y menú)."""
    matches = ThreatIntelMatch.objects.filter(role='destination').select_related('client')
    reviews = ThreatIntelReview.objects.select_related('incident')
    if client_id:
        matches, reviews = matches.filter(client_id=client_id), reviews.filter(client_id=client_id)
    matches = list(matches)
    return pending(matches, reviews.filter(ip__in={m.ip for m in matches}))


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
    # El plan gratuito publica solo el indicador (comprobado con una clave real): sin categoría por entrada.
    known = [f for f in feeds if f['usable'] and 'categorized' in f]
    uncategorized = bool(known) and not any(f['categorized'] for f in known)
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
    reviews = ThreatIntelReview.objects.select_related('incident', 'reviewed_by').filter(ip__in={r.ip for r in outbound})
    waiting = pending(outbound, reviews)
    inbound_qs = matches.filter(role='source')
    inbound = list(inbound_qs[:100])
    for row in outbound + inbound:
        row.url = ip_url(row.ip, row.client_id)
    summary = inbound_qs.aggregate(total=Count('id'), only_here=Count('id', filter=Q(crowdsec_listed=False)),
                                   allowed=Count('id', filter=Q(allowed__gt=0)))
    return render(request, 'threat_intel.html', {
        'values': values, 'feeds': feeds, 'configured': values.get('configured'), 'usable': bool(usable), 'uncategorized': uncategorized,
        'last_ok': parse_datetime(values.get('last_ok_at') or ''), 'checked': parse_datetime(values.get('checked_at') or ''),
        'query': query, 'result': result, 'invalid': invalid, 'outbound': outbound, 'inbound': inbound,
        'outbound_allowed': sum(1 for r in outbound if r.allowed), 'summary': summary, 'waiting': len(waiting),
        'offered': values.get('offered') or [], 'history': _history(values),
        'can_open_incident': request.user.has_perm('core.add_incident'), 'license_info': values.get('license') or {},
        'license_expires': license_expiry(values), 'lookup_info': values.get('lookup') or {}, 'can_lookup': lookup_available(values),
        'context': _context(query, result, now)})


@login_required
@require_POST
def review(request):
    """Decisión sobre un destino saliente: «Sin riesgo» o abrir una incidencia interna."""
    if not request.user.has_perm('core.manage_operations'):
        return HttpResponseForbidden('Permiso de operaciones requerido.')
    client_id, ip = request.POST.get('client', ''), request.POST.get('ip', '').strip()
    if not client_id.isdigit():
        raise Http404
    # Solo un destino que figura ahora en las coincidencias y dentro del ámbito del usuario.
    match = ThreatIntelMatch.objects.filter(role='destination', client_id=int(client_id), ip=ip).select_related('client').first()
    if match is None:
        messages.warning(request, 'Ese destino ya no figura en las coincidencias de los últimos 7 días.')
        return redirect(reverse_back(request))
    action = request.POST.get('action')
    now = timezone.now()
    if action == 'dismiss':
        reason = ' '.join(request.POST.get('reason', '').split())[:160]
        with transaction.atomic():
            ThreatIntelReview.objects.update_or_create(client=match.client, ip=match.ip, defaults={
                'decision': 'dismissed', 'reason': reason, 'incident': None, 'reviewed_by': request.user, 'reviewed_at': now})
            audit('threat_intel.dismissed', match.client, {'decision': 'dismissed'})
        messages.success(request, f'{match.ip} marcado sin riesgo para {match.client.name}. Volverá si hay tráfico nuevo hacia ese destino.')
        return redirect(reverse_back(request))
    if action != 'incident':
        return HttpResponseForbidden('Acción no válida.')
    if not request.user.has_perm('core.add_incident'):
        return HttpResponseForbidden('Tu cuenta no puede abrir incidencias.')
    current = ThreatIntelReview.objects.filter(client=match.client, ip=match.ip, decision='incident').select_related('incident').first()
    if current and current.incident and current.incident.status != 'resolved':
        return redirect('incident_detail', pk=current.incident_id)
    evidence = (SecurityEvidence._base_manager.filter(client_scope_id=match.client_id, destination_ip=match.ip)
                .select_related('device__site').order_by('-observed_at').first())
    device = evidence.device if evidence and evidence.device.site.client_id == match.client_id else None
    categories = ', '.join(match.categories) or 'sin categoría en el plan actual'
    lines = [f'Conexiones de equipos del cliente hacia {match.ip}, que figura en las listas de inteligencia de amenazas del SOC '
             f'(Q-Feeds: {", ".join(match.feeds)}; {categories}).',
             f'Últimos 7 días: {match.events} detecciones, {match.allowed} permitidas por el firewall. '
             f'Primera {timezone.localtime(match.first_seen):%d/%m/%Y %H:%M}, última {timezone.localtime(match.last_seen):%d/%m/%Y %H:%M}.',
             'Equipos internos: ' + (', '.join(match.peers) or 'sin identificar') + '.',
             'Figurar en una lista no acredita una infección: revisar el equipo de origen, el proceso que abre la conexión y si el destino es legítimo.']
    with transaction.atomic():
        incident = Incident.objects.create(
            client=match.client, site=device.site if device else None, device=device,
            title=f'Conexión hacia un destino de las listas de amenazas: {match.ip}'[:220], description='\n\n'.join(lines),
            severity='high' if match.allowed else 'medium', owner=request.user, observed_at=match.first_seen)
        IncidentUpdate.objects.create(incident=incident, author=request.user, text='Abierta desde la revisión de Q-Feeds.')
        ThreatIntelReview.objects.update_or_create(client=match.client, ip=match.ip, defaults={
            'decision': 'incident', 'reason': '', 'incident': incident, 'reviewed_by': request.user, 'reviewed_at': now})
        audit('threat_intel.incident', match.client, {'incident_id': incident.pk})
    messages.success(request, 'Incidencia interna abierta. El cliente no la ve hasta que se publique.')
    return redirect('incident_detail', pk=incident.pk)


def _history(values):
    """Últimos 30 días de la evolución, el más reciente primero, con la fecha como fecha."""
    from datetime import date
    rows = []
    for item in reversed(values.get('history') or []):
        try:
            rows.append({**item, 'day': date.fromisoformat(item.get('date') or '')})
        except (TypeError, ValueError):
            continue
        if len(rows) == 30:
            break
    return rows


def reverse_back(request):
    """Vuelve a la bandeja si la decisión se tomó allí; si no, a la página de Q-Feeds."""
    from django.urls import reverse
    if request.POST.get('back') == 'work_queue':
        return reverse('work_queue') + '#destinos-maliciosos'
    return reverse('threat_intel') + '#salientes'



def _clean_ioc(ioc):
    """Resumen acotado de la respuesta de IOC Lookup: nunca se guarda ni se muestra la respuesta cruda."""
    if not isinstance(ioc, dict):
        return {}

    def text(value, size):
        return str(value)[:size] if isinstance(value, (str, int, float)) else ''

    def stamp(value):
        return _iso(value)
    geo = next((e.get('data') for e in ioc.get('enrichments') or [] if isinstance(e, dict) and e.get('source') == 'geoip'
                and isinstance(e.get('data'), dict)), {}) or {}
    linked = ioc.get('linked_iocs') if isinstance(ioc.get('linked_iocs'), dict) else {}
    return {
        'verdict': text(ioc.get('verdict'), 20), 'score': ioc.get('score') if isinstance(ioc.get('score'), int) else None,
        'first_seen': stamp(ioc.get('first_seen')), 'last_seen': stamp(ioc.get('last_seen')),
        'sources': ioc.get('source_count') if isinstance(ioc.get('source_count'), int) else None,
        'false_positive': bool(ioc.get('is_false_positive')),
        'reasons': [text(r, 160) for r in (ioc.get('verdict_reasons') or [])[:8] if isinstance(r, str)],
        'tags': [text(t.get('name'), 40) for t in (ioc.get('tags') or [])[:10] if isinstance(t, dict) and t.get('name')],
        'mitre': [{'id': text(m.get('id'), 20), 'name': text(m.get('name'), 80),
                   'tactics': [text(t.get('name'), 60) for t in (m.get('tactics') or [])[:3] if isinstance(t, dict)]}
                  for m in (ioc.get('mitre_attack') or [])[:10] if isinstance(m, dict)],
        'country': text(geo.get('country_name') or geo.get('country'), 60), 'asn': text(geo.get('asn_org'), 120),
        'linked': sum(v for v in (linked.get('outbound_total'), linked.get('inbound_total')) if isinstance(v, int)),
    }


def process_lookups(now=None):
    """Trabajo `qfeeds_lookup`: envía las consultas en cola (como mucho 10 por pasada). Devuelve cuántas resolvió."""
    now = now or timezone.now()
    key = api_key()
    queued = list(ThreatIntelLookup.objects.filter(status='queued').order_by('requested_at', 'pk')[:LOOKUPS_PER_RUN])
    if not queued:
        return 0
    if not key:
        ThreatIntelLookup.objects.filter(pk__in=[q.pk for q in queued]).update(status='failed', error='Q-Feeds sin configurar.',
                                                                              done_at=now)
        return 0
    done = 0
    quota = None
    for item in queued:
        try:
            data = _get('/ioc_lookup.php', {'action': 'ioc', 'value': item.value}, key, MAX_LOOKUP)
        except FeedError as exc:
            if exc.status == 429:
                break  # cupo agotado o límite de peticiones: se queda en cola
            error = {403: 'La licencia no incluye las consultas de contexto o no tienen cupo.'}.get(exc.status, str(exc))
            ThreatIntelLookup.objects.filter(pk=item.pk).update(status='failed', error=error[:160], done_at=now)
            continue
        data = data if isinstance(data, dict) else {}
        quota = _quota(data.get('meta'))
        ThreatIntelLookup.objects.filter(pk=item.pk).update(status='done', matched=bool(data.get('matched')),
                                                            result=_clean_ioc(data.get('ioc')), done_at=now)
        done += 1
    if quota and quota.get('remaining') is not None:
        values = details()
        values['lookup'] = {**(values.get('lookup') or {}), 'available': True, **quota}
        _save(values)
    return done


VERDICTS = {'malicious': 'Maliciosa', 'suspicious': 'Sospechosa', 'benign': 'Benigna', 'unknown': 'Sin veredicto'}


def _context(query, result, now):
    """Última consulta de contexto del indicador buscado, preparada para la página."""
    if not result or not result.get('hits'):
        return None
    item = ThreatIntelLookup.objects.filter(value=query.lower().rstrip('.')).order_by('-requested_at').first()
    if item is None:
        return None
    data = item.result or {}
    item.verdict_label = VERDICTS.get(data.get('verdict'), (data.get('verdict') or 'Sin veredicto').capitalize())
    item.first = parse_datetime(data.get('first_seen') or '')
    item.last = parse_datetime(data.get('last_seen') or '')
    item.fresh = item.status == 'queued' or bool(item.status == 'done' and item.done_at and now - item.done_at < LOOKUP_REUSE)
    return item


def lookup_available(values=None):
    values = details() if values is None else values
    info = values.get('lookup') or {}
    return bool(values.get('configured') and info.get('available') and info.get('remaining') != 0)


@login_required
@require_POST
def lookup_request(request):
    """Encola una consulta de contexto. Solo indicadores que ya están en las listas descargadas."""
    from django.urls import reverse
    if not request.user.has_perm('core.manage_operations'):
        return HttpResponseForbidden('Permiso de operaciones requerido.')
    value = request.POST.get('value', '').strip().lower()[:253]
    back = reverse('threat_intel') + '?' + urlparse.urlencode({'q': value}) + '#consulta'
    if not lookup_available():
        messages.error(request, 'La licencia de Q-Feeds no incluye consultas de contexto o no queda cupo este mes.')
        return redirect(back)
    found = lookup(value)
    if found['status'] != 'ok' or not found['hits']:
        messages.error(request, 'Solo se consultan indicadores que ya están en las listas descargadas de Q-Feeds.')
        return redirect(back)
    recent = ThreatIntelLookup.objects.filter(value=value).exclude(status='failed').order_by('-requested_at').first()
    if recent and (recent.status == 'queued' or (recent.done_at and timezone.now() - recent.done_at < LOOKUP_REUSE)):
        messages.info(request, 'Ya hay una consulta reciente de este indicador: no se repite para no gastar cupo.')
        return redirect(back)
    ThreatIntelLookup.objects.create(value=value, requested_by=request.user)
    audit('threat_intel.lookup', None, {'status': 'queued'})
    messages.success(request, 'Consulta en cola: el resultado aparece aquí en un minuto aproximadamente.')
    return redirect(back)

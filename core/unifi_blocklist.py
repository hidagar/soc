"""Listas de bloqueo del SOC en consolas UniFi (Network 9/10, API oficial por el conector de Site Manager).

UniFi no descarga listas por URL: el SOC escribe las IPs en una «traffic matching list» de tipo
IPV4_ADDRESSES que el operador creó en UniFi y que usa una política de bloqueo creada también por
él. Frenos:
- Solo listas cuyo nombre empieza por «SOC» y de tipo IPV4_ADDRESSES; el SOC nunca crea ni
  modifica políticas ni otras listas.
- El formato de cada entrada se aprende de la propia lista (por eso se crea con una IP de prueba):
  no se adivina el esquema de escritura.
- Solo se escribe cuando cambia el contenido, se lee de nuevo para verificarlo y cualquier
  diferencia queda como error. IPv6 no cabe en una lista IPv4 y se omite.
- Lista vacía, detenida o caducada: se escribe solo PLACEHOLDER (documentación, no enrutable),
  porque UniFi puede no admitir listas vacías.
"""
import hashlib
import ipaddress
import json
import re
from urllib import error, parse, request

from django.utils import timezone

from .models import BlocklistFeed, UnifiBlocklistBinding
from .unifi_cloud import UnifiCloudError, _NoRedirect, decrypt_api_key

PREFIX = 'SOC'
PLACEHOLDER = '192.0.2.1'  # TEST-NET-1 (RFC 5737): no corresponde a ningún equipo real
MAX_ITEMS = 4000
UUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z')


def _uuid(value):
    if not isinstance(value, str) or not UUID.fullmatch(value):
        raise UnifiCloudError('Identificador de UniFi no válido.')
    return value


def call(api_key, host_id, path, method='GET', payload=None):
    """Llamada a la API oficial de Network por el conector, con lista cerrada de rutas y métodos."""
    if not isinstance(host_id, str) or not re.fullmatch(r'[A-Za-z0-9:-]{1,200}', host_id):
        raise UnifiCloudError('Consola UniFi no válida.')
    allowed = (method == 'GET' and (path == '/v1/sites' or re.fullmatch(r'/v1/sites/[0-9a-f-]{36}/traffic-matching-lists', path))) or (
        method in ('GET', 'PUT') and re.fullmatch(r'/v1/sites/[0-9a-f-]{36}/traffic-matching-lists/[0-9a-f-]{36}', path))
    if not allowed:
        raise UnifiCloudError('Operación de UniFi no permitida.')
    collection = path == '/v1/sites' or path.endswith('/traffic-matching-lists')
    query = '?' + parse.urlencode({'offset': 0, 'limit': 200}) if collection else ''
    url = ('https://api.ui.com/v1/connector/consoles/' + parse.quote(host_id, safe='') + '/proxy/network/integration' + path + query)
    data = json.dumps(payload).encode() if payload is not None else None
    req = request.Request(url, data=data, method=method, headers={'Accept': 'application/json', 'Content-Type': 'application/json',
                                                                  'X-API-Key': api_key})
    try:
        with request.build_opener(_NoRedirect()).open(req, timeout=25) as response:
            raw = response.read(4000001)
    except error.HTTPError as exc:
        if exc.code in (401, 403):
            raise UnifiCloudError('La clave de UniFi no permite esta operación (revisar permisos de escritura).') from None
        raise UnifiCloudError(f'UniFi respondió HTTP {exc.code}.') from None
    except (error.URLError, TimeoutError, OSError):
        raise UnifiCloudError('No se pudo conectar con la consola UniFi.') from None
    if len(raw) > 4000000:
        raise UnifiCloudError('Respuesta de UniFi demasiado grande.')
    try:
        result = json.loads(raw) if raw.strip() else {}
    except ValueError:
        raise UnifiCloudError('UniFi devolvió una respuesta no válida.') from None
    if not isinstance(result, dict):
        raise UnifiCloudError('UniFi devolvió una respuesta inesperada.')
    return result


def item_format(items):
    """Formato de las entradas de una lista existente: 'typed' ({type, value}) o 'plain' (texto)."""
    if not isinstance(items, list) or not items:
        return ''
    if all(isinstance(i, dict) and set(i) == {'type', 'value'} and i['type'] in ('IP_ADDRESS', 'SUBNET') for i in items):
        return 'typed'
    if all(isinstance(i, str) for i in items):
        return 'plain'
    return ''


def encode(values, fmt):
    items = []
    for value in values:
        network = ipaddress.ip_network(value, strict=False)
        text = str(network.network_address) if network.num_addresses == 1 else str(network)
        if fmt == 'typed':
            items.append({'type': 'IP_ADDRESS' if network.num_addresses == 1 else 'SUBNET', 'value': text})
        else:
            items.append(text)
    return items


def decode(items):
    values = []
    for item in items or []:
        value = item.get('value') if isinstance(item, dict) else item
        try:
            network = ipaddress.ip_network(str(value), strict=False)
        except ValueError:
            continue
        values.append(str(network.network_address) if network.num_addresses == 1 else str(network))
    return sorted(values)


def fingerprint(values):
    return hashlib.sha256(json.dumps(sorted(values)).encode()).hexdigest()


def default_site(api_key, host_id):
    sites = call(api_key, host_id, '/v1/sites').get('data')
    default = [s for s in sites or [] if isinstance(s, dict) and s.get('internalReference') == 'default']
    if len(default) != 1:
        raise UnifiCloudError('No se identifica el sitio principal de la consola UniFi.')
    return _uuid(default[0].get('id'))


def candidates(device):
    """Listas IPv4 «SOC…» de la consola, con su formato aprendido. Solo nombres y recuentos, nunca IPs."""
    connection = device.unifi_cloud
    key = decrypt_api_key(connection.encrypted_api_key)
    site = default_site(key, connection.remote_host_id)
    rows = call(key, connection.remote_host_id, f'/v1/sites/{site}/traffic-matching-lists').get('data') or []
    result = []
    for row in rows:
        if not isinstance(row, dict) or row.get('type') != 'IPV4_ADDRESSES':
            continue
        name = str(row.get('name') or '')[:240]
        if not name.upper().startswith(PREFIX):
            continue
        result.append({'id': _uuid(row.get('id')), 'name': name, 'count': len(row.get('items') or []),
                       'format': item_format(row.get('items')), 'site': site})
    return result


def desired(binding, now=None):
    """IPs que deben estar en la lista UniFi: las que el SOC sirve a ese cliente, solo IPv4 y con tope."""
    from .blocklist import servable
    feed = BlocklistFeed._base_manager.filter(client_id=binding.device.site.client_id).select_related('client').first()
    values = []
    if feed and binding.enabled and binding.device.active:
        for value in servable(feed, now, outbound=binding.direction == 'out'):
            if ipaddress.ip_network(value, strict=False).version == 4:
                values.append(value)
    return sorted(values[:MAX_ITEMS]) or [PLACEHOLDER]


def sync(binding, now=None, force=False):
    """Escribe la lista si cambió y la verifica. Devuelve True si quedó al día."""
    now = now or timezone.now()
    values = desired(binding, now)
    target = fingerprint(values)
    if target == binding.pushed_fingerprint and not force and not binding.error:
        return True
    connection = binding.device.unifi_cloud
    path = f'/v1/sites/{_uuid(binding.site_id)}/traffic-matching-lists/{_uuid(binding.list_id)}'
    try:
        key = decrypt_api_key(connection.encrypted_api_key)
        current = call(key, connection.remote_host_id, path)
        current = current.get('data', current) if isinstance(current.get('data'), dict) else current
        name = str(current.get('name') or '')
        if current.get('type') != 'IPV4_ADDRESSES' or not name.upper().startswith(PREFIX):
            raise UnifiCloudError('La lista de UniFi ya no es una lista IPv4 «SOC…»: no se modifica.')
        body = {k: current[k] for k in ('type', 'name', 'description') if k in current}
        body['items'] = encode(values, binding.item_format)
        call(key, connection.remote_host_id, path, 'PUT', body)
        check = call(key, connection.remote_host_id, path)
        check = check.get('data', check) if isinstance(check.get('data'), dict) else check
        if fingerprint(decode(check.get('items'))) != target:
            raise UnifiCloudError('UniFi no confirmó el contenido escrito; se reintentará.')
    except UnifiCloudError as exc:
        UnifiBlocklistBinding._base_manager.filter(pk=binding.pk).update(error=str(exc)[:240], error_at=now)
        return False
    UnifiBlocklistBinding._base_manager.filter(pk=binding.pk).update(
        pushed_fingerprint=target, pushed_count=0 if values == [PLACEHOLDER] else len(values), synced_at=now, error='',
        error_at=None)
    return True


def sync_all(now=None):
    """Tras recalcular las listas: lleva cada lista UniFi vinculada al contenido que sirve el SOC."""
    done = 0
    bindings = UnifiBlocklistBinding._base_manager.filter(device__unifi_cloud__isnull=False).select_related(
        'device__site', 'device__unifi_cloud')
    for binding in bindings:
        done += int(sync(binding, now))
    return done

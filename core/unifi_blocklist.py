"""Listas de bloqueo del SOC en consolas UniFi (Network 9/10, API oficial por el conector de Site Manager).

UniFi no descarga listas por URL: el SOC escribe las IPs en una «traffic matching list» de tipo
IPV4_ADDRESSES, creada por el SOC desde el panel o por el operador en UniFi, y que usa una política
de bloqueo. Frenos:
- Solo listas cuyo nombre empieza por «SOC» y de tipo IPV4_ADDRESSES; nunca se tocan las demás.
- El formato de cada entrada se aprende de la propia lista (se crea con una IP de prueba): no se
  adivina el esquema de escritura.
- Solo se escribe cuando cambia el contenido, se lee de nuevo para verificarlo y cualquier
  diferencia queda como error. IPv6 no cabe en una lista IPv4 y se omite.
- Lista vacía, detenida o caducada: se escribe solo PLACEHOLDER (documentación, no enrutable),
  porque UniFi puede no admitir listas vacías.
- Políticas: el SOC puede crear las suyas (nombre «SOC…», acción BLOCK) y siempre nacen
  desactivadas; activarlas es una acción explícita con MFA. Solo modifica o retira políticas
  cuyo nombre empieza por «SOC» y cuyo identificador guardó al crearlas.
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


def call(api_key, host_id, path, method='GET', payload=None, query=None):
    """Llamada a la API oficial de Network por el conector, con lista cerrada de rutas y métodos."""
    if not isinstance(host_id, str) or not re.fullmatch(r'[A-Za-z0-9:-]{1,200}', host_id):
        raise UnifiCloudError('Consola UniFi no válida.')
    site_path = r'/v1/sites/[0-9a-f-]{36}/'
    allowed = (method == 'GET' and (path == '/v1/sites' or re.fullmatch(
        site_path + r'(?:traffic-matching-lists|firewall/zones|firewall/policies)', path))) or (
        # Alta solo de políticas «SOC…» de bloqueo y desactivadas (ver create_policies).
        method == 'POST' and re.fullmatch(site_path + r'firewall/policies', path) and isinstance(payload, dict)
        and str(payload.get('name', '')).startswith(PREFIX) and payload.get('enabled') is False
        and payload.get('action') == {'type': 'BLOCK'}) or (
        # Una política concreta: el código comprueba antes que es «SOC…» y que la creó el SOC.
        method in ('GET', 'PUT', 'DELETE') and re.fullmatch(site_path + r'firewall/policies/[0-9a-f-]{36}', path)) or (
        # Alta solo de listas «SOC…» de IPv4 con la dirección de documentación (ver create_list).
        method == 'POST' and re.fullmatch(r'/v1/sites/[0-9a-f-]{36}/traffic-matching-lists', path)
        and isinstance(payload, dict) and payload.get('type') == 'IPV4_ADDRESSES'
        and str(payload.get('name', '')).startswith(PREFIX)) or (
        method in ('GET', 'PUT') and re.fullmatch(r'/v1/sites/[0-9a-f-]{36}/traffic-matching-lists/[0-9a-f-]{36}', path)) or (
        # Orden de un cruce de zonas: solo identificadores; move_first comprueba que no falta ninguno.
        method in ('GET', 'PUT') and re.fullmatch(site_path + r'firewall/policies/ordering', path)
        and _ordering_query(query) and (method == 'GET' or _ordering_body(payload)))
    if not allowed:
        raise UnifiCloudError('Operación de UniFi no permitida.')
    collection = method == 'GET' and (path == '/v1/sites' or path.endswith(('/traffic-matching-lists', '/zones', '/policies')))
    query = '?' + parse.urlencode({'offset': 0, 'limit': 200} if collection else query) if collection or query else ''
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
        raise UnifiCloudError(f'UniFi respondió HTTP {exc.code}{_vendor_code(exc)}.') from None
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


def _ordering_query(query):
    return (isinstance(query, dict) and set(query) == {'sourceFirewallZoneId', 'destinationFirewallZoneId'}
            and all(isinstance(v, str) and UUID.fullmatch(v) for v in query.values()))


def _ordering_body(payload):
    ids = (payload or {}).get('orderedFirewallPolicyIds') if isinstance(payload, dict) else None
    return (isinstance(payload, dict) and set(payload) == {'orderedFirewallPolicyIds'} and isinstance(ids, dict)
            and set(ids) == {'beforeSystemDefined', 'afterSystemDefined'}
            and all(isinstance(v, list) and all(isinstance(i, str) and UUID.fullmatch(i) for i in v) for v in ids.values()))


def _vendor_code(exc):
    """Solo el código de error de UniFi (un identificador), nunca el texto de su respuesta."""
    try:
        body = json.loads(exc.read(4000) or b'{}')
    except (ValueError, OSError):
        return ''
    code = body.get('code') if isinstance(body, dict) else None
    return f' ({code})' if isinstance(code, str) and re.fullmatch(r'[A-Za-z0-9._:-]{1,80}', code) else ''


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


NAMES = {'in': 'SOC Bloqueo entrada', 'out': 'SOC Bloqueo salida C2'}


def create_list(device, direction):
    """Crea en la consola la lista «SOC…» de esa dirección, o reutiliza la que ya exista con ese nombre.

    Nace con la dirección de documentación como único contenido: una lista sin política no cambia el
    tráfico, y la política de bloqueo la crea el operador en UniFi. Formato {type, value}, el de las
    listas IPV4_ADDRESSES de Network 10 (comprobado en una consola real).
    """
    name = NAMES[direction]
    found = next((c for c in candidates(device) if c['name'] == name), None)
    if found:
        return found
    connection = device.unifi_cloud
    key = decrypt_api_key(connection.encrypted_api_key)
    site = default_site(key, connection.remote_host_id)
    call(key, connection.remote_host_id, f'/v1/sites/{site}/traffic-matching-lists', 'POST',
         {'type': 'IPV4_ADDRESSES', 'name': name, 'items': [{'type': 'IP_ADDRESS', 'value': PLACEHOLDER}]})
    created = next((c for c in candidates(device) if c['name'] == name), None)
    if not created or not created['format']:
        raise UnifiCloudError('UniFi no confirmó la creación de la lista.')
    return created


# Zonas del sistema de UniFi por dirección: (origen, destino). La lista va en el lado externo.
FLOWS = {'in': (('External', 'Internal'), ('External', 'Gateway')), 'out': (('Internal', 'External'),)}


def _data(result):
    return result.get('data', result) if isinstance(result.get('data'), dict) else result


def zones(key, host, site):
    rows = call(key, host, f'/v1/sites/{site}/firewall/zones').get('data') or []
    return {str(z.get('name', '')).lower(): _uuid(z.get('id')) for z in rows if isinstance(z, dict)}


def policies(key, host, site):
    return [p for p in call(key, host, f'/v1/sites/{site}/firewall/policies').get('data') or [] if isinstance(p, dict)]


def protocol_scope(existing):
    """`ipProtocolScope` de una política del operador (formato real de la consola); si no hay, solo IPv4."""
    for row in existing:
        if (row.get('metadata') or {}).get('origin') == 'USER_DEFINED' and isinstance(row.get('ipProtocolScope'), dict):
            return row['ipProtocolScope']
    return {'ipVersion': 'IPV4'}


def create_policies(binding):
    """Crea (o reutiliza por nombre) las políticas de bloqueo que usan la lista, DESACTIVADAS."""
    connection = binding.device.unifi_cloud
    key, host, site = decrypt_api_key(connection.encrypted_api_key), connection.remote_host_id, _uuid(binding.site_id)
    zone_ids = zones(key, host, site)
    existing = policies(key, host, site)
    scope = protocol_scope(existing)
    created = []
    for source, destination in FLOWS[binding.direction]:
        if source.lower() not in zone_ids or destination.lower() not in zone_ids:
            raise UnifiCloudError(f'No se encuentra la zona «{source}» o «{destination}» en la consola UniFi.')
        name = f'{PREFIX} Bloqueo {"entrada" if binding.direction == "in" else "salida C2"} {source}→{destination}'
        found = next((p for p in existing if p.get('name') == name), None)
        if not found:
            match = {'type': 'IP_ADDRESS', 'ipAddressFilter': {'type': 'TRAFFIC_MATCHING_LIST', 'matchOpposite': False,
                                                               'trafficMatchingListId': _uuid(binding.list_id)}}
            body = {'enabled': False, 'name': name, 'description': 'Gestionada por el SOC de ib-red: no editar a mano.',
                    'action': {'type': 'BLOCK'}, 'loggingEnabled': True, 'ipProtocolScope': scope,
                    'source': {'zoneId': zone_ids[source.lower()]}, 'destination': {'zoneId': zone_ids[destination.lower()]}}
            # La lista va en el extremo externo: origen al entrar, destino al salir.
            body['source' if binding.direction == 'in' else 'destination']['trafficFilter'] = match
            call(key, host, f'/v1/sites/{site}/firewall/policies', 'POST', body)
            found = next((p for p in policies(key, host, site) if p.get('name') == name), None)
            if not found:
                raise UnifiCloudError('UniFi no confirmó la creación de la política.')
        if found.get('enabled') is not False:
            raise UnifiCloudError(f'La política «{name}» ya existe y está activa: revísala en UniFi.')
        created.append({'id': _uuid(found.get('id')), 'name': name})
    return created


def _own_policy(key, host, site, policy):
    current = _data(call(key, host, f'/v1/sites/{site}/firewall/policies/{_uuid(policy["id"])}'))
    if current.get('name') != policy['name'] or not str(current.get('name', '')).startswith(PREFIX):
        raise UnifiCloudError(f'La política «{policy["name"]}» ha cambiado en UniFi: no se modifica.')
    return current


def set_policies(binding, enabled):
    """Activa o desactiva las políticas del SOC y lo verifica leyendo de nuevo."""
    connection = binding.device.unifi_cloud
    key, host, site = decrypt_api_key(connection.encrypted_api_key), connection.remote_host_id, _uuid(binding.site_id)
    for policy in binding.policies:
        current = _own_policy(key, host, site, policy)
        body = {k: v for k, v in current.items() if k not in ('id', 'metadata', 'index')}
        body['enabled'] = enabled
        path = f'/v1/sites/{site}/firewall/policies/{policy["id"]}'
        call(key, host, path, 'PUT', body)
        if _data(call(key, host, path)).get('enabled') is not enabled:
            raise UnifiCloudError('UniFi no confirmó el cambio de la política.')


def _ordering(key, host, site, pair):
    query = {'sourceFirewallZoneId': pair[0], 'destinationFirewallZoneId': pair[1]}
    result = call(key, host, f'/v1/sites/{site}/firewall/policies/ordering', query=query)
    ids = _data(result).get('orderedFirewallPolicyIds') if isinstance(_data(result), dict) else None
    if not isinstance(ids, dict) or not all(isinstance(ids.get(k), list) for k in ('beforeSystemDefined', 'afterSystemDefined')):
        raise UnifiCloudError('UniFi no devolvió el orden de las políticas.')
    return query, list(ids['beforeSystemDefined']), list(ids['afterSystemDefined'])


def unidentified(ids):
    """Entradas del orden sin identificador de la API (políticas migradas del firewall antiguo)."""
    return sum(1 for uid in ids if not (isinstance(uid, str) and UUID.fullmatch(uid)))


def move_first(binding):
    """Pone las políticas del SOC las primeras de su cruce de zonas, sin cambiar el orden de las demás.

    UniFi evalúa las políticas en orden y gana la primera que coincide: una política del operador
    que permita ese tráfico y esté antes dejaría pasar a las IPs de la lista. La API exige enviar
    todas las políticas del cruce; se comprueba que el conjunto no cambia y se verifica leyendo.
    Devuelve cuántos cruces se reordenaron.
    """
    connection = binding.device.unifi_cloud
    key, host, site = decrypt_api_key(connection.encrypted_api_key), connection.remote_host_id, _uuid(binding.site_id)
    pairs = {}
    for policy in binding.policies:
        current = _own_policy(key, host, site, policy)
        pair = (_uuid((current.get('source') or {}).get('zoneId')), _uuid((current.get('destination') or {}).get('zoneId')))
        pairs.setdefault(pair, []).append(policy['id'])
    moved = 0
    for pair, ours in pairs.items():
        query, before, after = _ordering(key, host, site, pair)
        if before[:len(ours)] == ours:
            continue
        legacy = unidentified(before + after)
        if legacy:
            # La API exige enviar todas las políticas del cruce y estas no tienen identificador:
            # no se puede reordenar sin arriesgar el resto. Se hace a mano en UniFi.
            raise UnifiCloudError(f'Este cruce de zonas tiene {legacy} política(s) antiguas sin identificador en la API '
                                  '(migradas del firewall anterior de UniFi), así que UniFi no permite reordenarlo por API. '
                                  'Arrastra la política del SOC al principio en UniFi y vuelve a comprobar.')
        if any(uid not in before + after for uid in ours):
            raise UnifiCloudError('UniFi no incluye la política del SOC en el orden de su cruce de zonas.')
        new_before = ours + [uid for uid in before if uid not in ours]
        new_after = [uid for uid in after if uid not in ours]
        if sorted(new_before + new_after) != sorted(before + after):
            raise UnifiCloudError('El orden calculado no coincide con las políticas de UniFi; no se cambia.')
        call(key, host, f'/v1/sites/{site}/firewall/policies/ordering', 'PUT',
             {'orderedFirewallPolicyIds': {'beforeSystemDefined': new_before, 'afterSystemDefined': new_after}}, query=query)
        if _ordering(key, host, site, pair)[1][:len(ours)] != ours:
            raise UnifiCloudError('UniFi no confirmó el nuevo orden de las políticas.')
        moved += 1
    return moved


def delete_policies(binding):
    connection = binding.device.unifi_cloud
    key, host, site = decrypt_api_key(connection.encrypted_api_key), connection.remote_host_id, _uuid(binding.site_id)
    for policy in binding.policies:
        try:
            _own_policy(key, host, site, policy)
        except UnifiCloudError as exc:
            if 'HTTP 404' in str(exc):
                continue  # ya no existe
            raise
        call(key, host, f'/v1/sites/{site}/firewall/policies/{policy["id"]}', 'DELETE')


def efficacy(binding, now=None):
    """Indicio de que las políticas funcionan: detecciones en este equipo de IPs de su lista desde que se activaron.

    UniFi no da contadores por política. Si bloquea, el tráfico de esas IPs no debería llegar a
    generar detecciones; si llegan como «permitidas», algo deja pasar ese tráfico (orden, estado o
    una política nueva). Es un indicio, no una prueba: la ausencia de detecciones no acredita por
    sí sola el bloqueo (invariante 4). Se usa la lista actual, así que es aproximado. None si las
    políticas no están activas desde el panel.
    """
    from datetime import timedelta
    from .models import SecurityEvidence
    now = now or timezone.now()
    since = binding.policies_enabled_at
    if not binding.policies_enabled or not since:
        return None
    start = max(since, now - timedelta(days=7))
    values = [v for v in desired(binding, now) if v != PLACEHOLDER]
    singles = [v for v in values if '/' not in v]
    networks = [ipaddress.ip_network(v) for v in values if '/' in v]
    field = 'destination_ip' if binding.direction == 'out' else 'source_ip'
    events = SecurityEvidence._base_manager.filter(device=binding.device, observed_at__gte=start, observed_at__lte=now)
    total = allowed = 0
    for start_at in range(0, len(singles), 1000):
        rows = events.filter(**{field + '__in': singles[start_at:start_at + 1000]}).values_list('action', flat=True)
        for action in rows.iterator():
            total += 1
            allowed += action == 'allowed'
    if networks:
        for value, action in events.exclude(**{field: None}).values_list(field, 'action').iterator():
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                continue
            if value not in singles and any(address.version == n.version and address in n for n in networks):
                total += 1
                allowed += action == 'allowed'
    return {'since': since, 'start': start, 'events': total, 'allowed': allowed}


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
        # error_at guarda el primer fallo seguido: permite avisar si dura más de una hora.
        UnifiBlocklistBinding._base_manager.filter(pk=binding.pk).update(error=str(exc)[:240], error_at=binding.error_at or now)
        return False
    UnifiBlocklistBinding._base_manager.filter(pk=binding.pk).update(
        pushed_fingerprint=target, pushed_count=0 if values == [PLACEHOLDER] else len(values), synced_at=now, error='',
        error_at=None)
    return True


def sync_all(now=None):
    """Trabajo «Listas de bloqueo del SOC» (cada 15 min): lleva cada lista UniFi vinculada a lo que sirve el SOC.

    Una consola que lleva más de una hora sin poder actualizarse se avisa en «Salud del SOC».
    """
    from datetime import timedelta
    from .models import OperationalIssue
    from .operations import set_issue
    now = now or timezone.now()
    done = 0
    bindings = UnifiBlocklistBinding._base_manager.filter(device__unifi_cloud__isnull=False).select_related(
        'device__site', 'device__unifi_cloud')
    for binding in bindings:
        key = f'platform:unifi-blocklist:{binding.pk}'
        if sync(binding, now):
            done += 1
            OperationalIssue.objects.filter(key=key, active=True).update(active=False, resolved_at=now)
            continue
        binding.refresh_from_db()
        if binding.error_at and now - binding.error_at >= timedelta(hours=1) or not binding.synced_at:
            set_issue(key, f'Lista de bloqueo sin actualizar en {binding.device.name}', device=binding.device,
                      details=binding.error, now=now)
    return done

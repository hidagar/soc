"""Readonly official UniFi Integration API. Catalogue order is not a flow verdict."""
import json
import re
import time
from urllib import request, parse, error
from datetime import timedelta
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from .unifi_cloud import decrypt_api_key, UnifiCloudError, _NoRedirect
from .zenarmor_scope import digest

UUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z')
MAX_ROWS = 500
ORIGINS = {'SYSTEM_DEFINED': 'Del sistema', 'USER_DEFINED': 'Personalizada', 'DERIVED': 'Generada'}
FIELDS = {'id', 'name', 'description', 'index', 'enabled', 'action', 'source', 'destination',
    'ipProtocolScope', 'connectionStateFilter', 'loggingEnabled', 'metadata', 'schedule', 'ipsecFilter'}


def identity(value):
    if not isinstance(value, str) or not UUID.fullmatch(value):
        raise ValueError('Unknown UUID')
    return value


def name(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 240:
        raise ValueError('Unknown name')
    return value.strip()


def boolean(value):
    if not isinstance(value, bool): raise ValueError('Unknown boolean')
    return value


def integer(value):
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 2**31-1:
        raise ValueError('Unknown index/count')
    return value


def sequence(value, limit=MAX_ROWS):
    if not isinstance(value, list) or len(value) > limit: raise ValueError('Unknown/oversized list')
    return value


def integration_json(api_key, host_id, path, offset=0, limit=100):
    """Exact GET allowlist; no redirect, caller-supplied URL, arbitrary query or write."""
    if not isinstance(host_id, str) or not re.fullmatch(r'[A-Za-z0-9:-]{1,200}', host_id):
        raise UnifiCloudError('Consola no válida.')
    if path != '/v1/sites' and not re.fullmatch(
            r'/v1/sites/[0-9a-f-]{36}/(?:firewall/zones|firewall/policies|networks|traffic-matching-lists|acl-rules)', path):
        raise UnifiCloudError('Ruta de lectura no permitida.')
    if path != '/v1/sites': identity(path.split('/')[3])
    if not api_key or any(c in api_key for c in '\r\n\t') or integer(offset) > MAX_ROWS or not 1 <= integer(limit) <= 100:
        raise UnifiCloudError('Consulta no válida.')
    url = ('https://api.ui.com/v1/connector/consoles/' + parse.quote(host_id, safe='')
        + '/proxy/network/integration' + path + '?' + parse.urlencode({'offset': offset, 'limit': limit}))
    req = request.Request(url, method='GET', headers={'Accept': 'application/json', 'X-API-Key': api_key})
    try:
        with request.build_opener(_NoRedirect()).open(req, timeout=15) as response:
            raw = response.read(2000001)
        if len(raw) > 2000000: raise ValueError('Oversized response')
        data = json.loads(raw)
        if not isinstance(data, dict): raise ValueError('Unknown response')
        return data
    except (error.HTTPError, error.URLError, TimeoutError, OSError, ValueError) as exc:
        raise UnifiCloudError('No se pudo consultar la API oficial de zonas. Revisar permisos y compatibilidad de UniFi OS/Network.') from exc


def catalogue(read, path, deadline):
    rows, total = [], None
    for offset in range(0, MAX_ROWS, 100):
        if time.monotonic() >= deadline: raise ValueError('Read budget exceeded')
        data = read(path, offset, 100)
        page = sequence(data.get('data'), 100)
        expected = integer(data.get('totalCount'))
        if expected > MAX_ROWS or (total is not None and expected != total):
            raise ValueError('Incomplete/changing catalogue')
        total = expected
        if integer(data.get('offset')) != offset or integer(data.get('count')) != len(page) or integer(data.get('limit')) != 100:
            raise ValueError('Wrong page')
        if any(not isinstance(v, dict) for v in page): raise ValueError('Unknown row')
        rows.extend(page)
        if len(rows) == total: return rows
        if len(rows) > total or len(page) != 100: raise ValueError('Incomplete page')
    raise ValueError('Catalogue limit')


def resources(rows, kind):
    result = {}
    for row in rows:
        key = identity(row.get('id'))
        if key in result: raise ValueError('Duplicate resource')
        result[key] = {'id': key, 'name': name(row.get('name'))}
        if kind == 'list':
            values = sequence(row.get('items'))
            # Contents never displayed or stored, including MAC/device identities.
            result[key].update(count=len(values), fingerprint=digest({'type': row.get('type'), 'items': values}))
            result[key]['type'] = row.get('type') if row.get('type') in ('PORTS','IPV4_ADDRESSES','IPV6_ADDRESSES') else 'UNKNOWN'
    return result


def project(zones, policies, networks, lists):
    from .unifi_policy_details import ports, addresses, protocol as protocol_detail
    network_map, list_map = resources(networks, 'network'), resources(lists, 'list')
    zone_map, membership = {}, set()
    for row in zones:
        zid = identity(row.get('id'))
        if zid in zone_map: raise ValueError('Duplicate zone')
        ids = [identity(v) for v in sequence(row.get('networkIds'))]
        if len(set(ids)) != len(ids) or membership.intersection(ids): raise ValueError('Ambiguous zone membership')
        membership.update(ids)
        zone_map[zid] = {'id': zid, 'name': name(row.get('name')), 'network_ids': sorted(ids),
            'network_choices':[{'id':v,'name':network_map[v]['name'] if v in network_map else 'Red sin identificar ('+v[-6:]+')'} for v in sorted(ids)],
            'networks': [network_map[v]['name'] for v in ids if v in network_map],
            'unresolved_networks': sum(v not in network_map for v in ids)}
    if len(zone_map) > 30 or not zone_map: raise ValueError('Unknown zone catalogue')
    # The official network catalogue may exclude WAN/VPN interfaces. Preserve
    # unresolved zone member counts; never infer identity by names or subnet.
    for row in networks:
        if row.get('zoneId') is not None:
            zid = identity(row['zoneId'])
            if zid not in zone_map or row['id'] not in zone_map[zid]['network_ids']:
                raise ValueError('Network/zone catalogue conflict')
    pairs, known_ids, observations = {}, set(), set()
    for row in policies:
        enabled, logging = boolean(row.get('enabled')), boolean(row.get('loggingEnabled'))
        index = integer(row.get('index'))
        origin = row.get('metadata', {}).get('origin')
        origin_label = ORIGINS.get(origin, 'Origen sin identificar')
        pid = identity(row['id']) if row.get('id') is not None else None
        if pid:
            if pid in known_ids: raise ValueError('Duplicate policy identity')
            known_ids.add(pid)
        action = row.get('action')
        if not isinstance(action, dict) or action.get('type') not in ('ALLOW', 'BLOCK', 'REJECT'):
            raise ValueError('Unknown policy action')
        src, dst = row.get('source'), row.get('destination')
        if not isinstance(src, dict) or not isinstance(dst, dict): raise ValueError('Unknown endpoint')
        source, destination = identity(src.get('zoneId')), identity(dst.get('zoneId'))
        if source not in zone_map or destination not in zone_map: raise ValueError('Missing zone')
        criteria = []
        unknown = bool(set(row) - FIELDS or origin not in ORIGINS)
        unknown |= bool(set(action) - {'type', 'allowReturnTraffic'})
        if 'allowReturnTraffic' in action: boolean(action['allowReturnTraffic'])
        for endpoint, label in ((src, 'Origen'), (dst, 'Destino')):
            if set(endpoint) - {'zoneId', 'trafficFilter', 'portFilter'}: unknown = True
            traffic = endpoint.get('trafficFilter')
            if traffic is not None:
                if not isinstance(traffic, dict) or not isinstance(traffic.get('type'), str):
                    raise ValueError('Unknown traffic filter')
                kind = traffic['type']
                if kind == 'NETWORK':
                    spec = traffic.get('networkFilter', {})
                    ids = [identity(v) for v in sequence(spec.get('networkIds'))]
                    inverse = boolean(spec.get('matchOpposite'))
                    unknown |= bool(set(traffic) - {'type', 'networkFilter', 'portFilter'} or
                        set(spec) - {'networkIds', 'matchOpposite'} or any(v not in network_map for v in ids))
                    values = [network_map[v]['name'] if v in network_map else 'Red sin identificar' for v in ids]
                    criteria.append(label + ': ' + ('excepto ' if inverse else '') + ', '.join(values))
                elif kind == 'IP_ADDRESS' and traffic.get('ipAddressFilter', {}).get('type') == 'IP_ADDRESSES':
                    parsed=addresses(traffic['ipAddressFilter'])
                    unknown |= bool(set(traffic)-{'type','ipAddressFilter','portFilter'})
                    if parsed is None:
                        criteria.append(label + ': direcciones con formato pendiente');unknown=True
                    else:
                        unknown |= parsed['pending']
                        criteria.append(label + ': ' + ('excepto ' if parsed['matchOpposite'] else '') + str(len(parsed['networks'])) + ' direcciones/subredes literales')
                elif kind == 'IP_ADDRESS' and traffic.get('ipAddressFilter', {}).get('type') == 'TRAFFIC_MATCHING_LIST':
                    spec = traffic['ipAddressFilter']; inverse = boolean(spec.get('matchOpposite'))
                    unknown |= bool(set(traffic) - {'type', 'ipAddressFilter', 'portFilter'} or
                        set(spec) - {'type', 'matchOpposite', 'trafficMatchingListId'})
                    obj = list_map.get(identity(spec.get('trafficMatchingListId')))
                    criteria.append(label + ': ' + ('excepto ' if inverse else '') +
                        (obj['name'] + f" ({obj['count']} entradas)" if obj else 'Objeto sin identificar'))
                    unknown |= obj is None
                elif kind == 'PORT':
                    if 'portFilter' not in traffic: raise ValueError('Missing port filter')
                    unknown |= bool(set(traffic) - {'type','portFilter'})
                else:
                    criteria.append(label + ': filtro específico (' + kind[:80] + ')'); unknown = True
                if traffic.get('portFilter') is not None:
                    summary, pending = ports(traffic['portFilter'], list_map)
                    criteria.append(label + ' · puertos: ' + summary); unknown |= pending
            if endpoint.get('portFilter') is not None:
                criteria.append(label + ': ubicación de filtro de puertos pendiente; revisar en UniFi'); unknown = True
        protocol = row.get('ipProtocolScope')
        if not isinstance(protocol, dict) or protocol.get('ipVersion') not in ('IPV4', 'IPV6', 'IPV4_AND_IPV6'):
            raise ValueError('Unknown IP version')
        summary, pending = protocol_detail(protocol)
        criteria.append('Protocolos: ' + summary); unknown |= pending
        states = row.get('connectionStateFilter')
        if states is not None:
            states = sequence(states)
            if any(v not in ('NEW', 'INVALID', 'ESTABLISHED', 'RELATED') for v in states): raise ValueError('Unknown state')
            state_labels = {'NEW': 'nuevas', 'INVALID': 'no válidas', 'ESTABLISHED': 'establecidas', 'RELATED': 'relacionadas'}
            criteria.append('Conexiones: ' + ', '.join(state_labels[v] for v in states))
        if row.get('schedule') is not None:
            criteria.append('Horario definido; revisar vigencia en UniFi'); unknown = True
        if row.get('ipsecFilter') is not None:
            criteria.append('Condición IPsec; revisar en UniFi'); unknown = True
        # Hash recognized policy sections, never persist raw matching criteria.
        policy_hash = digest({k: row.get(k) for k in sorted(FIELDS) if k != 'description'})
        observation = (source, destination, index, policy_hash)
        if observation in observations: raise ValueError('Duplicate catalogue page/observation')
        observations.add(observation)
        projected = {'id': pid, 'name': name(row.get('name')), 'enabled': enabled, 'index': index,
            'origin': origin_label, 'action': {'ALLOW': 'Permitir', 'BLOCK': 'Bloquear', 'REJECT': 'Rechazar'}[action['type']],
            'return_traffic': action.get('allowReturnTraffic') is True, 'logging': logging,
            'ip_version': {'IPV4': 'IPv4', 'IPV6': 'IPv6', 'IPV4_AND_IPV6': 'IPv4 e IPv6'}[protocol['ipVersion']], 'criteria': criteria, 'criteria_pending': unknown,
            'fingerprint': policy_hash}
        from .unifi_flow import project as flow_project
        projected['flow_match']=flow_project(row)
        pair = pairs.setdefault((source, destination), {'source': zone_map[source]['name'],
            'destination': zone_map[destination]['name'], 'source_id': source, 'destination_id': destination, 'policies': []})
        pair['policies'].append(projected)
    for pair in pairs.values():
        pair['policies'].sort(key=lambda p: (p['index'], p['name'], p['fingerprint']))
        active = [p for p in pair['policies'] if p['enabled']]
        pair.update(active_count=len(active), disabled_count=len(pair['policies'])-len(active),
            order_unambiguous=len({p['index'] for p in active}) == len(active))
    result = {'zones': sorted(zone_map.values(), key=lambda z: z['name']),
        'pairs': sorted(pairs.values(), key=lambda p: (p['source'], p['destination'])),
        'policy_count': len(policies), 'active_count': sum(r['enabled'] for pair in pairs.values() for r in pair['policies']),
        'unidentified_count': sum(r['id'] is None for pair in pairs.values() for r in pair['policies']),
        'criteria_pending_count': sum(r['criteria_pending'] for pair in pairs.values() for r in pair['policies']),
        'objects': sorted(list_map.values(), key=lambda v:v['id']),
        'list_fingerprints': sorted((key, v['fingerprint']) for key, v in list_map.items())}
    result['fingerprint'] = digest(result)
    return result


def collect(connection, previous=None, now=None, api=integration_json):
    now = now or timezone.now()
    result = {'schema': 1, 'status': 'unavailable', 'checked_at': now.isoformat(), 'catalogue': {}}
    if isinstance(previous, dict) and previous.get('schema') == 1:
        result.update(catalogue=previous.get('catalogue', {}), last_success_at=previous.get('last_success_at'))
    try:
        deadline = time.monotonic() + 90
        key = decrypt_api_key(connection.encrypted_api_key)
        def read(path, offset, limit): return api(key, connection.remote_host_id, path, offset, limit)
        sites = catalogue(read, '/v1/sites', deadline)
        default = [v for v in sites if v.get('internalReference') == 'default']
        if len(default) != 1: raise ValueError('Ambiguous local site')
        site = identity(default[0].get('id'))
        paths = ['/v1/sites/' + site + '/' + suffix for suffix in
            ('firewall/zones', 'firewall/policies', 'networks', 'traffic-matching-lists')]
        initial = project(*(catalogue(read, path, deadline) for path in paths))
        final = project(*(catalogue(read, path, deadline) for path in paths))
        if initial['fingerprint'] != final['fingerprint']: raise ValueError('Configuration changed during read')
        result.update(status='checked', catalogue=final, last_success_at=now.isoformat())
    except Exception:
        pass
    from .unifi_policy_history import track
    return track(previous, result)


def snapshot(device, now=None):
    check = getattr(device, 'exposure_check', None)
    scope = check.coverage.get('zones', {}) if check else {}
    now = now or timezone.now()
    try:
        stamp = parse_datetime(scope.get('checked_at', ''))
        last = parse_datetime(scope.get('last_success_at') or '')
        current = bool(scope.get('schema') == 1 and scope.get('status') == 'checked' and stamp
            and timedelta(0) <= now - stamp <= timedelta(hours=12) and device.active
            and device.site.active and device.site.client.active and device.integration != 'paused')
    except (ValueError, TypeError): current, last = False, None
    from .unifi_policy_history import presentation
    return {'device': device, 'current': current, 'scope': scope, 'catalogue': scope.get('catalogue', {}),
        'last_success_at': last, 'history':presentation(scope)}

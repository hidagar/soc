"""Readonly Zenarmor 2.6 scope adapter; stored data is an explicit projection.

Policies are candidates, never an effective-policy decision for a flow. Global
traffic exemptions and inherited VLAN/bridge inspection are not inferred.
"""
import hashlib
import ipaddress
import json
import re
import time
from datetime import timedelta
from django.utils import timezone

MAX_POLICIES = 25
MAX_ITEMS = 250
INTERFACE = re.compile(r'[A-Za-z0-9_.:-]{1,120}\Z')
CONFIG_FIELDS = ('security', 'app', 'decision_is_block', 'block_untrusted_devices',
    'block_ech', 'sso', 'web', 'tls', 'safe_search', 'sort_number', 'webcategory_type',
    'groups', 'interfaces', 'interface_tags', 'usernames', 'directions', 'vlans')
DETAIL_FIELDS = ('networks', 'mac_addresses', 'devices', 'device_categories',
    'essential_security', 'advanced_security', 'web_controls', 'web_controls_custom',
    'app_controls', 'app_controls_custom', 'tls_controls', 'casb', 'url_blocks',
    'file_reputation', 'rtap', 'schedules', 'exclusions')


def digest(value):
    encoded = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
    if len(encoded) > 200000:
        raise ValueError('Policy projection too large')
    return hashlib.sha256(encoded.encode()).hexdigest()


def items(value):
    if not isinstance(value, list) or len(value) > MAX_ITEMS:
        raise ValueError('Invalid or oversized list')
    return value


def identifiers(value):
    result = items(value)
    if any(not isinstance(v, str) or not INTERFACE.fullmatch(v) for v in result):
        raise ValueError('Invalid interface identity')
    if len(set(result)) != len(result):
        raise ValueError('Duplicate identity')
    return sorted(result)


def boolean(value):
    if not isinstance(value, bool):
        raise ValueError('Unknown state')
    return value


def policy_id(value):
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**63:
        raise ValueError('Invalid policy identity')
    return str(value)


def parse_interfaces(status):
    """Status explicitly enumerates selected engine interfaces, not all interfaces."""
    result = []
    for row in items(status.get('interfaces_list')):
        if not isinstance(row, dict):
            raise ValueError('Unknown interface schema')
        name = row.get('interface')
        if not isinstance(name, str) or not INTERFACE.fullmatch(name):
            raise ValueError('Unknown interface identity')
        result.append({'name': name, 'tags': identifiers(row.get('tags'))})
    if len({v['name'] for v in result}) != len(result):
        raise ValueError('Duplicate interface')
    return sorted(result, key=lambda v: v['name'])


def parse_policy(detail, expected_id):
    if not isinstance(detail, dict) or policy_id(detail.get('id')) != expected_id:
        raise ValueError('Wrong policy returned')
    name = detail.get('name')
    if not isinstance(name, str) or not name.strip() or len(name) > 180:
        raise ValueError('Invalid policy name')
    config = detail.get('configs')
    if not isinstance(config, dict):
        raise ValueError('Missing policy configuration')
    if set(config) - set(CONFIG_FIELDS) - {'local_id'}:
        raise ValueError('Unrecognized policy criteria')
    directions = config.get('directions')
    if not isinstance(directions, dict):
        raise ValueError('Missing directions')
    directions = {k: boolean(directions.get(k)) for k in ('inbound', 'outbound')}
    order = config.get('sort_number')
    if isinstance(order, bool) or not isinstance(order, int) or not -2**31 <= order < 2**31:
        raise ValueError('Unknown policy order')
    networks = []
    for row in items(detail.get('networks')):
        if not isinstance(row, dict):
            raise ValueError('Unknown policy network')
        disabled = boolean(row.get('is_disabled'))
        value = row.get('value')
        if not isinstance(value, str) or len(value) > 80:
            raise ValueError('Invalid network literal')
        network = ipaddress.ip_network(value, strict=False)
        if not disabled:
            networks.append(str(network))
    vlans = items(config.get('vlans'))
    if any(isinstance(v, bool) or not str(v).isdigit() or not 0 <= int(v) <= 4096 for v in vlans):
        raise ValueError('Unknown VLAN filter')
    restrictions = []
    for obj, key, label in [(config, 'groups', 'grupos'), (config, 'usernames', 'usuarios'),
            (detail, 'mac_addresses', 'direcciones MAC'), (detail, 'devices', 'dispositivos'),
            (detail, 'device_categories', 'categorías de dispositivos'), (detail, 'schedules', 'horarios')]:
        count = len(items(obj.get(key)))
        if count:
            restrictions.append(f'{label}: {count}')
    controls = []
    for field, label in [('security', 'Seguridad'), ('app', 'Aplicaciones'), ('web', 'Web'), ('tls', 'TLS')]:
        if boolean(config.get(field)):
            controls.append(label)
    counts = {}
    for field in ('essential_security', 'advanced_security'):
        values = items(detail.get(field))
        if any(isinstance(v, bool) or not isinstance(v, int) for v in values):
            raise ValueError('Unknown category identifiers')
        counts[field] = len(set(values))
    active = boolean(detail.get('isActive'))
    # Hash only known policy sections; never store user names, MACs, exception
    # values, cloud identities or tokens. Changes to any observed section retire
    # previous per-network proofs, even when the human summary stays identical.
    fingerprint = digest({'id': expected_id, 'active': active,
        'configs': {k: config.get(k) for k in CONFIG_FIELDS},
        'details': {k: detail.get(k) for k in DETAIL_FIELDS}})
    return {'id': expected_id, 'name': name, 'active': active, 'default': expected_id == '0','exception_count':len(items(detail.get('exclusions'))),
        'order': order, 'interfaces': identifiers(config.get('interfaces')),
        'interface_tags': identifiers(config.get('interface_tags')),
        'networks': sorted(set(networks)), 'vlans': sorted(set(int(v) for v in vlans)),
        'directions': directions, 'restrictions': restrictions, 'controls': controls,
        'essential_count': counts['essential_security'], 'advanced_count': counts['advanced_security'],
        'exclusion_count': len(items(detail.get('exclusions'))), 'fingerprint': fingerprint}


def collect(connection, status, api, previous=None, now=None):
    now = now or timezone.now()
    scope = {'schema': 1, 'checked_at': now.isoformat(), 'interfaces_known': False,
        'interfaces': [], 'mode': 'unknown', 'policies_status': 'unavailable', 'policies': []}
    # A transient policy failure can show the previous projection as historical.
    # It cannot extend freshness or validate a proof.
    if isinstance(previous, dict) and previous.get('schema') == 1:
        scope['policies'] = previous.get('policies', [])
        scope['policies_last_success_at'] = previous.get('policies_last_success_at')
    try:
        scope['interfaces'] = parse_interfaces(status)
        scope['interfaces_known'] = True
        mode = status.get('deployment_mode')
        scope['mode'] = mode if mode in ('routed', 'bridge', 'passive') else 'unknown'
    except (ValueError, TypeError, AttributeError):
        pass
    try:
        deadline = time.monotonic() + 30
        data = api(connection, '/api/zenarmor/policy/index')
        rows = items(data.get('policies'))
        if len(rows) > MAX_POLICIES or data.get('error') is True:
            raise ValueError('Incomplete policy catalogue')
        ids = [policy_id(r.get('id')) for r in rows if isinstance(r, dict)]
        if len(ids) != len(rows) or len(set(ids)) != len(ids):
            raise ValueError('Duplicate or incomplete policies')
        # Only the local, single-node catalogue shape has been verified. Reject
        # ambiguous cloud/multi-node targets instead of attributing their rules.
        node_ids = set()
        for row in rows:
            nodes = items(row.get('nodes'))
            if len(nodes) != 1 or not isinstance(nodes[0], dict) or not isinstance(nodes[0].get('id'), str):
                raise ValueError('Unknown policy target')
            node_ids.add(nodes[0]['id'])
        if len(node_ids) > 1:
            raise ValueError('Mixed policy targets')
        policies = []
        for pid in ids:
            if time.monotonic() >= deadline:
                raise ValueError('Policy collection time limit')
            detail = api(connection, '/api/zenarmor/policy/detail?id=' + pid)
            nodes = items(detail.get('nodes'))
            if len(nodes) != 1 or not isinstance(nodes[0], dict) or nodes[0].get('id') not in node_ids:
                raise ValueError('Wrong detail target')
            entry = next(row for row in rows if policy_id(row['id']) == pid)
            if detail.get('checksum') != entry.get('checksum'):
                raise ValueError('Wrong detail revision')
            policies.append(parse_policy(detail, pid))
        # Re-read the catalogue to reject changes while collecting details.
        if time.monotonic() >= deadline:
            raise ValueError('Policy collection time limit')
        final = api(connection, '/api/zenarmor/policy/index')
        final_rows = items(final.get('policies'))
        def manifest(values):
            result = []
            for value in values:
                checksum = value.get('checksum')
                if isinstance(checksum, bool) or not isinstance(checksum, int):
                    raise ValueError('Unknown revision')
                result.append((policy_id(value.get('id')), boolean(value.get('isActive')), checksum,
                    digest(value.get('nodes'))))
            return sorted(result)
        if manifest(rows) != manifest(final_rows):
            raise ValueError('Policies changed during collection')
        states = {policy_id(r['id']): boolean(r.get('isActive')) for r in rows}
        if any(p['active'] != states[p['id']] for p in policies):
            raise ValueError('Policy status changed')
        scope.update(policies=sorted(policies, key=lambda p: (p['order'], p['id'])),
            policies_status='checked', policies_last_success_at=now.isoformat())
        scope['policy_fingerprint'] = digest(sorted((p['id'], p['fingerprint']) for p in policies))
    except Exception:
        # No exception text or raw backend response is stored or logged.
        scope.pop('policy_fingerprint', None)
    return scope


def scope_current(scope, now=None):
    from django.utils.dateparse import parse_datetime
    if not isinstance(scope, dict) or scope.get('schema') != 1:
        return False
    try:
        stamp = parse_datetime(scope.get('checked_at', ''))
        return bool(stamp and timedelta(0) <= (now or timezone.now()) - stamp <= timedelta(minutes=30))
    except (ValueError, TypeError):
        return False


def network_snapshot(network, fresh, now=None):
    health = getattr(network.device, 'health', None)
    engine = health.engines.get('Zenarmor', {}) if health else {}
    scope = engine.get('scope', {})
    current = bool(fresh and scope_current(scope, now))
    selection = None
    tags = set()
    if current and scope.get('interfaces_known') is True:
        matches = [v for v in scope['interfaces'] if v['name'] in (network.interface, network.physical_interface)]
        selection = bool(matches)
        tags = {tag for v in matches for tag in v['tags']}
    if not current:
        label = 'Zenarmor: consulta actual pendiente'
    elif network.enabled is False:
        label = 'Zenarmor: interfaz desactivada'
    elif engine.get('running') is False:
        label = 'Zenarmor: motor detenido'
    elif engine.get('bypass') is True:
        label = 'Zenarmor: bypass activado'
    elif selection is False:
        label = 'Zenarmor: interfaz no seleccionada explícitamente'
    elif selection is True:
        label = 'Zenarmor: interfaz seleccionada'
    else:
        label = 'Zenarmor: selección sin comprobar'
    candidates = []
    policies_current = current and scope.get('policies_status') == 'checked'
    if policies_current and selection is True:
        for p in scope['policies']:
            if not p['active']:
                continue
            if p['interfaces'] and not set(p['interfaces']).intersection((network.interface, network.physical_interface)):
                continue
            if p['interface_tags'] and not set(p['interface_tags']).intersection(tags):
                continue
            if p['networks'] and network.cidrs:
                pairs = [(ipaddress.ip_network(a), ipaddress.ip_network(b)) for a in p['networks'] for b in network.cidrs]
                if not any(a.version == b.version and a.overlaps(b) for a, b in pairs):
                    continue
            candidates.append(p)
    return {'label': label, 'selection': selection, 'current': current,
        'policies_current': bool(policies_current), 'candidates': candidates,
        'mode': {'routed': 'Enrutado', 'bridge': 'Puente', 'passive': 'Pasivo'}.get(scope.get('mode'), 'Sin comprobar'),
        'checked_at': scope.get('checked_at'), 'scope': scope}


def device_snapshot(device, now=None):
    from django.utils.dateparse import parse_datetime
    health = getattr(device, 'health', None)
    engine = health.engines.get('Zenarmor', {}) if health else {}
    scope = engine.get('scope', {})
    now = now or timezone.now()
    fresh = bool(scope_current(scope, now) and health and health.api_ok is True
        and health.protection_checked_at and timedelta(0) <= now - health.protection_checked_at <= timedelta(minutes=30)
        and device.active and device.site.active and device.site.client.active
        and device.integration != 'paused' and not (health.maintenance_until and health.maintenance_until > now))
    return {'device': device, 'scope': scope, 'current': fresh,
        'policies_current': fresh and scope.get('policies_status') == 'checked',
        'policies_last_success_at': parse_datetime(scope['policies_last_success_at']) if scope.get('policies_last_success_at') else None,
        'policies': scope.get('policies', [])}

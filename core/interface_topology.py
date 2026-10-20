"""Bounded OPNsense topology projection. Relationships do not imply inspection.

search_item decorates assigned VLAN names with ' [description]' (OPNsense
VlanSettingsController). The prefix is validated as an exact interface identity.
Bridge configured logical members must agree with the live physical members.
Only interface identifiers, types, tags and relationships are retained.
"""
import re
import time
from datetime import timedelta
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from .zenarmor_scope import digest

NAME = re.compile(r'[A-Za-z0-9_.:-]{1,120}\Z')
VLAN_DISPLAY = re.compile(r'([A-Za-z0-9_.:-]{1,120})(?: \[[^\r\n]{0,180}\])?\Z')
LIMIT = 250
PATHS = ('/api/interfaces/vlan_settings/search_item?rowCount=-1',
         '/api/interfaces/bridge_settings/search_item?rowCount=-1')
OVERVIEW_PATH = '/api/interfaces/overview/interfaces_info?rowCount=-1'


def identity(value):
    if not isinstance(value, str) or not NAME.fullmatch(value):
        raise ValueError('Unknown interface identity')
    return value


def catalogue(data):
    rows = data.get('rows') if isinstance(data, dict) else None
    total = data.get('total') if isinstance(data, dict) else None
    if isinstance(total, bool) or not isinstance(total, (str, int)) or not str(total).isdigit():
        raise ValueError('Unknown total')
    if not isinstance(rows, list) or len(rows) > LIMIT or int(total) != len(rows):
        raise ValueError('Incomplete catalogue')
    if any(not isinstance(row, dict) for row in rows):
        raise ValueError('Unknown catalogue row')
    return rows


def project(overview, vlans, bridges):
    runtime, logical = {}, {}
    for row in catalogue(overview):
        name = identity(row.get('device'))
        if name in runtime:
            raise ValueError('Ambiguous runtime interface')
        assigned = row.get('identifier')
        if not isinstance(assigned, str):
            raise ValueError('Unknown assignment schema')
        if assigned:
            assigned = identity(assigned)
            if assigned in logical:
                raise ValueError('Ambiguous assignment')
            logical[assigned] = name
        physical = row.get('is_physical')
        if not isinstance(physical, bool):
            raise ValueError('Unknown physical state')
        link = row.get('link_type')
        runtime[name] = {'interface': assigned or '', 'device': name,
            'kind': 'physical' if physical else 'virtual', 'parents': [], 'members': [],
            'vlan': None, 'link': link if link in ('pppoe', 'wireguard', 'gif', 'gre', 'ipsec') else ''}
    vlan_map, bridge_map = {}, {}
    for row in catalogue(vlans):
        match = VLAN_DISPLAY.fullmatch(row.get('vlanif', '')) if isinstance(row.get('vlanif'), str) else None
        if not match:
            raise ValueError('Unknown VLAN display schema')
        name, parent = match[1], identity(row.get('if'))
        tag = row.get('tag')
        if isinstance(tag, bool) or not isinstance(tag, (str, int)) or not str(tag).isdigit() or not 1 <= int(tag) <= 4094:
            raise ValueError('Unknown VLAN tag')
        if name in vlan_map or name == parent:
            raise ValueError('Ambiguous VLAN relationship')
        vlan_map[name] = {'parent': parent, 'tag': int(tag)}
    for row in catalogue(bridges):
        name = identity(row.get('bridgeif'))
        members = row.get('members')
        if not isinstance(members, str) or not members or len(members) > 32000:
            raise ValueError('Unknown bridge members')
        assigned = [identity(v) for v in members.split(',')]
        if len(assigned) > LIMIT or len(set(assigned)) != len(assigned) or name in bridge_map:
            raise ValueError('Ambiguous bridge')
        if any(v not in logical for v in assigned):
            raise ValueError('Unassigned bridge member')
        bridge_map[name] = sorted(logical[v] for v in assigned)
    if set(vlan_map).intersection(bridge_map):
        raise ValueError('Conflicting topology')
    source = {row['device']: row for row in catalogue(overview)}
    for name, vlan in vlan_map.items():
        if name not in runtime or vlan['parent'] not in runtime:
            raise ValueError('Configured VLAN missing in runtime')
        actual_tag = source[name].get('vlan_tag')
        if str(actual_tag) != str(vlan['tag']) or runtime[name]['kind'] == 'physical':
            raise ValueError('Configured VLAN differs from runtime')
        runtime[name].update(kind='vlan', parents=[vlan['parent']], vlan=vlan['tag'])
    for name, members in bridge_map.items():
        live = source.get(name, {}).get('members')
        if not isinstance(live, dict) or sorted(live) != members or name in members:
            raise ValueError('Bridge configuration differs from runtime')
        if runtime[name]['kind'] == 'physical':
            raise ValueError('Unknown bridge type')
        runtime[name].update(kind='bridge', members=members)
    # Reject unrecognized live VLAN/bridge relationships instead of silently
    # treating an incomplete configuration catalogue as an ordinary interface.
    for name, row in source.items():
        if row.get('vlan_tag') not in (None, '') and name not in vlan_map:
            raise ValueError('Runtime VLAN missing in configuration')
        if row.get('members') and name not in bridge_map:
            raise ValueError('Runtime bridge missing in configuration')
    def descendants(name, stack=()):
        if name in stack or len(stack) > 12:
            raise ValueError('Cyclic or excessive topology')
        node = runtime[name]
        related = node['parents'] + node['members']
        result = set(related)
        for child in related:
            result.update(descendants(child, (*stack, name)))
        return sorted(result)
    for name, node in runtime.items():
        node['related'] = descendants(name)
        node['related_interfaces'] = sorted(runtime[v]['interface'] for v in node['related'] if runtime[v]['interface'])
    for name, node in runtime.items():
        node['path_fingerprint'] = digest([{k: runtime[v][k] for k in
            ('device', 'interface', 'kind', 'parents', 'members', 'vlan', 'link')}
            for v in sorted({name, *node['related']})])
    # Keep physical/unassigned interfaces only when needed by an assigned node.
    return {key: runtime[value] for key, value in sorted(logical.items()) if key not in ('lo0', 'pfsync0')}


def collect(connection, overview, api, previous=None, now=None):
    now = now or timezone.now()
    result = {'schema': 1, 'checked_at': now.isoformat(), 'status': 'unavailable', 'networks': {}}
    if isinstance(previous, dict) and previous.get('schema') == 1:
        result['networks'] = previous.get('networks', {})
        result['last_success_at'] = previous.get('last_success_at')
    try:
        deadline = time.monotonic() + 30
        def read():
            values = []
            for path in PATHS:
                if time.monotonic() >= deadline:
                    raise ValueError('Topology read timeout')
                values.append(api(connection, path))
            return values
        vlans, bridges = read()
        networks = project(overview, vlans, bridges)
        if time.monotonic() >= deadline:
            raise ValueError('Topology read timeout')
        # Compare sanitized observations, not descriptions/UUIDs/config secrets.
        final_vlans, final_bridges = read()
        if time.monotonic() >= deadline:
            raise ValueError('Topology read timeout')
        final_overview = api(connection, OVERVIEW_PATH)
        if networks != project(final_overview, final_vlans, final_bridges):
            raise ValueError('Topology changed during read')
        if time.monotonic() >= deadline:
            raise ValueError('Topology read timeout')
        result.update(networks=networks, status='checked', last_success_at=now.isoformat())
    except Exception:
        pass  # Exception text and complete API responses are never retained.
    return result


def observed(network):
    health = getattr(network.device, 'health', None)
    return health.engines.get('Suricata', {}).get('topology', {}) if health else {}


def current(scope, now=None):
    try:
        stamp = parse_datetime(scope.get('checked_at', ''))
        return bool(scope.get('schema') == 1 and scope.get('status') == 'checked' and stamp
            and timedelta(0) <= (now or timezone.now()) - stamp <= timedelta(minutes=30))
    except (ValueError, TypeError, AttributeError):
        return False


def snapshot(network, fresh, now=None):
    scope = observed(network)
    node = scope.get('networks', {}).get(network.remote_id, {})
    valid = bool(fresh and current(scope, now) and node.get('device') == network.physical_interface)
    try:
        last_success = parse_datetime(scope.get('last_success_at') or '')
    except (ValueError, TypeError):
        last_success = None
    labels = {'physical': 'Puerto físico', 'vlan': 'VLAN', 'bridge': 'Puente', 'virtual': 'Interfaz virtual'}
    result = {'current': valid, 'label': labels.get(node.get('kind'), 'Tipo sin comprobar') if valid else 'Topología: consulta actual pendiente',
        'node': node if valid else {}, 'checked_at': last_success, 'relations': []}
    if valid:
        engines = network.device.health.engines
        zen = engines.get('Zenarmor', {}).get('scope', {})
        from .zenarmor_scope import scope_current
        if zen.get('interfaces_known') is True and scope_current(zen, now):
            names = {v['name'] for v in zen.get('interfaces', [])}
            linked = sorted(names.intersection(node['related'] + node['related_interfaces']))
            if linked:
                result['relations'].append('Zenarmor selecciona interfaces relacionadas: ' + ', '.join(linked) + '. Validar el recorrido y probar esta red.')
        sur = engines.get('Suricata', {})
        if sur.get('interfaces_known') is True:
            names = set(sur.get('interfaces') or [])
            linked = sorted(names.intersection(node['related']))
            if linked:
                result['relations'].append('Suricata selecciona interfaces relacionadas: ' + ', '.join(linked) + '. Validar el recorrido y probar esta red.')
    return result

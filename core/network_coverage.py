"""Bounded readonly discovery and network-specific proof, without inferring blanket protection."""
import hashlib
import ipaddress
import json
from datetime import timedelta
from django.db import transaction
from django.utils import timezone
from .models import NetworkCheck, NetworkCoverage

MAX_NETWORKS = 250
ENGINE_NAMES = {'suricata': 'Suricata', 'unifi': 'UniFi IPS', 'zenarmor': 'Zenarmor', 'clamav': 'ClamAV'}


def literal(value, size=120):
    return value[:size] if isinstance(value, str) else ''


def cidrs(values):
    result = set()
    for value in values:
        if not value:
            continue
        try:
            network = ipaddress.ip_network(value, strict=False)
        except (ValueError, TypeError):
            raise ValueError('Invalid network address')
        if network.is_loopback or network.is_link_local or network.is_multicast or network.prefixlen == 0:
            continue
        result.add(str(network))
    return sorted(result)


def opnsense_networks(data, engine):
    rows = data.get('rows') if isinstance(data, dict) else None
    if not isinstance(rows, list) or not 0 < len(rows) <= MAX_NETWORKS or int(data.get('total', -1)) != len(rows):
        raise ValueError('Incomplete interface catalogue')
    selected = engine.get('interfaces')
    known = engine.get('interfaces_known') is True and isinstance(selected, list)
    result = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError('Invalid interface')
        identifier = literal(row.get('identifier'))
        if not identifier or identifier in ('lo0', 'pfsync0'):
            continue
        physical = literal(row.get('device'))
        values = [row.get('addr4'), row.get('addr6')]
        for family in ('ipv4', 'ipv6'):
            for address in row.get(family, []) or []:
                if isinstance(address, dict):
                    values.append(address.get('ipaddr'))
        result.append({'remote_id': identifier, 'name': literal(row.get('description'), 180) or identifier,
            'interface': identifier, 'physical_interface': physical, 'cidrs': cidrs(values),
            'role': 'wan' if identifier.lower().startswith('wan') else 'network',
            'enabled': row.get('enabled') if isinstance(row.get('enabled'), bool) else None,
            'inspection_selected': (identifier in selected or physical in selected) if known else None})
    return result


def unifi_networks(data, settings):
    if not isinstance(data,dict):
        raise ValueError('Invalid network catalogue')
    rows = data.get('data') if isinstance(data, dict) else None
    if data.get('meta', {}).get('rc', 'ok') != 'ok' or not isinstance(rows, list) or not 0 < len(rows) <= MAX_NETWORKS:
        raise ValueError('Incomplete network catalogue')
    records = settings.get('data') if isinstance(settings, dict) else None
    if not isinstance(records, list) or settings.get('meta', {}).get('rc', 'ok') != 'ok':
        records = []
    ips = next((r for r in records if isinstance(r, dict) and r.get('key') == 'ips'), {})
    selected = ips.get('enabled_networks')
    known = isinstance(selected, list) and all(isinstance(v, str) for v in selected)
    result = []
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get('_id'), str) or len(row['_id']) > 120:
            raise ValueError('Invalid network identity')
        result.append({'remote_id': row['_id'], 'name': literal(row.get('name'), 180) or row['_id'],
            'interface': '', 'physical_interface': '', 'cidrs': cidrs([row.get('ip_subnet')]),
            'role': 'wan' if row.get('purpose') == 'wan' else 'network',
            'enabled': row.get('enabled') if isinstance(row.get('enabled'), bool) else None,
            'inspection_selected': row['_id'] in selected if known else None})
    return result


def save_discovery(device, rows, now=None):
    now = now or timezone.now()
    identities = [r['remote_id'] for r in rows]
    if not identities or len(set(identities)) != len(identities) or len(rows) > MAX_NETWORKS:
        raise ValueError('Invalid or empty catalogue')
    with transaction.atomic():
        for values in rows:
            NetworkCoverage.objects.update_or_create(device=device, remote_id=values['remote_id'],
                defaults={**values, 'last_seen_at': now, 'present': True})
        device.networks.exclude(remote_id__in=identities).update(present=False)
        NetworkCheck.objects.update_or_create(device=device, defaults={
            'checked_at': now, 'last_success_at': now, 'status': 'checked'})


def discover_networks(device, engines, now=None):
    now = now or timezone.now()
    try:
        if device.management_method != 'api':
            raise ValueError('Unsupported connector')
        if device.vendor == 'opnsense':
            from .provisioning import _api_request
            from .interface_topology import collect
            overview = _api_request(device.opnsense_api,
                '/api/interfaces/overview/interfaces_info?rowCount=-1')
            rows = opnsense_networks(overview, engines.get('Suricata', {}))
            suricata = engines.setdefault('Suricata', {})
            suricata['topology'] = collect(device.opnsense_api, overview, _api_request,
                previous=suricata.get('topology'), now=now)
            health = getattr(device, 'health', None)
            if health:
                health.engines = engines
                health.save(update_fields=['engines', 'updated_at'])
        elif device.vendor == 'unifi':
            from .unifi_cloud import connector_json, decrypt_api_key
            connection = device.unifi_cloud
            key = decrypt_api_key(connection.encrypted_api_key)
            catalogue = connector_json(key, connection.remote_host_id, '/network/api/s/default/rest/networkconf')
            try:
                settings = connector_json(key, connection.remote_host_id, '/network/api/s/default/rest/setting')
            except Exception:
                settings = {}
            rows = unifi_networks(catalogue, settings)
        else:
            raise ValueError('Unsupported vendor')
        save_discovery(device, rows, now)
        return len(rows)
    except Exception:
        NetworkCheck.objects.update_or_create(device=device, defaults={'checked_at': now, 'status': 'unavailable'})
        return 0


def current(network, now=None):
    now = now or timezone.now()
    device = network.device
    check = getattr(device, 'network_check', None)
    health = getattr(device, 'health', None)
    return bool(network.present and check and check.status == 'checked' and check.last_success_at
        and timedelta(0) <= now - check.last_success_at <= timedelta(minutes=30)
        and health and health.api_ok is True and health.protection_checked_at
        and timedelta(0) <= now - health.protection_checked_at <= timedelta(minutes=30)
        and device.active and device.site.active and device.site.client.active
        and device.integration != 'paused' and not (health.maintenance_until and health.maintenance_until > now))


def fingerprint(network, engine):
    health = getattr(network.device, 'health', None)
    values = health.engines.get(ENGINE_NAMES.get(engine), {}) if health else {}
    payload = {'remote_id': network.remote_id, 'cidrs': sorted(network.cidrs),
        'interface': network.interface, 'physical': network.physical_interface,
        'enabled': network.enabled, 'selected': network.inspection_selected,
        'configured': values.get('configured'), 'mode': values.get('mode'),
        'interfaces': sorted(values.get('interfaces') or []), 'bypass': values.get('bypass')}
    if engine == 'zenarmor':
        scope = values.get('scope', {})
        payload.pop('selected')  # Suricata selection does not describe Zenarmor.
        payload.update(zenarmor_interfaces=scope.get('interfaces'),
            zenarmor_interfaces_known=scope.get('interfaces_known'), zenarmor_mode=scope.get('mode'),
            zenarmor_policies=scope.get('policy_fingerprint'), zenarmor_policies_status=scope.get('policies_status'))
    if network.device.vendor == 'opnsense':
        from .interface_topology import observed
        topology = observed(network)
        payload.update(topology_status=topology.get('status'),
            topology=topology.get('networks', {}).get(network.remote_id))
    elif network.device.vendor == 'unifi':
        from .unifi_zone_scope import snapshot as zone_snapshot
        observed=zone_snapshot(network.device)
        payload.update(zone_current=observed['current'],zone_fingerprint=observed['catalogue'].get('fingerprint'))
        check=getattr(network.device,'exposure_check',None)
        advanced=check.coverage.get('advanced',{}) if check else {}
        payload['advanced']={k:{f:advanced.get(k,{}).get(f) for f in ('status','fingerprint')} for k in ('acl','upnp')}
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def matches_ip(address, networks):
    try:
        host = ipaddress.ip_address(address)
        return any(host in ipaddress.ip_network(n) for n in networks)
    except (ValueError, TypeError):
        return False


def uniquely_contains(network, address):
    if not matches_ip(address, network.cidrs):
        return False
    for other in network.device.networks.filter(present=True).exclude(pk=network.pk).exclude(enabled=False):
        if matches_ip(address, other.cidrs):
            return False
    return True


def snapshot(network, now=None):
    now = now or timezone.now()
    fresh = current(network, now)
    device = network.device
    health = getattr(device, 'health', None)
    engines = health.engines if health else {}
    name = 'UniFi IPS' if device.vendor == 'unifi' else 'Suricata'
    engine = 'unifi' if device.vendor == 'unifi' else 'suricata'
    value = engines.get(name, {})
    from .zenarmor_scope import network_snapshot
    zenarmor = network_snapshot(network, fresh, now) if device.vendor == 'opnsense' else None
    from .interface_topology import snapshot as topology_snapshot, observed as topology_observed
    topology = topology_snapshot(network, fresh, now) if device.vendor == 'opnsense' else None
    selection = network.inspection_selected if fresh else None
    if not fresh:
        label = 'Consulta actual pendiente'
    elif network.enabled is False:
        label = 'Interfaz/red desactivada'
    elif value.get('configured') is False:
        label = name + ' desactivado'
    elif value.get('running') is False:
        label = name + ' detenido'
    elif selection is False:
        label = 'No seleccionada en ' + name
    elif selection is True:
        label = ('IPS configurado' if value.get('mode') == 'ips' else
                 'IDS configurado; no acredita bloqueo' if value.get('mode') == 'ids' else 'Seleccionada; modo sin comprobar')
    else:
        label = 'Selección sin comprobar'
    proofs = {}
    for candidate in network.validations.select_related('evidence').exclude(evidence=None).order_by('-started_at')[:50]:
        if candidate.engine in proofs:
            continue
        compatible = candidate.engine != 'zenarmor' or (zenarmor and zenarmor['policies_current'] and zenarmor['selection'] is not None)
        if device.vendor == 'opnsense' and topology_observed(network) and not topology['current']:
            compatible = False
        if fresh and compatible and candidate.started_at >= now - timedelta(days=30) and uniquely_contains(network,candidate.test_ip) and candidate.configuration_fingerprint == fingerprint(network, candidate.engine):
            proofs[candidate.engine] = candidate
    excluded = network.scope == 'excluded' and network.review_until and network.review_until > now
    gaps = []
    if network.scope == 'pending':
        gaps.append('Definir si esta red forma parte del servicio y los motores que necesita.')
    elif network.scope == 'excluded' and not excluded:
        gaps.append('La exclusión ha vencido; revisar su justificación.')
    elif network.scope == 'included':
        if topology and not topology['current']:
            gaps.append('Consultar la topología actual y revisar padres VLAN, miembros del puente o recorrido del túnel.')
        if network.require_ips:
            if not fresh or selection is None:
                gaps.append('Comprobar selección y modo IPS mediante una consulta reciente.')
            elif selection is False:
                gaps.append('La red no está seleccionada en ' + name + '; revisar la arquitectura y otras interfaces de inspección.')
            elif value.get('configured') is False or value.get('running') is False or value.get('mode') != 'ips' or network.enabled is False:
                gaps.append('La configuración observada no acredita el IPS requerido.')
            if engine not in proofs:
                gaps.append('Preparar una prueba IPS desde un equipo de esta red.')
            elif proofs[engine].evidence.action != 'blocked':
                gaps.append('La prueba fue recibida, pero su acción no acredita bloqueo.')
        if network.require_zenarmor:
            if not zenarmor or not zenarmor['current'] or zenarmor['selection'] is None:
                gaps.append('Consultar las interfaces seleccionadas de Zenarmor con una conexión API compatible.')
            elif zenarmor['selection'] is False:
                gaps.append('Esta interfaz no está seleccionada explícitamente en Zenarmor; revisar interfaces, VLAN y recorrido del tráfico.')
            if not zenarmor or not zenarmor['policies_current']:
                gaps.append('Consulta completa de políticas Zenarmor pendiente; revisar versión y permisos API.')
            elif zenarmor['selection'] is True and not zenarmor['candidates']:
                gaps.append('No se han encontrado políticas activas candidatas para esta interfaz y subred; revisar los criterios en Zenarmor.')
            if engines.get('Zenarmor', {}).get('running') is not True or engines.get('Zenarmor', {}).get('bypass') is not False:
                gaps.append('Comprobar que el motor Zenarmor está en marcha y fuera de bypass.')
            gaps.append('Revisar la política efectiva, sus condiciones y las exenciones globales de tráfico en Zenarmor.')
            if 'zenarmor' not in proofs:
                gaps.append('Preparar una prueba Zenarmor desde un equipo de esta red.')
            elif proofs['zenarmor'].evidence.action != 'blocked':
                gaps.append('La prueba Zenarmor fue recibida, pero su acción no acredita bloqueo.')
    return {'network': network, 'current': fresh, 'label': label, 'proofs': list(proofs.values()),
        'gaps': gaps, 'excluded': bool(excluded), 'selection': selection, 'zenarmor': zenarmor, 'topology': topology}

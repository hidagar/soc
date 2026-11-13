"""Fase 2 de las políticas propuestas: aplicar «restringir un servicio publicado» con el control de cambios.

Solo OPNsense con API. No se modifica la publicación (NAT) del cliente: el plan crea objetos propios,
identificados por su descripción, y por tanto reversibles sin tocar nada ajeno:

- un alias con las IPs o redes autorizadas (`SOC_POL_<plan>`);
- una regla de bloqueo en la interfaz externa, desactivada al crearla, para el destino y el puerto del
  servicio cuando el origen NO está en el alias.

El resto es el ciclo de `change_control`: borrador desactivado, aprobación con MFA, punto de
recuperación, comprobación del acceso de gestión y reversión automática si no se confirma a tiempo.
Un alias vacío bloquearía a todo el mundo: por eso se exige al menos un origen y, antes de dar el
borrador por preparado, se comprueba que la tabla del firewall tiene entradas.

El filtro por país, el modo del IPS y UniFi siguen aplicándose a mano (ver docs/operations.md).
"""
import ipaddress
import re

from .models import ChangePlan

TEMPLATE = 'policy_restrict'
VERSION = '1.0'
TITLE = 'Restringir el acceso a un servicio publicado'
MAX_ORIGINS = 20
INTERFACE = re.compile(r'^(wan[0-9]*|opt[0-9]+)$')
PROTOCOLS = {'tcp': 'TCP', 'udp': 'UDP', 'tcp/udp': 'TCP/UDP'}


def alias_name(plan):
    return f'SOC_POL_{plan.pk}'


def parse_origins(text):
    """IPs o redes IPv4 autorizadas, una por línea o separadas por comas. Rechaza redes demasiado amplias."""
    values = []
    for raw in re.split(r'[\s,;]+', text or ''):
        if not raw:
            continue
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            raise ValueError(f'«{raw}» no es una IP ni una red válida.') from None
        if network.version != 4:
            raise ValueError('Esta versión prepara reglas IPv4; un origen IPv6 se restringe a mano.')
        if network.prefixlen < 16:
            raise ValueError(f'«{raw}» es una red demasiado amplia: autoriza redes de /16 o más pequeñas.')
        value = str(network.network_address) if network.prefixlen == 32 else str(network)
        if value not in values:
            values.append(value)
    if not values:
        raise ValueError('Indica al menos una IP o red autorizada: sin ninguna, la regla bloquearía a todo el mundo.')
    if len(values) > MAX_ORIGINS:
        raise ValueError(f'Como mucho {MAX_ORIGINS} orígenes; para más, usa una VPN.')
    return values


def target(proposal):
    """(interfaz, destino, puerto, protocolo) de la regla, o ValueError con el motivo por el que no es automatizable."""
    device, finding = proposal.device, proposal.exposure
    if proposal.kind != 'restrict_service':
        raise ValueError('Solo «restringir un servicio publicado» se aplica con el control de cambios.')
    if not device or device.vendor != 'opnsense' or device.management_method != 'api' or not hasattr(device, 'opnsense_api'):
        raise ValueError('Requiere un OPNsense conectado por API.')
    if finding is None or not finding.present:
        raise ValueError('El hallazgo del control de exposición ya no existe.')
    evidence = finding.evidence or {}
    interface = str(evidence.get('interface', '')).strip().lower()
    if not INTERFACE.match(interface):
        raise ValueError('La publicación usa varias interfaces o un grupo: se restringe a mano.')
    try:
        destination = ipaddress.ip_address(str(evidence.get('destination', '')).strip())
    except ValueError:
        raise ValueError('El destino de la publicación no es una IP fija (alias o el propio firewall): se restringe a mano.') from None
    if destination.version != 4:
        raise ValueError('Esta versión prepara reglas IPv4.')
    port = str(evidence.get('target_port') or evidence.get('port') or '').strip().replace(':', '-')
    if not re.fullmatch(r'\d{1,5}(-\d{1,5})?', port) or not all(1 <= int(p) <= 65535 for p in port.split('-')):
        raise ValueError('El puerto de la publicación no es un puerto o rango literal: se restringe a mano.')
    protocol = PROTOCOLS.get(str(evidence.get('protocol', '')).strip().lower())
    if not protocol:
        raise ValueError('El protocolo de la publicación no es TCP ni UDP: se restringe a mano.')
    return interface, str(destination), port, protocol


def automatable(proposal):
    """Cadena vacía si se puede preparar con el control de cambios; si no, el motivo."""
    try:
        target(proposal)
    except ValueError as exc:
        return str(exc)
    return ''


def build_preview(proposal, origins):
    interface, destination, port, protocol = target(proposal)
    service = (proposal.evidence or {}).get('service', 'el servicio')
    return {
        'profile': TITLE, 'version': VERSION, 'networks': [], 'interface': interface,
        'alias': {'type': 'network', 'content': origins, 'description': f'Orígenes autorizados para {service}'},
        'rules': [{'enabled': '0', 'sequence': '1', 'action': 'block', 'quick': '1', 'interface': interface, 'direction': 'in',
                   'ipprotocol': 'inet', 'protocol': protocol, 'source_net': 'Orígenes autorizados', 'source_not': '1',
                   'destination_net': destination, 'destination_port': port, 'log': '1'}],
        'checks': [f'La regla bloquea en {interface.upper()} el acceso a {destination}:{port} desde cualquier origen que no esté autorizado: {", ".join(origins)}.',
                   'No modifica la publicación (NAT) del cliente: retirar esta regla devuelve el acceso tal como estaba.',
                   'Confirmar con el cliente que la lista de orígenes está completa (proveedor, otras sedes, teletrabajo).',
                   'Tras activar, comprobar desde un origen autorizado que el servicio responde y, desde otro, que ya no conecta, antes de confirmar.',
                   'Si un permiso anterior del firewall acepta antes ese tráfico, la regla no tendría efecto: la verificación de la política lo detecta a los 7 días.'],
        'zenarmor': [], 'suricata': [],
    }


def create_plan(proposal, origins, user):
    """Borrador del cambio (no escribe nada en el firewall) enlazado a la propuesta."""
    preview = build_preview(proposal, origins)
    plan = ChangePlan.objects.create(
        device=proposal.device, template=TEMPLATE, template_version=VERSION, title=f'{TITLE}: {proposal.evidence.get("service", "")}'[:240],
        parameters={'client': proposal.client_id, 'proposal': proposal.pk, 'finding': proposal.exposure_id, 'origins': origins},
        preview=preview, requested_by=user)
    type(proposal).objects.filter(pk=proposal.pk).update(change_plan=plan)
    return plan


def stage_alias(plan, api, connection, completed):
    """Crea (o reutiliza) el alias de orígenes del plan y comprueba que la tabla cargada no está vacía."""
    origins = parse_origins('\n'.join(plan.parameters.get('origins') or []))
    name, description = alias_name(plan), f'SOC PLAN {plan.pk} alias'
    desired = {'enabled': '1', 'name': name, 'type': 'network', 'content': '\n'.join(origins), 'description': description}
    rows = api(connection, '/api/firewall/alias/search_item?rowCount=-1').get('rows', [])
    found = next((r for r in rows if r.get('name') == name), None)
    if found:
        if found.get('description') != description:
            raise ValueError('Ya existe un alias con ese nombre que no pertenece a esta propuesta.')
        uid = found['uuid']
    else:
        response = api(connection, '/api/firewall/alias/add_item', {'alias': desired})
        if response.get('result') != 'saved' or not response.get('uuid'):
            raise ValueError('Creación del alias rechazada.')
        uid = response['uuid']
    if not any(o['uuid'] == uid for o in plan.remote_objects):
        plan.remote_objects.append({'kind': 'alias', 'uuid': uid, 'rule': {'description': description, 'name': name}})
        plan.save(update_fields=['remote_objects'])
    if not completed(api(connection, '/api/firewall/alias/reconfigure', {})):
        raise ValueError('No se confirmó la carga del alias.')
    # Con la tabla vacía, «bloquear lo que no esté en el alias» bloquearía a todo el mundo.
    table = api(connection, '/api/firewall/alias_util/list/' + name)
    loaded = table.get('total') if isinstance(table.get('total'), int) else len(table.get('rows') or [])
    if loaded < len(origins):
        raise ValueError('La tabla de orígenes autorizados no se cargó completa en el firewall.')
    return name


def active_findings(client):
    """Hallazgos de exposición de este cliente que ya tienen una regla de restricción activa."""
    plans = ChangePlan._base_manager.filter(device__site__client=client, template=TEMPLATE, status='active')
    return {plan.parameters.get('finding') for plan in plans if plan.parameters.get('finding')}


def sync_applied(now):
    """Marca como aplicadas las propuestas aprobadas cuyo plan ya está activo y confirmado. Devuelve cuántas."""
    from .models import PolicyProposal
    done = 0
    rows = PolicyProposal._base_manager.filter(status='approved', change_plan__template=TEMPLATE, change_plan__status='active')
    for proposal in rows.select_related('change_plan'):
        done += PolicyProposal._base_manager.filter(pk=proposal.pk, status='approved').update(
            status='applied', applied_at=now, applied_by=proposal.change_plan.approved_by, updated_at=now,
            applied_note='Aplicada con el control de cambios (regla propia del SOC, reversible).')
    return done

"""Políticas de firewall que el SOC propone a cada cliente a partir de su configuración y sus detecciones.

Fase 1 (reducción de exposición y endurecimiento). El trabajo `policy_proposals` (cada 6 horas):

1. **Propone** con evidencia de los últimos 30 días:
   - `restrict_service`: un servicio publicado en Internet a cualquier origen (control de exposición),
     con los ataques que recibe ese puerto.
   - `geo_filter`: alternativa cuando casi todos los ataques a ese servicio llegan de fuera de los
     países habituales del cliente (`SOC_PORTAL_POLICY_HOME_COUNTRIES`, por defecto ES).
   - `ips_block`: IPS en modo detección con detecciones permitidas.
   - `outbound_c2`: equipos que conectan con destinos de malware o control remoto (Q-Feeds) sin la
     lista de salida del SOC activada.
   - `inbound_blocklist`: atacantes que repiten sin la lista de bloqueo del SOC activada.
2. **Verifica** lo aplicado a partir de los 7 días: la configuración leída del firewall y, si procede,
   que dejen de entrar ataques permitidos. Si no se puede comprobar en 30 días, lo dice.

Nada se aplica solo: el SOC revisa y ofrece, el cliente aprueba o rechaza en su portal y el SOC aplica
(con el control de cambios donde existe plantilla, o como actuación guiada). Lo que ve el cliente se
congela al ofrecérselo y solo contiene cifras, el servicio y el firewall (invariante 3). Una detección
no prueba un compromiso y una regla nueva no garantiza el bloqueo: por eso se verifica después.
"""
import ipaddress
import os
from collections import Counter
from datetime import timedelta

from django.db import transaction
from django.utils import timezone

from .models import BlocklistFeed, Client, Device, ExposureFinding, PolicyProposal, ThreatIntelMatch

WINDOW = timedelta(days=30)
VERIFY_AFTER = timedelta(days=7)
VERIFY_LIMIT = timedelta(days=30)
REPROPOSE_AFTER = timedelta(days=90)
OPEN_CUSTOMER = ('offered', 'approved', 'applied')
SERVICES = {'21': 'FTP', '22': 'SSH', '23': 'Telnet', '25': 'correo (SMTP)', '80': 'web (HTTP)', '135': 'RPC de Windows',
            '139': 'compartición de Windows (NetBIOS)', '443': 'web (HTTPS)', '445': 'compartición de archivos (SMB)',
            '1433': 'SQL Server', '1723': 'VPN PPTP', '3306': 'MySQL', '3389': 'escritorio remoto (RDP)', '5432': 'PostgreSQL',
            '5900': 'VNC', '5985': 'administración remota de Windows', '5986': 'administración remota de Windows',
            '8080': 'web alternativa', '8443': 'administración web'}
EXPOSURE_KINDS = ('publication', 'wan_permission', 'management')


def home_countries():
    value = os.environ.get('SOC_PORTAL_POLICY_HOME_COUNTRIES', 'ES')
    return {c.strip().upper() for c in value.split(',') if len(c.strip()) == 2} or {'ES'}


def _public(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except (TypeError, ValueError):
        return False


def _ports(evidence):
    """Puertos literales de la regla, o None si es un alias, un rango grande o «cualquiera»."""
    ports = set()
    for field in ('port', 'target_port'):
        value = str(evidence.get(field) or '').strip()
        if not value:
            continue
        for part in value.split(','):
            part = part.strip()
            bounds = part.replace(':', '-').split('-')
            if not all(b.isdigit() for b in bounds) or len(bounds) > 2:
                return None
            low, high = int(bounds[0]), int(bounds[-1])
            if not 1 <= low <= high <= 65535 or high - low > 20:
                return None
            ports.update(str(p) for p in range(low, high + 1))
    return ports or None


def service_label(ports):
    if not ports:
        return 'un servicio'
    named = [SERVICES[p] for p in sorted(ports, key=int) if p in SERVICES]
    if named:
        return ' y '.join(dict.fromkeys(named))
    return 'el puerto ' + ', '.join(sorted(ports, key=int)[:3])


def attacks(client, device, since, ports=None, now=None):
    """Cifras de los ataques entrantes desde Internet al firewall (y a esos puertos, si se indican)."""
    from .investigation import evidence_queryset
    now = now or timezone.now()
    days = max(1, (now - since).days)
    rows = evidence_queryset(client, days).filter(device=device, observed_at__gte=since)
    if ports:
        rows = rows.filter(destination_port__in=list(ports))
    stats = {'total': 0, 'allowed': 0, 'blocked': 0, 'sources': set(), 'countries': Counter(), 'foreign': 0}
    home = home_countries()
    for source, action, geography in rows.values_list('source_ip', 'action', 'geography')[:20000]:
        if not _public(source):
            continue
        stats['total'] += 1
        stats['allowed'] += action == 'allowed'
        stats['blocked'] += action == 'blocked'
        stats['sources'].add(source)
        code = (geography or {}).get('country_code', '')
        if code:
            stats['countries'][code] += 1
            stats['foreign'] += code not in home
    return {'total': stats['total'], 'allowed': stats['allowed'], 'blocked': stats['blocked'], 'sources': len(stats['sources']),
            'countries': len(stats['countries']), 'top_countries': [c for c, _ in stats['countries'].most_common(5)],
            'located': sum(stats['countries'].values()), 'foreign': stats['foreign']}


def _vendor_steps(device, kind, rule_name, label):
    name = f'«{rule_name}»' if rule_name else 'correspondiente'
    if kind == 'restrict_service':
        if device.vendor == 'unifi':
            return (f'UniFi › Ajustes › Seguridad/Enrutamiento › Reenvío de puertos {name}: limitar «Origen» a las IPs autorizadas '
                    f'(proveedor, oficinas) o retirar el reenvío y dar acceso por VPN (Teleport/WireGuard). Servicio: {label}.')
        return (f'OPNsense › Firewall › NAT › Reenvío de puertos {name}: cambiar «Origen» de «cualquiera» a un alias con las IPs '
                f'autorizadas, o retirar la publicación y usar la VPN. Revisar la regla de filtro asociada. Servicio: {label}. '
                'Copia de configuración antes del cambio.')
    if kind == 'geo_filter':
        if device.vendor == 'unifi':
            return (f'UniFi › Ajustes › Seguridad › Restricción por región: bloquear el tráfico entrante de fuera de los países '
                    f'del cliente para el reenvío {name} ({label}), o crear una regla de entrada con origen limitado por región.')
        return (f'OPNsense › Firewall › Alias: crear un alias GeoIP con los países del cliente; en la publicación {name} ({label}) '
                'usarlo como «Origen». Requiere la base GeoIP configurada en el firewall.')
    if kind == 'ips_block':
        if device.vendor == 'unifi':
            return 'UniFi › Ajustes › Seguridad › Detección y prevención de amenazas: cambiar el modo de «Detección» a «Prevención».'
        return ('OPNsense › Servicios › Detección de intrusiones › Administración: activar el modo IPS (y el bloqueo en Zenarmor si '
                'aplica). Antes, revisar las alertas de 30 días y desactivar las firmas que dan falsos positivos.')
    return ''


def _proposals(client, now):
    """Propuestas que corresponden hoy al cliente: {key: datos}."""
    result = {}
    since = now - WINDOW
    devices = list(Device._base_manager.filter(site__client=client, active=True, site__active=True).select_related('site'))
    by_id = {d.pk: d for d in devices}
    from .exposure import any_network
    from .policy_changes import active_findings
    restricted = active_findings(client)  # ya tienen una regla del SOC que limita el origen
    for finding in ExposureFinding._base_manager.filter(device_id__in=by_id, present=True, kind__in=EXPOSURE_KINDS):
        if finding.exception_active or finding.pk in restricted or not any_network(finding.evidence.get('source', '')):
            continue
        device = by_id[finding.device_id]
        ports = _ports(finding.evidence)
        label = service_label(ports)
        stats = attacks(client, device, since, ports, now) if ports else None
        total = stats['total'] if stats else 0
        if finding.severity != 'high' and not total:
            continue
        confidence = 'high' if stats and (stats['allowed'] or total >= 20) else 'medium' if total else 'low'
        rule = str(finding.evidence.get('name') or '')[:80]
        evidence = {'service': label, 'ports': sorted(ports, key=int) if ports else [], 'rule': rule, 'severity': finding.severity,
                    'attacks': stats, 'firewall': device.name, 'site': device.site.name}
        result[f'restrict:{finding.pk}'] = {
            'kind': 'restrict_service', 'device': device, 'exposure': finding, 'confidence': confidence, 'evidence': evidence,
            'title': f'Restringir el acceso a {label} publicado en {device.name}',
            'change': _vendor_steps(device, 'restrict_service', rule, label),
            'risk': 'Quien acceda hoy desde otras direcciones dejará de conectar. Confirmar antes con el cliente qué orígenes '
                    'necesitan acceso (proveedor de software, teletrabajo, otra sede).',
            'customer_title': f'Limitar quién puede acceder a {label} desde Internet'}
        if stats and total >= 20 and stats['located'] and stats['foreign'] / stats['located'] >= 0.9 and stats['countries'] >= 3:
            result[f'geo:{finding.pk}'] = {
                'kind': 'geo_filter', 'device': device, 'exposure': finding, 'confidence': 'medium', 'evidence': evidence,
                'title': f'Filtrar por país el acceso a {label} en {device.name}',
                'change': _vendor_steps(device, 'geo_filter', rule, label),
                'risk': 'Usuarios de viaje o proveedores de otros países dejarían de conectar. Es una alternativa si no se pueden '
                        'fijar las IPs autorizadas; no sustituye a la VPN.',
                'customer_title': f'Permitir el acceso a {label} solo desde vuestros países habituales'}
    from .protection import snapshot
    for device in devices:
        try:
            snap = snapshot(device, now, incidents=False)
        except Exception:
            continue
        ids = [c for c in snap['controls'] if c['name'] in ('Suricata', 'UniFi IPS') and c['mode'] == 'ids']
        if not ids or not snap['current']:
            continue
        stats = attacks(client, device, since, now=now)
        result[f'ips:{device.pk}'] = {
            'kind': 'ips_block', 'device': device, 'exposure': None, 'confidence': 'high' if stats['allowed'] else 'medium',
            'evidence': {'attacks': stats, 'engine': ids[0]['name'], 'firewall': device.name, 'site': device.site.name},
            'title': f'Pasar el IPS de {device.name} a modo bloqueo',
            'change': _vendor_steps(device, 'ips_block', '', ''),
            'risk': 'Una firma con falsos positivos bloquearía tráfico legítimo. Se revisan antes las alertas de 30 días.',
            'customer_title': 'Que el firewall bloquee los ataques que detecta, en lugar de solo avisar'}
    feed = BlocklistFeed.objects.filter(client=client).first()
    outbound = ThreatIntelMatch._base_manager.filter(client=client, role='destination')
    allowed_out = sum(outbound.values_list('allowed', flat=True))
    if devices and outbound.exists() and not (feed and feed.enabled and feed.outbound_enabled and not feed.stopped):
        result['outbound_c2'] = {
            'kind': 'outbound_c2', 'device': None, 'exposure': None, 'confidence': 'high' if allowed_out else 'medium',
            'evidence': {'destinations': outbound.count(), 'allowed': allowed_out, 'internal_hosts': len({p for peers in outbound.values_list('peers', flat=True) for p in peers})},
            'title': 'Bloquear la salida hacia destinos de malware y control remoto',
            'change': 'Listas de bloqueo › activar la lista de salida (C2) del cliente y crear la regla de salida: en OPNsense con el '
                      'control de cambios; en UniFi, la política de salida vinculada.',
            'risk': 'Un destino legítimo mal clasificado quedaría bloqueado: se añade a «Excepciones» de la lista.',
            'customer_title': 'Impedir que vuestros equipos conecten con servidores de malware conocidos'}
    if devices and not (feed and feed.enabled and not feed.stopped):
        sources = Counter()
        from .investigation import evidence_queryset
        for source in evidence_queryset(client, WINDOW.days).values_list('source_ip', flat=True)[:20000]:
            if _public(source):
                sources[source] += 1
        repeated = [ip for ip, n in sources.items() if n >= 3]
        if len(repeated) >= 10:
            result['inbound_blocklist'] = {
                'kind': 'inbound_blocklist', 'device': None, 'exposure': None, 'confidence': 'high' if len(repeated) >= 50 else 'medium',
                'evidence': {'repeat_sources': len(repeated), 'events': sum(sources[ip] for ip in repeated)},
                'title': 'Activar la lista de bloqueo del SOC (atacantes conocidos)',
                'change': 'Listas de bloqueo › activar la lista del cliente y crear la regla con el control de cambios (OPNsense) o '
                          'escribirla en la consola (UniFi). Empezar en observación si hay dudas.',
                'risk': 'Bajo: solo IPs con mala reputación. Las de proveedores y socios se añaden a «Excepciones».',
                'customer_title': 'Bloquear de antemano a los atacantes que el SOC ya conoce'}
    return result


def generate(now=None, clients=None):
    """Crea o actualiza propuestas. Devuelve cuántas nuevas. Lo ya ofrecido al cliente no se toca."""
    now = now or timezone.now()
    created = 0
    for client in clients if clients is not None else Client._base_manager.filter(active=True):
        wanted = _proposals(client, now)
        existing = {p.key: p for p in PolicyProposal._base_manager.filter(client=client)}
        with transaction.atomic():
            for key, data in wanted.items():
                fields = {k: data[k] for k in ('kind', 'device', 'exposure', 'confidence', 'evidence', 'title', 'change', 'risk')}
                proposal = existing.get(key)
                if proposal is None:
                    PolicyProposal._base_manager.create(client=client, key=key, customer_title=data['customer_title'],
                                                        created_at=now, updated_at=now, evaluated_at=now, **fields)
                    created += 1
                    continue
                reopen = (proposal.status in ('obsolete',) or
                          (proposal.status in ('dismissed', 'rejected') and (proposal.decided_at or proposal.updated_at) < now - REPROPOSE_AFTER) or
                          proposal.status == 'verified')
                if proposal.status == 'proposed' or reopen:
                    for name, value in fields.items():
                        setattr(proposal, name, value)
                    if reopen:
                        proposal.evidence = {**proposal.evidence, 'reopened_from': proposal.status}
                        proposal.status, proposal.customer_title = 'proposed', data['customer_title']
                        proposal.customer_summary, proposal.notice_status = {}, ''
                    proposal.evaluated_at = proposal.updated_at = now
                    proposal.save()
            # Lo que ya no se cumple y nadie ha ofrecido todavía.
            PolicyProposal._base_manager.filter(client=client, status='proposed').exclude(key__in=list(wanted)).update(
                status='obsolete', updated_at=now)
    return created


def verify(now=None):
    """Comprueba lo aplicado a partir de los 7 días. Devuelve cuántas cerró."""
    now = now or timezone.now()
    closed = 0
    for proposal in PolicyProposal._base_manager.filter(status='applied', applied_at__lte=now - VERIFY_AFTER).select_related('client', 'device', 'exposure'):
        ok, text = _check(proposal, now)
        result = {'checked_at': now.isoformat(), 'ok': ok, 'text': text}
        if ok is None and now - proposal.applied_at < VERIFY_LIMIT:
            PolicyProposal._base_manager.filter(pk=proposal.pk).update(verification=result)
            continue
        if ok is None:
            result['text'] = text + ' No se ha podido comprobar en 30 días: revisar a mano.'
        PolicyProposal._base_manager.filter(pk=proposal.pk, status='applied').update(
            status='verified' if ok else 'not_effective', verified_at=now, verification=result, updated_at=now)
        closed += 1
    return closed


def _check(proposal, now):
    """(True | False | None, explicación) a partir de lo que el SOC puede leer hoy."""
    from .exposure import any_network
    kind = proposal.kind
    if kind in ('restrict_service', 'geo_filter'):
        finding = proposal.exposure
        if finding is not None:
            finding.refresh_from_db()
        from .policy_changes import TEMPLATE as RESTRICT
        plan = proposal.change_plan
        if kind == 'restrict_service' and plan is not None and plan.template == RESTRICT:
            # Aplicada con una regla propia: la publicación sigue igual, así que se comprueba la regla y los ataques.
            plan.refresh_from_db()
            if plan.status != 'active':
                return False, f'La regla del SOC ya no está activa ({plan.status_label.lower()}).'
            ports = set(proposal.evidence.get('ports') or [])
            stats = attacks(proposal.client, proposal.device, proposal.applied_at, ports or None, now) if ports else None
            if stats and stats['allowed']:
                return False, f'La regla está activa, pero después han entrado {stats["allowed"]} ataques permitidos a ese servicio: revisar el orden de reglas.'
            return True, 'La regla del SOC que limita el origen sigue activa' + (' y no han entrado ataques permitidos.' if stats is not None else '.')
        if finding is not None and finding.present and any_network(finding.evidence.get('source', '')) and kind == 'restrict_service':
            return False, 'El control de exposición sigue viendo el servicio publicado a cualquier origen.'
        ports = set(proposal.evidence.get('ports') or [])
        stats = attacks(proposal.client, proposal.device, proposal.applied_at, ports or None, now) if proposal.device and ports else None
        if stats and stats['allowed']:
            return False, f'Después del cambio han entrado {stats["allowed"]} ataques permitidos a ese servicio.'
        if kind == 'restrict_service' and (finding is None or not finding.present or not any_network(finding.evidence.get('source', ''))):
            return True, 'El servicio ya no está abierto a cualquier origen' + (' y no han entrado ataques permitidos.' if stats is not None else '.')
        if kind == 'geo_filter' and stats is not None:
            return True, 'Sin ataques permitidos a ese servicio desde la aplicación.'
        return None, 'Sin datos suficientes para comprobarlo.'
    if kind == 'ips_block':
        from .protection import snapshot
        snap = snapshot(proposal.device, now, incidents=False)
        modes = {c['mode'] for c in snap['controls'] if c['name'] in ('Suricata', 'UniFi IPS')}
        if 'ips' in modes and snap['current']:
            return True, 'El IPS está en modo bloqueo según la última lectura del firewall.'
        if 'ids' in modes and snap['current']:
            return False, 'El IPS sigue en modo detección.'
        return None, 'No hay una lectura reciente del modo del IPS.'
    feed = BlocklistFeed.objects.filter(client=proposal.client).first()
    from .blocklist import TEMPLATE, TEMPLATE_OUT
    from .models import ChangePlan, UnifiBlocklistBinding
    template, direction = (TEMPLATE_OUT, 'out') if kind == 'outbound_c2' else (TEMPLATE, 'in')
    enabled = bool(feed and feed.enabled and not feed.stopped and (feed.outbound_enabled if kind == 'outbound_c2' else True))
    rule = (ChangePlan._base_manager.filter(device__site__client=proposal.client, template=template, status='active').exists() or
            UnifiBlocklistBinding._base_manager.filter(device__site__client=proposal.client, direction=direction, enabled=True,
                                                       policies_enabled=True).exists())
    if enabled and rule:
        return True, 'La lista está publicada y hay una regla activa que la usa.'
    if not enabled:
        return False, 'La lista del SOC no está publicada.'
    return False, 'La lista está publicada, pero ningún firewall tiene una regla activa que la use.'


def run(now=None):
    now = now or timezone.now()
    from .policy_changes import sync_applied
    sync_applied(now)
    created = generate(now)
    verify(now)
    return created

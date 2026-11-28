"""Accesos fallidos a los equipos de los clientes (agente Wazuh): Windows, SSH, sudo y PAM.

- Entrada: los mismos eventos de agentes de PC y servidores que el antivirus (`endpoints.observe`, desde
  `alerts.json`) y una recuperación propia desde el indexador. Solo cuentan los equipos asignados y desde su
  asignación (invariante 2).
- Qué es un intento:
  - Windows (canal Security): 4625 inicio de sesión fallido y 4771 preautenticación Kerberos fallida;
    4740 cuenta bloqueada; 4624 inicio de sesión correcto.
  - Cualquier sistema por los grupos de las reglas de Wazuh: `authentication_failed` (fallo),
    `authentication_failures` (Wazuh ya los correlacionó), `authentication_success` (correcto) y la regla 40112
    («varios fallos seguidos de un acceso correcto»). Así entran SSH, sudo, PAM y lo que Wazuh decodifique.
- Ráfaga: mismo equipo y mismo origen (o mismo usuario si no hay origen), con menos de una hora entre intentos.
  Cada alerta de Wazuh se cuenta una vez por su identificador: repetir una lectura no infla los intentos.
- Gravedad (solo empeora): fallos aislados (no se muestran) → repetidos (5 o más, o correlación de Wazuh) →
  cuenta bloqueada → acceso correcto tras los fallos, desde el mismo origen (o del mismo usuario sin origen) en
  los 30 minutos siguientes al último fallo.
- Aviso urgente al cliente solo para el acceso correcto tras los fallos desde una IP de Internet. Puede ser el
  usuario que se equivocó de contraseña; el aviso lo dice (invariante 4). Nunca lleva el usuario ni la IP interna
  (invariante 3).
"""
import hashlib
import ipaddress
import json
from datetime import timedelta

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db import IntegrityError, transaction
from django.db.models import Count, Q
from django.http import HttpResponseForbidden
from django.shortcuts import redirect, render
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_http_methods

from .models import Client, EndpointAccessAlert, EndpointAccessEvent, Incident, IncidentUpdate
from .security import audit

SECURITY_CHANNEL = 'Security'
WIN_FAILED = {'4625', '4771'}
WIN_LOCKOUT = {'4740'}
WIN_SUCCESS = {'4624'}
FAILED_GROUP = 'authentication_failed'
CORRELATED_GROUP = 'authentication_failures'
SUCCESS_GROUP = 'authentication_success'
SUCCESS_AFTER_RULES = {'40112'}  # regla oficial de Wazuh: varios fallos seguidos de un acceso correcto
LOCKOUT_RULES = {'60115'}  # regla oficial de Wazuh para el 4740
BURST_GAP = timedelta(hours=1)
SUCCESS_WINDOW = timedelta(minutes=30)
REPEATED_AT = 5
MAX_COUNTED = 5000  # por ráfaga; más allá se muestra «5000+» sin guardar más identificadores
MAX_USERS = 20
MAX_AGE = timedelta(days=25)  # los identificadores contados se guardan 30 días (retención)
RANK = {'isolated': 0, 'repeated': 1, 'lockout': 2, 'success': 3}
VISIBLE = ('repeated', 'lockout', 'success')
IGNORED_USERS = {'', '-', 'system', 'anonymous logon', 'local service', 'network service'}


def _clean(value, size):
    from .endpoints import _clean as clean
    return clean(value, size)


def _user(value):
    user = _clean(value, 120)
    if user.lower() in IGNORED_USERS or user.endswith('$') or user.upper().startswith(('DWM-', 'UMFD-')):
        return ''  # cuentas de equipo y del sistema: no son personas probando contraseñas
    return user


def _address(value):
    text = str(value or '').strip()
    if text.lower().startswith('::ffff:'):
        text = text[7:]
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    if address.is_loopback or address.is_unspecified or address.is_link_local:
        return None
    return address


def access_event(source):
    """{'outcome': failure|lockout|success, 'correlated', 'after_failures', 'user', 'ip'} o None."""
    rule = source.get('rule') if isinstance(source.get('rule'), dict) else {}
    groups = {str(g) for g in rule.get('groups') or () if isinstance(g, str)} if isinstance(rule.get('groups'), list) else set()
    rule_id = str(rule.get('id') or '')
    data = source.get('data') if isinstance(source.get('data'), dict) else {}
    win = data.get('win') if isinstance(data.get('win'), dict) else {}
    system = win.get('system') if isinstance(win.get('system'), dict) else {}
    outcome = None
    if str(system.get('channel') or '') == SECURITY_CHANNEL:
        event_id = str(system.get('eventID') or '')
        outcome = ('failure' if event_id in WIN_FAILED else 'lockout' if event_id in WIN_LOCKOUT
                   else 'success' if event_id in WIN_SUCCESS else None)
    if outcome is None:
        if rule_id in LOCKOUT_RULES:
            outcome = 'lockout'
        elif rule_id in SUCCESS_AFTER_RULES or SUCCESS_GROUP in groups:
            outcome = 'success'
        elif CORRELATED_GROUP in groups or FAILED_GROUP in groups:
            outcome = 'failure'
    if outcome is None:
        return None
    from .endpoints import _fields
    fields = _fields(win.get('eventdata'))
    # Windows: la cuenta de destino. sudo: quien falla es el usuario de origen; SSH y PAM: la cuenta de destino.
    names = ('srcuser', 'dstuser', 'user') if 'sudo' in groups else ('dstuser', 'srcuser', 'user')
    user = fields.get('targetusername') or next((data.get(n) for n in names if isinstance(data.get(n), str) and data.get(n)), '')
    address = fields.get('ipaddress') or data.get('srcip')
    return {'outcome': outcome, 'correlated': CORRELATED_GROUP in groups, 'after_failures': rule_id in SUCCESS_AFTER_RULES,
            'user': _user(user), 'ip': _address(address)}


def _kind(row):
    if row.succeeded_at:
        return 'success'
    if row.locked_out_at:
        return 'lockout'
    if row.correlated or row.failures >= REPEATED_AT:
        return 'repeated'
    return 'isolated'


def _open_rows(endpoint, stamp, cache):
    """Ráfagas del equipo que pueden recibir este intento; una consulta por equipo y lote."""
    key = ('access', endpoint.pk)
    floor = stamp - BURST_GAP - SUCCESS_WINDOW
    entry = cache.get(key)
    if entry is None or floor < entry['floor']:
        rows = EndpointAccessAlert._base_manager.filter(agent=endpoint, last_at__gte=floor)
        entry = {'floor': floor, 'rows': {}}
        for row in rows:
            row.agent = endpoint
            entry['rows'][row.pk] = row
        cache[key] = entry
    return entry['rows']


def record(endpoint, event, stamp, now, source, cache):
    """Cuenta un intento de un equipo asignado. Llamada desde `endpoints.observe` dentro de la transacción del lote."""
    if now - stamp > MAX_AGE:
        return
    rows = _open_rows(endpoint, stamp, cache)
    if event['outcome'] == 'success':
        _success(endpoint, event, stamp, now, source, rows)
        return
    address = event['ip']
    group_user = '' if address else event['user'].lower()
    if not address and not group_user:
        return  # sin origen ni usuario no se puede agrupar ni explicar
    recent = [r for r in sorted(rows.values(), key=lambda r: r.last_at, reverse=True)
              if r.first_at - BURST_GAP <= stamp <= r.last_at + BURST_GAP]
    row = next((r for r in recent if r.source_ip == (str(address) if address else None) and r.group_user == group_user), None)
    if row is None and event['outcome'] == 'lockout' and group_user:
        # El bloqueo (4740) no trae origen: se une a la ráfaga del equipo que probó esa cuenta.
        row = next((r for r in recent if group_user in (u.lower() for u in r.users)), None)
    if row is None:
        row = EndpointAccessAlert._base_manager.create(
            agent=endpoint, client_scope_id=endpoint.client_id, source_ip=str(address) if address else None,
            source_public=bool(address and address.is_global), group_user=group_user, first_at=stamp, last_at=stamp,
            updated_at=now)
        rows[row.pk] = row
    ident = _clean(source.get('id'), 64)
    if event['outcome'] == 'failure':
        if row.failures >= MAX_COUNTED:
            return
        if ident:
            try:
                with transaction.atomic():
                    EndpointAccessEvent._base_manager.create(agent=endpoint, alert=row, event_id=ident, observed_at=stamp)
            except IntegrityError:
                return  # ya contado (relectura o recuperación)
        row.failures += 1
    elif not row.locked_out_at or stamp < row.locked_out_at:
        row.locked_out_at = stamp
    row.correlated = row.correlated or event['correlated']
    if event['user'] and event['user'] not in row.users and len(row.users) < MAX_USERS:
        row.users = [*row.users, event['user']]
    row.first_at, row.last_at = min(row.first_at, stamp), max(row.last_at, stamp)
    _save(row, now)


def _success(endpoint, event, stamp, now, source, rows):
    address = str(event['ip']) if event['ip'] else None
    user = event['user'].lower()
    candidates = [r for r in rows.values() if r.kind in ('repeated', 'lockout') and not r.succeeded_at
                  and r.first_at <= stamp <= r.last_at + SUCCESS_WINDOW
                  and ((r.source_ip and r.source_ip == address) or (not r.source_ip and user and r.group_user == user))]
    if not candidates and event['after_failures'] and (address or user):
        # Wazuh correlacionó fallos y acceso correcto que el SOC no tenía contados (p. ej. previos a la asignación
        # no: esos no llegan aquí). Se registra con lo que dice la alerta.
        row = EndpointAccessAlert._base_manager.create(
            agent=endpoint, client_scope_id=endpoint.client_id, source_ip=address,
            source_public=bool(event['ip'] and event['ip'].is_global), group_user='' if address else user,
            first_at=stamp, last_at=stamp, correlated=True, updated_at=now)
        rows[row.pk] = row
        candidates = [row]
    rule = source.get('rule') if isinstance(source.get('rule'), dict) else {}
    from .endpoints import _number
    level = _number(rule.get('level')) or 0
    for row in sorted(candidates, key=lambda r: r.last_at, reverse=True)[:1]:
        row.succeeded_at = stamp
        row.success_user = event['user']
        _save(row, now, level)


def _save(row, now, level=0):
    previous = row.kind
    row.kind = _kind(row)
    row.updated_at = now
    if RANK[row.kind] > RANK[previous] and row.review == 'reviewed':
        row.review = 'pending'  # empeora: vuelve a la cola
    EndpointAccessAlert._base_manager.filter(pk=row.pk).update(
        failures=row.failures, correlated=row.correlated, locked_out_at=row.locked_out_at, succeeded_at=row.succeeded_at,
        success_user=row.success_user, users=row.users, first_at=row.first_at, last_at=row.last_at, kind=row.kind,
        updated_at=now, review=row.review)
    if row.kind == 'success' and previous != 'success' and row.urgent:
        _queue_urgent(row, now, level)


def _queue_urgent(row, now, level):
    """Un aviso por ráfaga, como mucho. Sin usuario ni IP interna."""
    from django.core.exceptions import ValidationError
    from django.core.validators import validate_email
    from .models import UrgentAlert
    from .urgent_alerts import MAX_AGE as URGENT_MAX_AGE
    endpoint = row.agent
    client = endpoint.client
    if client is None or not client.active or not client.urgent_alerts_enabled or client.pk != row.client_scope_id:
        return
    recipient = client.urgent_email or client.report_email
    try:
        validate_email(recipient)
    except ValidationError:
        return
    uid = hashlib.sha256(f'endpoint-access\x00{row.pk}'.encode()).hexdigest()
    fingerprint = hashlib.sha256(json.dumps([client.pk, 'endpoint_access', endpoint.agent_id, row.source_ip]).encode()).hexdigest()
    UrgentAlert._base_manager.get_or_create(event_uid=uid, defaults={
        'client': client, 'fingerprint': fingerprint, 'kind': UrgentAlert.Kind.ENDPOINT_ACCESS,
        'status': UrgentAlert.Status.EXPIRED if now - row.succeeded_at > URGENT_MAX_AGE else UrgentAlert.Status.PENDING,
        'observed_at': row.succeeded_at, 'source_ip': endpoint.ip, 'external_ip': row.source_ip,
        'site_name': _clean(endpoint.site.name if endpoint.site else '', 160), 'asset_name': _clean(endpoint.name, 160),
        'signature': attempts_label(row) + ' y después un acceso correcto', 'action': 'success', 'rule_level': max(0, min(level, 65535)),
        'recipient': recipient,
        'interpretation': {'engine': 'wazuh', 'event_family': 'authentication', 'soc_priority': 'critical',
                           'priority_label': 'Crítica', 'failures': row.failures}})


def attempts_label(row):
    if not row.failures:
        return 'Varios intentos fallidos'  # bloqueo o correlación de Wazuh sin los fallos sueltos
    count = f'{MAX_COUNTED}+' if row.failures >= MAX_COUNTED else str(row.failures)
    return f'{count} intento{"s" if row.failures != 1 else ""} fallido{"s" if row.failures != 1 else ""}'


# --- SOC ---------------------------------------------------------------------------------------

def review_queue(client_id=None):
    """Para la bandeja de trabajo: accesos tras fallos y cuentas bloqueadas por revisar."""
    rows = EndpointAccessAlert.objects.filter(review='pending', kind__in=('success', 'lockout')).select_related('agent__client')
    if client_id:
        rows = rows.filter(client_scope_id=client_id)
    return sorted(rows[:200], key=lambda r: (not r.urgent, r.kind != 'success', -r.last_at.timestamp()))


def badge():
    rows = EndpointAccessAlert.objects.filter(review='pending', kind__in=('success', 'lockout')).aggregate(
        total=Count('id'), urgent=Count('id', filter=Q(kind='success')))
    return rows['total'] or 0, bool(rows['urgent'])


def client_summary(client):
    """Para el portal: accesos correctos tras fallos desde Internet que el SOC aún no ha revisado."""
    rows = EndpointAccessAlert.objects.filter(client_scope_id=client.pk, review='pending', kind='success')
    return {'success': rows.count(), 'internet_success': rows.filter(source_public=True).count()}


@login_required
@never_cache
@require_http_methods(['GET', 'POST'])
def overview(request):
    if not request.user.has_perm('core.manage_operations'):
        return HttpResponseForbidden('Permiso de operaciones requerido.')
    now = timezone.now()
    if request.method == 'POST':
        response = _action(request, now)
        return response if response is not None else redirect(request.get_full_path())
    selected = request.GET.get('client', '')
    shown = request.GET.get('show', 'pending')
    rows = EndpointAccessAlert.objects.filter(kind__in=VISIBLE).select_related('agent', 'incident')
    if selected.isdigit():
        rows = rows.filter(client_scope_id=int(selected))
    week = rows.filter(last_at__gte=now - timedelta(days=7))
    kpis = week.aggregate(success=Count('id', filter=Q(kind='success')), lockout=Count('id', filter=Q(kind='lockout')),
                          repeated=Count('id', filter=Q(kind='repeated')),
                          internet=Count('id', filter=Q(source_public=True)),
                          pending=Count('id', filter=Q(review='pending')))
    if shown == 'pending':
        rows = rows.filter(review='pending')
    clients = {c.pk: c for c in Client.objects.all()}
    rows = list(rows.order_by('-last_at')[:300])
    for row in rows:
        row.client = clients.get(row.client_scope_id)
        row.attempts = attempts_label(row)
    rows.sort(key=lambda r: (r.review != 'pending', -RANK[r.kind], not r.source_public, -r.last_at.timestamp()))
    return render(request, 'endpoint_access.html', {
        'rows': rows, 'kpis': kpis, 'clients': Client.objects.filter(active=True), 'selected_client': selected,
        'show': shown, 'can_open_incident': request.user.has_perm('core.add_incident'), 'repeated_at': REPEATED_AT,
        'burst_minutes': int(BURST_GAP.total_seconds() // 60), 'success_minutes': int(SUCCESS_WINDOW.total_seconds() // 60)})


def _action(request, now):
    action = request.POST.get('action', '')
    if action == 'reviewed_repeated':
        # Fallos repetidos sin bloqueo ni acceso: ruido habitual de un servicio expuesto; se revisan en bloque.
        rows = EndpointAccessAlert.objects.filter(review='pending', kind='repeated')
        selected = request.POST.get('client', '')
        if selected.isdigit():
            rows = rows.filter(client_scope_id=int(selected))
        count = rows.update(review='reviewed', reviewed_by=request.user, reviewed_at=now)
        audit('endpoint.access_reviewed', None, {'count': count, 'kind': 'repeated'})
        messages.success(request, f'{count} ráfaga{"s" if count != 1 else ""} de fallos repetidos marcada{"s" if count != 1 else ""} '
                                  'como revisada. Vuelven a la cola si terminan en bloqueo o en un acceso correcto.')
        return None
    if action not in ('reviewed', 'incident'):
        return HttpResponseForbidden('Acción no válida.')
    pk = request.POST.get('alert', '')
    row = EndpointAccessAlert.objects.filter(pk=int(pk) if pk.isdigit() else 0).select_related('agent__site').first()
    if row is None:
        messages.error(request, 'Ese registro ya no existe o no está en tu ámbito.')
        return None
    if action == 'reviewed':
        EndpointAccessAlert.objects.filter(pk=row.pk).update(review='reviewed', reviewed_by=request.user, reviewed_at=now)
        audit('endpoint.access_reviewed', row.agent, {'status': 'reviewed', 'kind': row.kind})
        messages.success(request, 'Marcado como revisado. Vuelve a la cola si empeora.')
        return None
    if not request.user.has_perm('core.add_incident'):
        return HttpResponseForbidden('Tu cuenta no puede abrir incidencias.')
    if row.incident_id:
        return redirect('incident_detail', pk=row.incident_id)
    client = Client.objects.filter(pk=row.client_scope_id).first()
    if client is None:
        return HttpResponseForbidden('Cliente no disponible.')
    origin = (f'{row.source_ip} ({"Internet" if row.source_public else "red interna"})' if row.source_ip
              else 'sin origen en el registro')
    lines = [f'{row.get_kind_display()} en el equipo {row.agent.name} (agente Wazuh {row.agent.agent_id}): '
             f'{attempts_label(row)} entre {timezone.localtime(row.first_at):%d/%m/%Y %H:%M} y '
             f'{timezone.localtime(row.last_at):%d/%m/%Y %H:%M}.',
             f'Origen: {origin}. Cuentas probadas: {", ".join(row.users) or "sin indicar"}.']
    if row.locked_out_at:
        lines.append(f'Cuenta bloqueada a las {timezone.localtime(row.locked_out_at):%H:%M}.')
    if row.succeeded_at:
        lines.append(f'Acceso correcto de «{row.success_user or "sin indicar"}» a las '
                     f'{timezone.localtime(row.succeeded_at):%H:%M}.')
    lines.append('Un acceso correcto tras fallos puede ser el propio usuario: confirmarlo con él antes de concluir. '
                 'Si no lo reconoce, cambiar la contraseña, cerrar sus sesiones y revisar el equipo.')
    with transaction.atomic():
        incident = Incident.objects.create(
            client=client, site=row.agent.site, title=f'{row.get_kind_display()} en {row.agent.name}'[:220],
            description='\n\n'.join(lines), observed_at=row.first_at, owner=request.user,
            severity='critical' if row.urgent else 'high' if row.kind in ('success', 'lockout') else 'medium')
        IncidentUpdate.objects.create(incident=incident, author=request.user, text='Abierta desde «Accesos a equipos».')
        EndpointAccessAlert.objects.filter(pk=row.pk).update(review='incident', incident=incident, reviewed_by=request.user,
                                                             reviewed_at=now)
        audit('endpoint.access_incident', row.agent, {'incident_id': incident.pk})
    messages.success(request, 'Incidencia interna abierta. El cliente no la ve hasta que se publique.')
    return redirect('incident_detail', pk=incident.pk)


# --- Portal del cliente (proyección explícita, invariante 3) -----------------------------------

PORTAL_KINDS = {'repeated': 'Varios intentos fallidos', 'lockout': 'Cuenta bloqueada por intentos fallidos',
                'success': 'Acceso correcto después de varios intentos fallidos'}
PORTAL_DAYS = 30


def customer_rows(client, now=None):
    """Lo que ve el cliente: equipo, sede, qué pasó, cuántos intentos y si vino de Internet. La IP solo si es pública;
    nunca el usuario ni la IP interna."""
    now = now or timezone.now()
    rows = []
    for row in (EndpointAccessAlert.objects.filter(client_scope_id=client.pk, kind__in=VISIBLE,
                                                   last_at__gte=now - timedelta(days=PORTAL_DAYS))
                .select_related('agent__site').order_by('-last_at')[:100]):
        agent = row.agent  # un agente no cambia de cliente: retirarlo y volver a asignarlo crea otro registro
        rows.append({'last_at': row.last_at, 'device': agent.name, 'site': agent.site.name if agent.site else '',
                     'what': PORTAL_KINDS[row.kind],
                     'attempts': attempts_label(row), 'kind': row.kind,
                     'origin': 'Internet' if row.source_public else 'Red interna' if row.source_ip else 'Sin origen registrado',
                     'public_ip': row.source_ip if row.source_public else '',
                     'state': 'Revisado por el SOC' if row.review != 'pending' else 'El SOC lo revisa',
                     'urgent': row.urgent})
    return rows


# --- Recuperación desde el indexador -----------------------------------------------------------

def recovery_filter():
    """Eventos que recupera `endpoints.reconcile` (flujo «access»). Los accesos correctos sueltos no se recuperan
    (son demasiados); sí la correlación 40112 de Wazuh."""
    return {'bool': {'should': [
        {'terms': {'rule.groups': [FAILED_GROUP, CORRELATED_GROUP]}},
        {'terms': {'rule.id': sorted(SUCCESS_AFTER_RULES | LOCKOUT_RULES)}},
        {'bool': {'filter': [{'term': {'data.win.system.channel': SECURITY_CHANNEL}},
                             {'terms': {'data.win.system.eventID': sorted(WIN_FAILED | WIN_LOCKOUT)}}]}}],
        'minimum_should_match': 1}}

"""Antivirus de los equipos de los clientes vía agente Wazuh (Microsoft Defender).

- Entrada: los eventos de agentes que no son de un firewall llegan por la misma lectura de `alerts.json`
  (`operations.ingest_events`). Un agente desconocido queda «sin asignar»; el SOC lo asigna a un cliente y
  solo desde entonces se le atribuyen eventos (invariante 2).
- Defender (canal «Microsoft-Windows-Windows Defender/Operational», reglas oficiales de Wazuh 62100-62599 y
  la propia `deploy/wazuh/soc_defender_rules.xml` para el informe de salud 1151):
  - 1116/1006: detección; 1117/1007: acción tomada; 1118/1119/1008: no pudo actuar. Se unen por el
    identificador de detección. Sin acción confirmada queda «detectada» (invariante 4).
  - 1151: informe de salud (protección en tiempo real, antigüedad de las firmas, último análisis rápido).
  - 5000/5001: protección en tiempo real activada/desactivada; 5010/5012: análisis desactivado;
    2001/2003/2004: fallo al actualizar firmas o motor.
- Estado por equipo: protegido, sin protección en tiempo real, firmas antiguas, sin informar o sin datos
  del antivirus. Las detecciones se revisan («Revisada» o «Abrir incidencia») en «Antivirus de equipos» y en
  la bandeja de trabajo.
- Aviso urgente al cliente (correo, Teams o Telegram, como los de los firewalls) cuando una detección queda
  «permitida» o «no pudo actuar», si tiene los avisos urgentes activos. Lleva equipo, sede, hora, amenaza,
  gravedad y resultado; nunca la ruta del archivo ni el usuario, que son datos internos (invariante 3).
"""
import hashlib
import ipaddress
import re
from datetime import timedelta

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.db.models import Count, Q
from django.http import HttpResponseForbidden
from django.shortcuts import redirect, render
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_http_methods

from .models import Client, EndpointAgent, EndpointDetection, Incident, IncidentUpdate, Site
from .security import audit

CHANNEL = 'Microsoft-Windows-Windows Defender/Operational'
DETECTED = {'1116', '1006', '1015'}
ACTED = {'1117', '1007'}
FAILED = {'1118', '1119', '1008'}
HEALTH = '1151'
RTP_ON, RTP_OFF = '5000', '5001'
SCAN_OFF = {'5010', '5012'}
UPDATE_FAILED = {'2001', '2003', '2004'}
CONTAINING = ('quarantine', 'remove', 'clean', 'block', 'cuarentena', 'quitar', 'eliminar', 'limpiar', 'bloquear')
ALLOWING = ('allow', 'permitir')
SILENT_AFTER = timedelta(hours=72)  # un PC apagado el fin de semana no es una alarma
HEALTH_STALE = timedelta(hours=72)
SIGNATURE_MAX_DAYS = 3
UPDATE_FAILED_WINDOW = timedelta(days=2)
STATES = {'protected': 'Protegido', 'unprotected': 'Sin protección en tiempo real', 'outdated': 'Firmas antiguas',
          'silent': 'Sin informar', 'unknown': 'Sin datos del antivirus'}


def _key(name):
    return re.sub(r'[^a-z0-9]', '', str(name).lower())


def _fields(eventdata):
    """Campos de Defender por nombre normalizado: Wazuh los convierte («Threat Name» → threatName)."""
    return {_key(k): str(v) for k, v in (eventdata.items() if isinstance(eventdata, dict) else ()) if v is not None}


def _clean(value, size):
    return re.sub(r'[\x00-\x1f\x7f]+', ' ', str(value or '')).strip()[:size]


def _number(value):
    match = re.match(r'\s*(\d{1,6})', str(value or ''))
    return int(match.group(1)) if match else None


def defender_event(source):
    """(id de evento, campos) si el evento es del canal de Defender; si no, None."""
    data = source.get('data') if isinstance(source.get('data'), dict) else {}
    win = data.get('win') if isinstance(data.get('win'), dict) else {}
    system = win.get('system') if isinstance(win.get('system'), dict) else {}
    if str(system.get('channel') or '') != CHANNEL:
        return None
    return str(system.get('eventID') or ''), _fields(win.get('eventdata'))


def agent_of(source):
    agent = source.get('agent') if isinstance(source.get('agent'), dict) else {}
    agent_id = str(agent.get('id') or '')
    if not re.fullmatch(r'\d{1,10}', agent_id) or agent_id == '000':
        return None
    try:
        address = str(ipaddress.ip_address(str(agent.get('ip') or '')))
    except ValueError:
        address = None
    return agent_id, _clean(agent.get('name') or ('agente ' + agent_id), 120), address


def current(agent_id):
    return EndpointAgent._base_manager.filter(agent_id=agent_id, retired_at__isnull=True).first()


def observe(source, stamp, now, cache):
    """Llamada por `ingest_events` para un evento de agente sin firewall. Devuelve True si lo ha usado.

    `cache` evita escribir «visto por última vez» en cada evento del mismo agente dentro de un lote.
    """
    found = agent_of(source)
    if not found:
        return False
    agent_id, name, address = found
    endpoint = cache.get(agent_id)
    if endpoint is None:
        endpoint = current(agent_id)
        if endpoint is None:
            endpoint = EndpointAgent._base_manager.create(agent_id=agent_id, name=name, ip=address, first_seen_at=stamp,
                                                          last_seen_at=stamp)
        cache[agent_id] = endpoint
    if stamp > endpoint.last_seen_at:
        EndpointAgent._base_manager.filter(pk=endpoint.pk).update(last_seen_at=stamp, name=name, ip=address)
        endpoint.last_seen_at = stamp
    event = defender_event(source)
    # Sin asignar o anterior a la asignación: no se atribuye a ningún cliente (invariante 2).
    if event is None or endpoint.status != 'assigned' or not endpoint.assigned_at or stamp < endpoint.assigned_at:
        return True
    _defender(endpoint, event[0], event[1], stamp, now, source)
    return True


def _queue_urgent(endpoint, row, level, now):
    """Aviso urgente para una detección permitida o que el antivirus no pudo contener (como mucho uno por detección)."""
    import json
    from django.core.exceptions import ValidationError
    from django.core.validators import validate_email
    from .models import UrgentAlert
    from .urgent_alerts import MAX_AGE
    client = endpoint.client
    if client is None or not client.active or not client.urgent_alerts_enabled:
        return
    recipient = client.urgent_email or client.report_email
    try:
        validate_email(recipient)
    except ValidationError:
        return
    uid = hashlib.sha256(f'endpoint\x00{endpoint.pk}\x00{row.detection_key}'.encode()).hexdigest()
    fingerprint = hashlib.sha256(json.dumps([client.pk, 'endpoint', endpoint.agent_id, row.threat, row.action],
                                            ensure_ascii=False).encode()).hexdigest()
    UrgentAlert._base_manager.get_or_create(event_uid=uid, defaults={
        'client': client, 'fingerprint': fingerprint, 'kind': UrgentAlert.Kind.ENDPOINT_MALWARE,
        'status': UrgentAlert.Status.EXPIRED if now - row.observed_at > MAX_AGE else UrgentAlert.Status.PENDING,
        'observed_at': row.observed_at, 'source_ip': endpoint.ip, 'site_name': _clean(endpoint.site.name if endpoint.site else '', 160),
        'asset_name': _clean(endpoint.name, 160), 'signature': _clean(row.threat, 240), 'action': row.action,
        'rule_level': max(0, min(level, 65535)), 'recipient': recipient,
        # Solo lo que puede ver el cliente: sin ruta, proceso ni usuario.
        'interpretation': {'engine': 'defender', 'event_family': 'malware', 'soc_priority': 'critical',
                           'priority_label': 'Crítica', 'vendor_severity': _clean(row.severity, 40),
                           'category': _clean(row.category, 80)}})


def _defender(endpoint, event_id, fields, stamp, now, source):
    manager = EndpointAgent._base_manager.filter(pk=endpoint.pk)
    updates = {'defender_seen_at': stamp} if not endpoint.defender_seen_at or stamp > endpoint.defender_seen_at else {}
    if event_id == HEALTH and (not endpoint.health_at or stamp >= endpoint.health_at):
        rtp = fields.get('rtpstate', '').strip().lower()
        updates.update(health_at=stamp, signature_age_days=_number(fields.get('avsignatureage')),
                       quick_scan_age_days=_number(fields.get('lastquickscanage')),
                       signature_version=_clean(fields.get('avsignatureversion'), 40))
        if rtp in ('enabled', 'disabled', 'habilitado', 'deshabilitado'):
            updates.update(realtime_enabled=rtp in ('enabled', 'habilitado'), realtime_changed_at=stamp)
    elif event_id in (RTP_ON, RTP_OFF) and (not endpoint.realtime_changed_at or stamp >= endpoint.realtime_changed_at):
        updates.update(realtime_enabled=event_id == RTP_ON, realtime_changed_at=stamp)
        if event_id == RTP_ON:
            updates['scanning_disabled_at'] = None
    elif event_id in SCAN_OFF:
        # Un evento antiguo que llega tarde (recuperación) no pisa una reactivación posterior.
        if (not endpoint.realtime_changed_at or stamp >= endpoint.realtime_changed_at) and (
                not endpoint.scanning_disabled_at or stamp > endpoint.scanning_disabled_at):
            updates['scanning_disabled_at'] = stamp
    elif event_id in UPDATE_FAILED:
        if not endpoint.update_failed_at or stamp > endpoint.update_failed_at:
            updates['update_failed_at'] = stamp
    elif event_id in DETECTED | ACTED | FAILED:
        _detection(endpoint, event_id, fields, stamp, now, source)
    if updates:
        manager.update(**updates)
        for field, value in updates.items():
            setattr(endpoint, field, value)


def _detection(endpoint, event_id, fields, stamp, now, source):
    threat = _clean(fields.get('threatname'), 200) or 'Amenaza sin nombre'
    key = _clean(fields.get('detectionid'), 80).strip('{}').lower()
    if not key:  # sin identificador: amenaza + ruta + minuto, para que una repetición no duplique
        raw = f'{threat}|{fields.get("path", "")}|{stamp:%Y%m%d%H%M}|{source.get("id", "")}'
        key = 'h' + hashlib.sha256(raw.encode()).hexdigest()[:40]
    action_name = _clean(fields.get('actionname'), 80)
    if event_id in FAILED:
        action = 'failed'
    elif event_id in ACTED:
        lowered = action_name.lower()
        action = ('contained' if any(word in lowered for word in CONTAINING)
                  else 'allowed' if any(word in lowered for word in ALLOWING) else 'detected')
    else:
        action = 'detected'
    defaults = {'client_scope_id': endpoint.client_id, 'observed_at': stamp, 'updated_at': now, 'threat': threat,
                'severity': _clean(fields.get('severityname'), 40), 'category': _clean(fields.get('categoryname'), 80),
                'action': action, 'action_name': action_name, 'path': _clean(fields.get('path'), 400),
                'process': _clean(fields.get('processname'), 260), 'user': _clean(fields.get('detectionuser'), 120)}
    level = _number((source.get('rule') or {}).get('level') if isinstance(source.get('rule'), dict) else 0) or 0
    row, created = EndpointDetection._base_manager.get_or_create(agent=endpoint, detection_key=key, defaults=defaults)
    if created:
        if row.urgent:
            _queue_urgent(endpoint, row, level, now)
        return
    # Mismo identificador: la acción posterior completa la detección. Un fallo o un «permitido» no se rebaja.
    rank = {'detected': 0, 'contained': 1, 'allowed': 2, 'failed': 3}
    changes = {'updated_at': now}
    if rank[action] > rank[row.action] or (row.action == 'detected' and action != 'detected'):
        changes.update(action=action, action_name=action_name or row.action_name)
        if row.review == 'reviewed' and action in ('allowed', 'failed'):
            changes['review'] = 'pending'  # empeora: vuelve a la cola
    for field in ('severity', 'category', 'path', 'process', 'user'):
        if not getattr(row, field) and defaults[field]:
            changes[field] = defaults[field]
    if stamp < row.observed_at:
        changes['observed_at'] = stamp
    EndpointDetection._base_manager.filter(pk=row.pk).update(**changes)
    if changes.get('action') in ('allowed', 'failed'):
        row.action = changes['action']
        _queue_urgent(endpoint, row, level, now)


def state(endpoint, now=None):
    """(código, texto) del estado del antivirus de un equipo asignado."""
    now = now or timezone.now()
    if not endpoint.defender_seen_at:
        if now - endpoint.last_seen_at > SILENT_AFTER:
            return 'silent', STATES['silent']
        return 'unknown', STATES['unknown']
    if now - endpoint.last_seen_at > SILENT_AFTER:
        return 'silent', STATES['silent']
    if endpoint.realtime_enabled is False or endpoint.scanning_disabled_at:
        return 'unprotected', STATES['unprotected']
    if (endpoint.signature_age_days is not None and endpoint.signature_age_days > SIGNATURE_MAX_DAYS) or (
            endpoint.update_failed_at and now - endpoint.update_failed_at < UPDATE_FAILED_WINDOW):
        return 'outdated', STATES['outdated']
    if not endpoint.health_at or now - endpoint.health_at > HEALTH_STALE:
        return 'unknown', 'Sin informe de salud reciente'
    return 'protected', STATES['protected']


def client_summary(client, now=None):
    """Para la ficha del cliente: equipos asignados por estado y detecciones por revisar."""
    now = now or timezone.now()
    rows = list(EndpointAgent.objects.filter(client=client, status='assigned'))
    counts = {}
    for row in rows:
        code = state(row, now)[0]
        counts[code] = counts.get(code, 0) + 1
    pending = EndpointDetection.objects.filter(client_scope_id=client.pk, review='pending').count()
    return {'total': len(rows), 'protected': counts.get('protected', 0),
            'attention': len(rows) - counts.get('protected', 0), 'detections': pending}


def review_queue(client_id=None):
    rows = EndpointDetection.objects.filter(review='pending').select_related('agent__client')
    if client_id:
        rows = rows.filter(client_scope_id=client_id)
    return sorted(rows[:200], key=lambda d: (not d.urgent, -d.observed_at.timestamp()))


def _global(user):
    from .blocklist import global_access
    return global_access(user)


@login_required
@never_cache
@require_http_methods(['GET', 'POST'])
def overview(request):
    if not request.user.has_perm('core.manage_operations'):
        return HttpResponseForbidden('Permiso de operaciones requerido.')
    now = timezone.now()
    if request.method == 'POST':
        response = _action(request, now)
        if response is not None:
            return response
        return redirect(request.get_full_path())
    selected = request.GET.get('client', '')
    agents = EndpointAgent.objects.filter(status='assigned').select_related('client', 'site')
    detections = EndpointDetection.objects.select_related('agent', 'incident').order_by('review', '-observed_at')
    if selected.isdigit():
        agents = agents.filter(client_id=int(selected))
        detections = detections.filter(client_scope_id=int(selected))
    agents = list(agents)
    for row in agents:
        row.state_code, row.state_label = state(row, now)
    agents.sort(key=lambda r: (r.state_code == 'protected', r.client.name if r.client else '', r.name))
    clients = {c.pk: c for c in Client.objects.all()}
    detections = list(detections[:200])
    for row in detections:
        row.client = clients.get(row.client_scope_id)
    pending_agents = (list(EndpointAgent._base_manager.filter(status='pending').order_by('-last_seen_at')[:300])
                      if _global(request.user) else [])
    state_counts = [(code, label, sum(1 for r in agents if r.state_code == code)) for code, label in STATES.items()]
    return render(request, 'endpoints.html', {
        'agents': agents, 'detections': detections, 'pending_agents': pending_agents, 'state_counts': state_counts,
        'clients': Client.objects.filter(active=True), 'selected_client': selected, 'can_assign': _global(request.user),
        'sites': Site.objects.filter(active=True).select_related('client'), 'silent_hours': int(SILENT_AFTER.total_seconds() // 3600),
        'can_open_incident': request.user.has_perm('core.add_incident')})


def _action(request, now):
    action = request.POST.get('action', '')
    if action in ('assign', 'retire'):
        if not _global(request.user) or not request.user.has_perm('core.manage_connections'):
            return HttpResponseForbidden('Asignar equipos a clientes requiere acceso global y permiso de conexiones.')
        ids = [int(v) for v in request.POST.getlist('agent') if v.isdigit()][:300]
        if action == 'assign':
            client = Client.objects.filter(pk=request.POST.get('client') or 0, active=True).first()
            site = Site.objects.filter(pk=request.POST.get('site') or 0, client=client).first() if client else None
            if not client or not ids:
                messages.error(request, 'Elige los agentes y el cliente.')
                return None
            with transaction.atomic():
                count = EndpointAgent._base_manager.filter(pk__in=ids, status='pending', retired_at__isnull=True).update(
                    status='assigned', client=client, site=site, assigned_at=now, assigned_by=request.user)
                audit('endpoint.assigned', client, {'count': count})
            messages.success(request, f'{count} agente{"s" if count != 1 else ""} asignado{"s" if count != 1 else ""} a {client.name}. '
                                      'Sus eventos cuentan desde ahora.')
        else:
            with transaction.atomic():
                rows = EndpointAgent.objects.filter(pk__in=ids, retired_at__isnull=True)
                count = rows.update(status='retired', retired_at=now)
                audit('endpoint.retired', None, {'count': count})
            messages.success(request, f'{count} agente{"s" if count != 1 else ""} retirado{"s" if count != 1 else ""}.')
        return None
    if action in ('reviewed', 'incident'):
        pk = request.POST.get('detection', '')
        row = EndpointDetection.objects.filter(pk=int(pk) if pk.isdigit() else 0).select_related('agent__site').first()
        if row is None:
            messages.error(request, 'Esa detección ya no existe o no está en tu ámbito.')
            return None
        if action == 'reviewed':
            EndpointDetection.objects.filter(pk=row.pk).update(review='reviewed', reviewed_by=request.user, reviewed_at=now)
            audit('endpoint.detection_reviewed', row.agent, {'status': 'reviewed'})
            messages.success(request, 'Detección marcada como revisada. Volverá a la cola si empeora (permitida o sin poder actuar).')
            return None
        if not request.user.has_perm('core.add_incident'):
            return HttpResponseForbidden('Tu cuenta no puede abrir incidencias.')
        if row.incident_id:
            return redirect('incident_detail', pk=row.incident_id)
        client = Client.objects.filter(pk=row.client_scope_id).first()
        if client is None:
            return HttpResponseForbidden('Cliente no disponible.')
        lines = [f'Microsoft Defender detectó «{row.threat}» en el equipo {row.agent.name} (agente Wazuh {row.agent.agent_id}).',
                 f'Gravedad: {row.severity or "sin indicar"} · categoría: {row.category or "sin indicar"} · '
                 f'resultado: {row.get_action_display().lower()}' + (f' ({row.action_name})' if row.action_name else '') + '.',
                 f'Ruta: {row.path or "sin indicar"} · proceso: {row.process or "sin indicar"} · usuario: {row.user or "sin indicar"}.',
                 'Una detección contenida no descarta una ejecución previa; una sin acción no prueba compromiso. Revisar el equipo.']
        with transaction.atomic():
            incident = Incident.objects.create(
                client=client, site=row.agent.site, title=f'Malware en {row.agent.name}: {row.threat}'[:220],
                description='\n\n'.join(lines), observed_at=row.observed_at, owner=request.user,
                severity='critical' if row.action in ('allowed', 'failed') else 'high')
            IncidentUpdate.objects.create(incident=incident, author=request.user, text='Abierta desde «Antivirus de equipos».')
            EndpointDetection.objects.filter(pk=row.pk).update(review='incident', incident=incident, reviewed_by=request.user,
                                                               reviewed_at=now)
            audit('endpoint.detection_incident', row.agent, {'incident_id': incident.pk})
        messages.success(request, 'Incidencia interna abierta. El cliente no la ve hasta que se publique.')
        return redirect('incident_detail', pk=incident.pk)
    return HttpResponseForbidden('Acción no válida.')


def badge():
    """(por revisar, urgente) para el menú."""
    rows = EndpointDetection.objects.filter(review='pending').aggregate(
        total=Count('id'), urgent=Count('id', filter=Q(action__in=('allowed', 'failed'))))
    return rows['total'] or 0, bool(rows['urgent'])


# --- Portal del cliente (proyección explícita, invariante 3) ------------------------------------

PORTAL_STATES = {
    'protected': ('Protegido', 'ok'),
    'unprotected': ('Protección en tiempo real desactivada', 'attention'),
    'outdated': ('Antivirus sin actualizar', 'attention'),
    'silent': ('Sin noticias del equipo', 'pending'),
    'unknown': ('Pendiente de datos del antivirus', 'pending'),
}
PORTAL_RESULTS = {'detected': 'Detectada; el SOC la revisa', 'contained': 'Contenida por el antivirus',
                  'allowed': 'Permitida en el equipo', 'failed': 'El antivirus no pudo actuar'}
PORTAL_DAYS = 90


def _portal_devices(client, now):
    rows = []
    for agent in EndpointAgent.objects.filter(client=client, status='assigned').select_related('site').order_by('name'):
        code = state(agent, now)[0]
        label, tone = PORTAL_STATES[code]
        rows.append({'name': agent.name, 'site': agent.site.name if agent.site else '', 'state': label, 'tone': tone,
                     'code': code, 'signature_age_days': agent.signature_age_days, 'health_at': agent.health_at,
                     'last_seen_at': agent.last_seen_at})
    rows.sort(key=lambda r: (r['code'] == 'protected', r['name']))
    return rows


def portal_summary(client, now=None):
    """Para el inicio del portal: equipos, protegidos, que necesitan revisión y detecciones recientes."""
    now = now or timezone.now()
    devices = _portal_devices(client, now)
    recent = EndpointDetection.objects.filter(client_scope_id=client.pk, observed_at__gte=now - timedelta(days=30)).count()
    protected = sum(1 for d in devices if d['code'] == 'protected')
    attention = sum(1 for d in devices if d['code'] in ('unprotected', 'outdated'))
    return {'total': len(devices), 'protected': protected, 'attention': attention, 'recent_detections': recent}


def customer_context(client, preview=False, now=None):
    """Lo que ve el cliente: sin identificador de agente, IP, ruta, proceso ni usuario."""
    from .service_development import _portal_base
    now = now or timezone.now()
    devices = _portal_devices(client, now)
    names = {a.pk: (a.name, a.site.name if a.site else '') for a in
             EndpointAgent.objects.filter(client=client).select_related('site')}
    detections = []
    for row in EndpointDetection.objects.filter(client_scope_id=client.pk, observed_at__gte=now - timedelta(days=PORTAL_DAYS)
                                                ).order_by('-observed_at')[:200]:
        name, site = names.get(row.agent_id, ('Equipo retirado', ''))
        detections.append({'observed_at': row.observed_at, 'device': name, 'site': site, 'threat': row.threat,
                           'severity': row.severity, 'result': PORTAL_RESULTS[row.action], 'urgent': row.urgent})
    return {**_portal_base(client, preview, 'endpoints'), 'devices': devices, 'detections': detections,
            'summary': portal_summary(client, now), 'portal_days': PORTAL_DAYS}


@login_required
@never_cache
def customer_view(request):
    from django.http import Http404
    from .service_development import customer_client
    client = customer_client(request)
    if not client.customer_endpoints_enabled:
        raise Http404
    return render(request, 'customer_endpoints.html', customer_context(client))



# --- Recuperación desde el indexador -----------------------------------------------------------

RECONCILE_STATE = 'endpoint-reconciliation'
RECONCILE_ISSUE = 'platform:endpoint-reconciliation'
USEFUL_EVENTS = sorted(DETECTED | ACTED | FAILED | SCAN_OFF | UPDATE_FAILED | {HEALTH, RTP_ON, RTP_OFF})


def reconcile(now=None, pages=3, page_size=200, initial_days=1):
    """Trabajo `endpoint_reconciliation`: recupera del indexador los eventos de Defender que no llegaron por
    `alerts.json` (rotación, parada del lector). Ventana fija con 10 minutos de solape y cursor propio.

    Invariante 5: con una respuesta incompleta del indexador no se avanza el cursor. Volver a procesar un
    evento ya visto no duplica nada (detecciones por identificador, estado por fecha, avisos por detección;
    un aviso de algo antiguo queda caducado sin enviarse).
    """
    import json
    from django.db.models import F
    from django.utils.dateparse import parse_datetime
    from .indexer_results import complete
    from .models import Device, OperationalIssue, WorkerState
    from .operations import set_issue
    from .reporting import _search, indexer_authorization
    now = now or timezone.now()
    state, _ = WorkerState.objects.get_or_create(name=RECONCILE_STATE)
    state.last_run_at = now
    state.save(update_fields=['last_run_at'])
    details = dict(state.details)
    if not details.get('end'):
        previous = parse_datetime(details.get('completed_until', ''))
        start = (previous - timedelta(minutes=10)) if previous else now - timedelta(days=initial_days)
        start = max(start, now - timedelta(days=90))
        details = {'start': start.isoformat(), 'end': (now - timedelta(minutes=1)).isoformat()}
    firewall_agents = set(Device.objects.filter(log_method='wazuh_agent').exclude(wazuh_identifier='')
                          .values_list('wazuh_identifier', flat=True))
    recovered = 0
    try:
        authorization = indexer_authorization()
        for _ in range(pages):
            body = {'size': page_size, 'track_total_hits': False,
                    'query': {'bool': {'filter': [
                        {'term': {'data.win.system.channel': CHANNEL}},
                        {'terms': {'data.win.system.eventID': USEFUL_EVENTS}},
                        {'range': {'timestamp': {'gte': details['start'], 'lt': details['end']}}}],
                        'must_not': [{'term': {'agent.id': '000'}}]}},
                    'sort': [{'timestamp': 'asc'}, {'id': {'order': 'asc', 'unmapped_type': 'keyword'}}, {'_index': 'asc'}],
                    '_source': ['id', 'timestamp', 'agent', 'rule', 'data']}
            if details.get('after'):
                body['search_after'] = details['after']
            result = complete(_search(body, authorization))
            hits = result.get('hits', {}).get('hits')
            if not isinstance(hits, list) or any(not isinstance(h, dict) or not isinstance(h.get('_source'), dict) for h in hits):
                raise ValueError('Respuesta del indexador incompleta.')
            if hits and (not all(h['_source'].get('id') for h in hits) or len(hits[-1].get('sort') or []) != 3):
                raise ValueError('Falta una identidad estable para reanudar.')
            with transaction.atomic():
                WorkerState.objects.filter(pk=state.pk).update(offset=F('offset'))  # reserva el escritor (SQLite)
                cache = {}
                for hit in hits:
                    source = hit['_source']
                    agent = source.get('agent') if isinstance(source.get('agent'), dict) else {}
                    if str(agent.get('id') or '') in firewall_agents:
                        continue  # agente de un firewall: lo trata la recuperación de los firewalls
                    stamp = parse_datetime(str(source.get('timestamp') or ''))
                    if stamp is None or timezone.is_naive(stamp) or stamp > now + timedelta(minutes=5):
                        continue
                    recovered += int(observe(source, stamp, now, cache))
                if len(hits) < page_size:
                    details = {'completed_until': details['end']}
                    state.last_success_at = now
                else:
                    details['after'] = hits[-1]['sort']
                state.details = json.loads(json.dumps(details))
                state.error = ''
                state.save()
            if 'completed_until' in details:
                break
        OperationalIssue.objects.filter(key=RECONCILE_ISSUE, active=True).update(active=False, resolved_at=now)
    except Exception:
        state.error = 'No terminó la recuperación de los eventos del antivirus. Revisar el acceso al indexador; el cursor se conserva.'
        state.save(update_fields=['error'])
        set_issue(RECONCILE_ISSUE, 'Recuperación del antivirus de equipos pendiente', details=state.error, now=now)
    return recovered

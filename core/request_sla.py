"""Plazos de respuesta de las solicitudes de clientes.

Dos objetivos por solicitud, distintos para las urgentes: **primera respuesta** del SOC y **resolución**.
Se configuran en «Plazos de atención» y se activan aparte de los de las incidencias.

- Solo cuentan las solicitudes abiertas desde la activación: activar no convierte en vencidas las anteriores.
- El tiempo en «Esperando vuestra respuesta» no cuenta para la resolución (`waiting_since`/`waited_seconds`).
- Con el horario laboral activado (`business_hours`), las solicitudes normales solo cuentan dentro de la
  jornada; las urgentes siguen en tiempo natural salvo que se marque lo contrario.
- Un plazo vencido se registra una sola vez: nota interna en la solicitud, auditoría y aviso operativo
  (`request-sla:<id>:<plazo>`), crítico si la solicitud es urgente. El aviso se retira al cumplirse.
"""
from datetime import timedelta

from django.utils import timezone

from .models import CustomerRequest, CustomerRequestEntry, OperationalIssue, SlaSettings
from .sla import DUE_SOON, STATE_LABELS, duration

PREFIX = 'request-sla:'
MILESTONES = (('response', 'Primera respuesta'), ('resolve', 'Resolución'))


def config():
    return SlaSettings.objects.filter(pk=1).first()


def applies(request_obj, settings_row):
    return bool(settings_row and settings_row.requests_enabled and settings_row.requests_enabled_at
                and request_obj.created_at >= settings_row.requests_enabled_at)


def targets(request_obj, settings_row):
    if request_obj.urgent or request_obj.kind == 'incident':
        return {'response': settings_row.request_urgent_response_minutes, 'resolve': settings_row.request_urgent_resolve_minutes}
    return {'response': settings_row.request_response_minutes, 'resolve': settings_row.request_resolve_minutes}


def calendar_for_request(request_obj, settings_row):
    """Calendario laboral que aplica a la solicitud, o None si su plazo corre en tiempo natural."""
    from .business_hours import calendar_for
    urgent = request_obj.urgent or request_obj.kind == 'incident'
    if urgent and not (settings_row and settings_row.business_urgent_requests):
        return None
    return calendar_for(settings_row)


def waited(request_obj, now):
    """Tiempo total esperando al cliente, incluida la espera en curso."""
    total = timedelta(seconds=request_obj.waited_seconds)
    if request_obj.waiting_since:
        total += max(timedelta(0), now - request_obj.waiting_since)
    return total


def waited_work(request_obj, now, calendar):
    """La misma espera en minutos de jornada (para los plazos con horario laboral)."""
    total = request_obj.waited_work_minutes
    if request_obj.waiting_since:
        total += calendar.between(request_obj.waiting_since, now)
    return total


def transition_fields(request_obj, new_status, now):
    """Campos de espera que cambian al pasar a `new_status` (para un `update`)."""
    fields = {}
    if new_status == 'waiting' and not request_obj.waiting_since:
        fields['waiting_since'] = now
    elif new_status != 'waiting' and request_obj.waiting_since:
        fields['waited_seconds'] = request_obj.waited_seconds + max(0, int((now - request_obj.waiting_since).total_seconds()))
        # Se guarda también en minutos de jornada, con el calendario vigente al terminar la espera.
        from .business_hours import calendar_for
        calendar = calendar_for(config())
        if calendar:
            fields['waited_work_minutes'] = request_obj.waited_work_minutes + calendar.between(request_obj.waiting_since, now)
        fields['waiting_since'] = None
    return fields


def evaluate(request_obj, now=None, settings_row=None):
    """Lista de plazos {'key','label','target_label','deadline','state','state_label','done_at'}; vacía si no aplican."""
    now = now or timezone.now()
    settings_row = settings_row or config()
    if not applies(request_obj, settings_row):
        return []
    goal = targets(request_obj, settings_row)
    from . import business_hours
    calendar = calendar_for_request(request_obj, settings_row)
    rows = []
    for key, label in MILESTONES:
        minutes = goal[key]
        paused = False
        if key == 'response':
            done, deadline = request_obj.first_response_at, business_hours.deadline(calendar, request_obj.created_at, minutes)
        else:
            done = request_obj.resolved_at if request_obj.status == 'resolved' else None
            if calendar:
                deadline = calendar.add(request_obj.created_at, minutes + waited_work(request_obj, now, calendar))
            else:
                deadline = request_obj.created_at + timedelta(minutes=minutes) + waited(request_obj, now)
            paused = request_obj.status == 'waiting'
        if done:
            state = 'met' if done <= deadline else 'late'
        elif paused:
            state = 'paused'
        elif now > deadline:
            state = 'breached'
        elif business_hours.remaining_minutes(calendar, now, deadline) <= minutes * DUE_SOON:
            state = 'soon'
        else:
            state = 'running'
        rows.append({'key': key, 'label': label, 'target_label': duration(minutes), 'deadline': deadline, 'done_at': done, 'state': state,
                     'state_label': 'En pausa: esperando al cliente' if paused and not done else 'Vence pronto' if state == 'soon' else STATE_LABELS.get(state, 'En plazo')})
    return rows


def next_due(rows):
    """El plazo abierto más urgente (vencido primero), o None."""
    open_rows = [r for r in rows if r['state'] in ('breached', 'soon', 'running')]
    return min(open_rows, key=lambda r: (r['state'] != 'breached', r['deadline'])) if open_rows else None


def annotate(requests, now=None):
    """Añade `sla_rows` y `sla_next` a cada solicitud (una sola lectura de la configuración)."""
    now = now or timezone.now()
    settings_row = config()
    for request_obj in requests:
        request_obj.sla_rows = evaluate(request_obj, now, settings_row)
        request_obj.sla_next = next_due(request_obj.sla_rows)
    return requests


def customer_commitment(request_obj, settings_row=None):
    """Lo que se enseña al cliente, si está activado: hasta cuándo llegará la primera respuesta."""
    settings_row = settings_row or config()
    if not (settings_row and settings_row.requests_visible and applies(request_obj, settings_row)) or request_obj.first_response_at:
        return None
    from .business_hours import deadline
    return deadline(calendar_for_request(request_obj, settings_row), request_obj.created_at, targets(request_obj, settings_row)['response'])


def check(now=None):
    """Registra una sola vez cada plazo vencido y mantiene al día sus avisos. Devuelve cuántos hay vencidos."""
    from .operations import set_issue
    from .security import audit
    now = now or timezone.now()
    settings_row = config()
    active = set(OperationalIssue._base_manager.filter(active=True, key__startswith=PREFIX).values_list('key', flat=True))
    breached = set()
    if settings_row and settings_row.requests_enabled and settings_row.requests_enabled_at:
        rows = (CustomerRequest._base_manager.exclude(status='resolved').filter(created_at__gte=settings_row.requests_enabled_at)
                .select_related('client'))
        for request_obj in rows:
            for row in evaluate(request_obj, now, settings_row):
                if row['state'] != 'breached':
                    continue
                key = f"{PREFIX}{request_obj.pk}:{row['key']}"
                breached.add(key)
                if row['key'] not in request_obj.sla_breaches:
                    request_obj.sla_breaches = {**request_obj.sla_breaches, row['key']: now.isoformat()}
                    CustomerRequest._base_manager.filter(pk=request_obj.pk).update(sla_breaches=request_obj.sla_breaches)
                    CustomerRequestEntry._base_manager.create(
                        request=request_obj, kind='internal', status=request_obj.status, created_at=now,
                        text=f"Plazo de {row['label'].lower()} vencido: el objetivo era {row['target_label']}.")
                    audit('request.sla_breached', request_obj, {'status': row['key']})
                set_issue(key, f"Plazo de {row['label'].lower()} vencido · {request_obj.client.name}: {request_obj.subject[:120]}",
                          now=now, severity='critical' if request_obj.urgent or request_obj.kind == 'incident' else 'warning',
                          details=f"{request_obj.reference}: objetivo de {row['target_label']}, venció el "
                                  f"{timezone.localtime(row['deadline']):%d/%m/%Y %H:%M}. Revisar en «Solicitudes de clientes».")
    stale = active - breached
    if stale:
        OperationalIssue._base_manager.filter(key__in=stale, active=True).update(active=False, resolved_at=now)
    return len(breached)

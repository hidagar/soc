"""Plazos de atención (hoja de ruta 5): acuse, diagnóstico y resolución por gravedad, globales o por cliente.

Hitos, guardados en la incidencia la primera vez que ocurren (`record`):
- acuse: alguien asume el caso, se le asigna responsable o pasa a investigación;
- diagnóstico: primer avance documentado (nota, acción, tarea para el cliente o comprobación de la guía);
- resolución: la incidencia se marca resuelta; si se reabre, vuelve a contar.

El reloj es continuo (24x7) desde que el caso entra en el SOC (`created_at`) y no se detiene mientras se
espera al cliente. Solo cuentan los casos creados después de activar los plazos.

Escalado (`check`, trabajo «Avisos operativos», cada minuto): al vencer un plazo se anota en el
historial del caso y en la auditoría y se abre un aviso en «Salud del SOC»; con gravedad alta o crítica
es crítico y llega también por correo de operaciones.
"""
import re
from datetime import timedelta

from django.utils import timezone

from .models import Incident, IncidentUpdate, OperationalIssue, SlaPolicy, SlaSettings

MILESTONES = (('acknowledge', 'Acuse', 'acknowledged_at'), ('investigate', 'Diagnóstico', 'investigated_at'),
              ('resolve', 'Resolución', 'resolved_at'))
# Minutos (acuse, diagnóstico, resolución) por gravedad mientras no se configuren otros.
DEFAULTS = {'critical': (15, 60, 24 * 60), 'high': (30, 4 * 60, 3 * 24 * 60),
            'medium': (4 * 60, 24 * 60, 7 * 24 * 60), 'low': (24 * 60, 3 * 24 * 60, 30 * 24 * 60)}
DUE_SOON = 0.25  # queda menos de una cuarta parte del plazo
MAX_MINUTES = 90 * 24 * 60
STATE_LABELS = {'met': 'Cumplido', 'late': 'Cumplido fuera de plazo', 'breached': 'Vencido',
                'due_soon': 'Vence pronto', 'pending': 'En plazo'}


def config():
    return SlaSettings.objects.filter(pk=1).first()


def policies():
    """{(cliente o None, gravedad): (acuse, diagnóstico, resolución)} con los valores por defecto debajo."""
    table = {(None, severity): values for severity, values in DEFAULTS.items()}
    for row in SlaPolicy.objects.all():
        table[(row.client_id, row.severity)] = (row.acknowledge_minutes, row.investigate_minutes, row.resolve_minutes)
    return table


def targets(incident, table):
    return table.get((incident.client_id, incident.severity)) or table[(None, incident.severity)]


def applies(incident, settings_row):
    return bool(settings_row and settings_row.enabled and settings_row.enabled_at
                and incident.created_at and incident.created_at >= settings_row.enabled_at)


def duration(minutes):
    """15 min · 4 h · 3 d · 1 d 6 h: lo mismo que acepta `parse_duration`."""
    if minutes % 1440 == 0:
        return f'{minutes // 1440} d'
    if minutes % 60 == 0:
        return f'{minutes // 60} h' if minutes < 1440 else f'{minutes // 1440} d {minutes % 1440 // 60} h'
    return f'{minutes} min'


def parse_duration(text):
    """«30 min», «4 h», «3 d», «1 d 6 h» o un número de minutos. ValueError si no se entiende."""
    value = (text or '').strip().lower().replace(',', '.')
    if value.isdigit():
        minutes = int(value)
    else:
        parts = re.findall(r'(\d+)\s*(min|m|h|d)\b', value)
        if not parts or re.sub(r'(\d+)\s*(min|m|h|d)\b', '', value).strip():
            raise ValueError(f'No se entiende «{text[:20]}»: usa por ejemplo 30 min, 4 h o 3 d.')
        minutes = sum(int(n) * {'min': 1, 'm': 1, 'h': 60, 'd': 1440}[unit] for n, unit in parts)
    if not 1 <= minutes <= MAX_MINUTES:
        raise ValueError('Cada plazo debe estar entre 1 minuto y 90 días.')
    return minutes


def evaluate(incident, now=None, table=None, settings_row=None):
    """Estado de cada hito: [{key, label, target, deadline, done_at, state, state_label}]; [] si no aplica."""
    now = now or timezone.now()
    settings_row = settings_row if settings_row is not None else config()
    if not applies(incident, settings_row):
        return []
    table = table or policies()
    rows = []
    for (key, label, field), minutes in zip(MILESTONES, targets(incident, table)):
        start = incident.created_at
        deadline = start + timedelta(minutes=minutes)
        resolved = incident.resolved_at if incident.status == 'resolved' else None
        # Un caso resuelto ha pasado por el acuse y el diagnóstico aunque nadie los registrara antes.
        done = resolved if key == 'resolve' else getattr(incident, field) or resolved
        if done:
            state = 'met' if done <= deadline else 'late'
        elif now > deadline:
            state = 'breached'
        elif deadline - now <= timedelta(minutes=minutes) * DUE_SOON:
            state = 'due_soon'
        else:
            state = 'pending'
        rows.append({'key': key, 'label': label, 'target': minutes, 'target_label': duration(minutes),
                     'deadline': deadline, 'done_at': done, 'state': state, 'state_label': STATE_LABELS[state]})
    return rows


def next_due(rows):
    """El primer hito pendiente (vencido o no), o None."""
    pending = [row for row in rows if row['state'] in ('breached', 'due_soon', 'pending')]
    return min(pending, key=lambda row: row['deadline']) if pending else None


def attention(incidents, now=None):
    """Casos abiertos con algún plazo vencido o a punto de vencer, con su próximo hito."""
    now, table, settings_row = now or timezone.now(), policies(), config()
    if not (settings_row and settings_row.enabled):
        return []
    result = []
    for incident in incidents:
        upcoming = next_due(evaluate(incident, now, table, settings_row))
        if upcoming and upcoming['state'] in ('breached', 'due_soon'):
            incident.sla_next = upcoming
            result.append(incident)
    return result


def record(incident, *milestones, now=None):
    """Primera vez que ocurre un hito. Actualización condicional: dos peticiones a la vez no lo pisan.
    El diagnóstico implica el acuse."""
    now = now or timezone.now()
    fields = {'acknowledge': 'acknowledged_at', 'investigate': 'investigated_at'}
    wanted = set(milestones) | ({'acknowledge'} if 'investigate' in milestones else set())
    for key in ('acknowledge', 'investigate'):
        if key in wanted and getattr(incident, fields[key]) is None:
            if Incident._base_manager.filter(pk=incident.pk, **{fields[key]: None}).update(**{fields[key]: now}):
                setattr(incident, fields[key], now)


def check(now=None):
    """Escalado: registra cada plazo que vence una sola vez y mantiene sus avisos al día."""
    from .operations import set_issue
    from .security import audit
    now = now or timezone.now()
    settings_row = config()
    active = set(OperationalIssue._base_manager.filter(active=True, key__startswith='sla:').values_list('key', flat=True))
    breached = set()
    if settings_row and settings_row.enabled and settings_row.enabled_at:
        table = policies()
        for incident in (Incident._base_manager.exclude(status='resolved').filter(created_at__gte=settings_row.enabled_at)
                         .select_related('client', 'device')):
            for row in evaluate(incident, now, table, settings_row):
                if row['state'] != 'breached':
                    continue
                key = f"sla:{incident.pk}:{row['key']}"
                breached.add(key)
                if row['key'] not in incident.sla_breaches:
                    incident.sla_breaches = {**incident.sla_breaches, row['key']: now.isoformat()}
                    Incident._base_manager.filter(pk=incident.pk).update(sla_breaches=incident.sla_breaches)
                    IncidentUpdate.objects.create(incident=incident, text=f"Plazo de {row['label'].lower()} vencido: el "
                                                  f"objetivo era {row['target_label']} desde la entrada del caso.")
                    audit('incident.sla_breached', incident, {'status': row['key']})
                set_issue(key, f"Plazo de {row['label'].lower()} vencido · {incident.client.name}: {incident.title[:120]}",
                          device=incident.device, now=now,
                          severity='critical' if incident.severity in ('high', 'critical') else 'warning',
                          details=f"Gravedad {incident.get_severity_display().lower()}: objetivo de {row['target_label']}, "
                                  f"venció el {timezone.localtime(row['deadline']):%d/%m/%Y %H:%M}. Revisar en la bandeja de trabajo.")
    stale = active - breached
    if stale:
        OperationalIssue._base_manager.filter(key__in=stale, active=True).update(active=False, resolved_at=now)
    return len(breached)

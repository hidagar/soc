"""Eficacia de las reglas de bloqueo del SOC en los firewalls (listas de bloqueo, fase 2).

Para cada regla «Bloqueo CrowdSec del SOC» activa, el trabajo protegido `blocklist_efficacy`
consulta por API al OPNsense del cliente:
- los contadores de la regla (`filter_util/rule_stats`): paquetes y bytes bloqueados;
- cuántas IPs de la tabla del SOC tiene cargadas el firewall (`alias_util/list`).

Los contadores de pf vuelven a cero al recargar las reglas o reiniciar el equipo: se acumula
por diferencias y un valor menor que el anterior se toma como reinicio. Se habla de paquetes
bloqueados, no de ataques: una conexión rechazada puede ser varios paquetes y un paquete
bloqueado no acredita un ataque (invariante 4). Un fallo de la API deja los datos anteriores
con su error; nunca inventa cero bloqueos.
"""
from datetime import timedelta

from django.db import transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from .models import ChangePlan, WorkerState

PREFIX = 'blocklist-efficacy:'
HISTORY_DAYS = 35


def state_name(plan):
    return f'{PREFIX}{plan.pk}'


def _int(value):
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return None


def rule_counters(stats, uuids):
    """Suma de paquetes y bytes de las reglas del plan en la respuesta de rule_stats. None si no aparecen."""
    table = stats.get('stats') if isinstance(stats, dict) and isinstance(stats.get('stats'), dict) else stats
    if not isinstance(table, dict):
        return None
    packets = size = 0
    found = False
    for uid in uuids:
        row = table.get(uid)
        if isinstance(row, dict) and _int(row.get('packets')) is not None:
            packets += _int(row.get('packets'))
            size += _int(row.get('bytes')) or 0
            found = True
    return (packets, size) if found else None


def loaded_entries(listing):
    """IPs que el firewall tiene cargadas en la tabla del alias. None si la respuesta no lo dice."""
    if not isinstance(listing, dict):
        return None
    total = _int(listing.get('total'))
    if total is not None:
        return total
    rows = listing.get('rows')
    return len(rows) if isinstance(rows, list) else None


def accumulate(details, packets, size, now):
    """Nuevo estado a partir de la lectura anterior: diferencias, reinicios y totales por día."""
    previous_packets = details.get('packets')
    if previous_packets is None:
        delta, size_delta = 0, 0  # primera lectura: el punto de partida, no bloqueos nuevos
    elif packets < previous_packets:
        delta, size_delta = packets, size  # el firewall reinició sus contadores
    else:
        delta, size_delta = packets - previous_packets, max(0, size - details.get('bytes', 0))
    day = timezone.localtime(now).date().isoformat()
    history = dict(details.get('history') or {})
    history[day] = history.get(day, 0) + delta
    cutoff = (timezone.localtime(now).date() - timedelta(days=HISTORY_DAYS)).isoformat()
    history = {d: v for d, v in history.items() if d >= cutoff}
    return {**details, 'packets': packets, 'bytes': size, 'checked_at': now.isoformat(), 'error': '',
            'since': details.get('since') or now.isoformat(),
            'total_packets': details.get('total_packets', 0) + delta,
            'total_bytes': details.get('total_bytes', 0) + size_delta,
            'resets': details.get('resets', 0) + int(previous_packets is not None and packets < previous_packets),
            'history': history}


def measure(plan, now=None):
    """Lee los contadores de una regla activa y guarda su estado. Devuelve True si se midió."""
    from .change_control import api
    now = now or timezone.now()
    state = WorkerState.objects.filter(name=state_name(plan)).first()
    details = dict(state.details) if state else {}
    uuids = [o['uuid'] for o in plan.remote_objects if o.get('kind', 'firewall') == 'firewall']
    alias = next((o['rule'].get('name') for o in plan.remote_objects if o.get('kind') == 'alias'), '')
    counters = loaded = None
    error = ''
    try:
        connection = plan.device.opnsense_api
        counters = rule_counters(api(connection, '/api/firewall/filter_util/rule_stats'), uuids)
        if alias:
            loaded = loaded_entries(api(connection, '/api/firewall/alias_util/list/' + alias))
    except Exception:
        # Nunca el texto del proveedor en el panel: solo un mensaje fijo.
        error = 'No se pudieron leer los contadores del firewall por API.'
    if counters is None:
        details.update(error=error or 'El firewall no informa de los contadores de la regla (¿versión de OPNsense anterior a 23.7?).',
                       error_at=now.isoformat())
        result = False
    else:
        details = accumulate(details, *counters, now)
        details['loaded_entries'] = loaded
        result = True
    with transaction.atomic():
        WorkerState.reserve(state_name(plan))
        WorkerState.objects.filter(name=state_name(plan)).update(details=details)
    return result


def refresh(now=None):
    """Trabajo `blocklist_efficacy`: mide cada regla de bloqueo del SOC activa en un OPNsense por API."""
    from .blocklist import TEMPLATE
    now = now or timezone.now()
    measured = 0
    plans = ChangePlan._base_manager.filter(template=TEMPLATE, status='active', device__vendor='opnsense',
                                            device__management_method='api', device__active=True).select_related('device')
    for plan in plans:
        measured += int(measure(plan, now))
    return measured


def summary(plan, now=None):
    """Datos para el panel del SOC: últimas 24 h (aprox., día actual y anterior), 7 días y desde la medición."""
    now = now or timezone.now()
    state = WorkerState.objects.filter(name=state_name(plan)).first()
    if not state or not state.details:
        return None
    details = state.details
    today = timezone.localtime(now).date()
    history = details.get('history') or {}

    def days(n):
        return sum(v for d, v in history.items() if d >= (today - timedelta(days=n - 1)).isoformat())
    return {'today': history.get(today.isoformat(), 0), 'week': days(7), 'month': days(30),
            'total': details.get('total_packets', 0), 'since': parse_datetime(details.get('since') or ''),
            'checked_at': parse_datetime(details.get('checked_at') or ''), 'loaded': details.get('loaded_entries'),
            'error': details.get('error', ''), 'resets': details.get('resets', 0)}

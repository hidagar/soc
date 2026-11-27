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
DNS_TOP = 5000  # dominios bloqueados que se piden a Unbound; más allá, la cifra se queda corta (nunca exagera)
DNS_TOP_SHOWN = 10


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


def accumulate_dns(details, count, now):
    """Unbound da lo bloqueado en la ventana que guarda (días); se acumula por diferencias.

    Cuando el firewall descarta consultas antiguas la cifra baja: se toma como cero nuevo, no como negativo.
    Así la medida puede quedarse corta, pero nunca cuenta dos veces lo mismo.
    """
    previous = details.get('window')
    delta = 0 if previous is None else max(0, count - previous)
    day = timezone.localtime(now).date().isoformat()
    history = dict(details.get('history') or {})
    history[day] = history.get(day, 0) + delta
    cutoff = (timezone.localtime(now).date() - timedelta(days=HISTORY_DAYS)).isoformat()
    return {**details, 'window': count, 'checked_at': now.isoformat(), 'error': '',
            'since': details.get('since') or now.isoformat(), 'total_queries': details.get('total_queries', 0) + delta,
            'history': {d: v for d, v in history.items() if d >= cutoff}}


def dns_blocked(totals, uuids):
    """(consultas bloqueadas por las listas del SOC, dominios más bloqueados, recortado) de `overview/totals`.

    Unbound agrupa por dominio y anota la última política que lo bloqueó (`latest_policy_uuid`). None si la
    respuesta no tiene esa forma (versión sin estadísticas por política).
    """
    top = totals.get('top_blocked') if isinstance(totals, dict) else None
    if not isinstance(top, dict):
        return None
    count, domains = 0, []
    for domain, row in top.items():
        if not isinstance(row, dict) or str(row.get('latest_policy_uuid') or '') not in uuids:
            continue
        hits = _int(row.get('total')) or 0
        count += hits
        domains.append((hits, str(domain)[:253]))
    domains.sort(key=lambda item: (-item[0], item[1]))
    return count, [{'domain': d, 'queries': n} for n, d in domains[:DNS_TOP_SHOWN]], len(top) >= DNS_TOP


def measure_dns(plan, now=None):
    """Consultas que bloqueó la lista DNS del SOC según las estadísticas de Unbound. True si se midió."""
    from .change_control import api
    now = now or timezone.now()
    state = WorkerState.objects.filter(name=state_name(plan)).first()
    details = dict(state.details) if state else {}
    uuids = {o['uuid'] for o in plan.remote_objects if o.get('kind') == 'dnsbl'}
    result, error = None, ''
    try:
        connection = plan.device.opnsense_api
        enabled = api(connection, '/api/unbound/overview/is_enabled').get('enabled')
        if str(enabled) != '1':
            error = ('Las estadísticas de Unbound están desactivadas: activa la recogida local en «Informes › Ajustes» '
                     '(Unbound DNS) para medir lo que bloquea la lista del SOC.')
        else:
            result = dns_blocked(api(connection, f'/api/unbound/overview/totals/{DNS_TOP}'), uuids)
    except Exception:
        error = 'No se pudieron leer las estadísticas de Unbound por API.'
    if result is None:
        details.update(error=error or 'Unbound no informa de qué lista bloqueó cada dominio (¿OPNsense anterior a 25.7?).',
                       error_at=now.isoformat())
    else:
        details = accumulate_dns(details, result[0], now)
        details.update(top=result[1], truncated=result[2])
    with transaction.atomic():
        WorkerState.reserve(state_name(plan))
        WorkerState.objects.filter(name=state_name(plan)).update(details=details)
    return result is not None


def refresh(now=None):
    """Trabajo `blocklist_efficacy`: mide cada regla de bloqueo del SOC activa en un OPNsense por API, y sus listas DNS."""
    from .blocklist import ALL_TEMPLATES
    from .qfeeds_distribution import DNS_TEMPLATE
    now = now or timezone.now()
    measured = 0
    plans = ChangePlan._base_manager.filter(template__in=ALL_TEMPLATES + (DNS_TEMPLATE,), status='active',
                                            device__vendor='opnsense', device__management_method='api',
                                            device__active=True).select_related('device')
    for plan in plans:
        measured += int(measure_dns(plan, now) if plan.template == DNS_TEMPLATE else measure(plan, now))
    from .unifi_blocklist import measure_efficacy
    return measured + measure_efficacy(now)


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
            'total': details.get('total_packets', details.get('total_queries', 0)),
            'since': parse_datetime(details.get('since') or ''),
            'checked_at': parse_datetime(details.get('checked_at') or ''), 'loaded': details.get('loaded_entries'),
            'error': details.get('error', ''), 'resets': details.get('resets', 0),
            'top': details.get('top') or [], 'truncated': details.get('truncated', False)}


def client_protection(client, first_day=None, last_day=None, now=None):
    """Proyección para el cliente (invariante 3): solo cifras agregadas de las reglas activas del SOC.

    IPs en sus listas y paquetes bloqueados en el periodo (por defecto, los últimos 7 días), por lista:
    `inbound` (lista del SOC), `outbound` (salida C2), `preventive` (Q-Feeds preventiva) y `dns` (consultas
    bloqueadas por la lista DNS del SOC en Unbound, con `queries` en lugar de paquetes). La de entrada
    añade `sources`: cuántas de sus IPs confirman CrowdSec y cuántas Q-Feeds. Nunca IPs, motivos, bloqueos
    manuales ni errores internos. None si no hay ninguna regla activa con la lista publicada. `measured`
    es False hasta que haya una lectura de los contadores.
    """
    from .blocklist import ALL_TEMPLATES, plan_kind
    from .models import BlocklistFeed
    from .qfeeds_distribution import source_counts
    now = now or timezone.now()
    last_day = last_day or timezone.localtime(now).date()
    first_day = first_day or last_day - timedelta(days=6)
    feed = BlocklistFeed._base_manager.filter(client=client, enabled=True, stopped=False).first()
    if not feed:
        return None
    keys = {'in': 'inbound', 'out': 'outbound', 'preventive': 'preventive', 'qfeeds': 'preventive'}
    available = {'inbound': True, 'outbound': feed.outbound_enabled, 'preventive': feed.qfeeds_preventive}

    def item_for(key):
        if key not in result:
            entries = {'inbound': len(feed.entries), 'outbound': len(feed.outbound_entries),
                       'preventive': feed.preventive_count}[key]
            result[key] = {'entries': entries, 'packets': 0, 'firewalls': [], 'measured': False, 'measuring': False}
            if key == 'inbound':
                counts = source_counts(feed.entries)
                result[key]['sources'] = {'crowdsec': counts['crowdsec'], 'qfeeds': counts['qfeeds']}
        return result[key]

    plans = ChangePlan._base_manager.filter(template__in=ALL_TEMPLATES, status='active', device__site__client=client,
                                            device__active=True).select_related('device').order_by('device__name')
    result = {}
    for plan in plans:
        key = keys[plan_kind(plan)]
        if not available[key]:
            continue
        item = item_for(key)
        if plan.device.name not in item['firewalls']:
            item['firewalls'].append(plan.device.name)
        item['measuring'] = True
        state = WorkerState.objects.filter(name=state_name(plan)).first()
        history = (state.details.get('history') or {}) if state else {}
        if state and state.details.get('checked_at'):
            item['measured'] = True
            item['packets'] += sum(v for d, v in history.items() if first_day.isoformat() <= d <= last_day.isoformat())
    # Listas DNS del SOC en Unbound: consultas bloqueadas, no paquetes.
    from .qfeeds_distribution import DNS_TEMPLATE
    if feed.qfeeds_dns:
        for plan in ChangePlan._base_manager.filter(template=DNS_TEMPLATE, status='active', device__site__client=client,
                                                    device__active=True).select_related('device').order_by('device__name'):
            item = result.setdefault('dns', {'entries': feed.dns_count, 'queries': 0, 'firewalls': [], 'measured': False,
                                             'measuring': True})
            if plan.device.name not in item['firewalls']:
                item['firewalls'].append(plan.device.name)
            state = WorkerState.objects.filter(name=state_name(plan)).first()
            if state and state.details.get('checked_at'):
                item['measured'] = True
                item['queries'] += sum(v for d, v in (state.details.get('history') or {}).items()
                                       if first_day.isoformat() <= d <= last_day.isoformat())
    # DNS del SOC por la VPN de sedes: cuenta si alguna sede está conectada.
    if feed.dns_resolver and feed.qfeeds_dns:
        from .dns_resolver import blocked_between
        from .models import VpnPeer
        sites = list(VpnPeer._base_manager.filter(site__client=client, enabled=True, status='connected', site__active=True)
                     .order_by('site__name').values_list('site__name', flat=True))
        if sites:
            item = result.setdefault('dns', {'entries': feed.dns_count, 'queries': 0, 'firewalls': [], 'measured': False,
                                             'measuring': True})
            item['firewalls'] += [f'{name} (DNS del SOC)' for name in sites if f'{name} (DNS del SOC)' not in item['firewalls']]
            blocked = blocked_between(client.pk, first_day, last_day)
            if blocked is not None:
                item['measured'] = True
                item['queries'] += blocked
    # Consolas UniFi con la lista escrita por el SOC y sus políticas de bloqueo activas (no se presume
    # protección por una política hecha a mano que el SOC no ve). UniFi no ofrece contadores por regla.
    from .models import UnifiBlocklistBinding
    for binding in UnifiBlocklistBinding._base_manager.filter(device__site__client=client, device__active=True, enabled=True,
                                                              synced_at__isnull=False, error='',
                                                              policies_enabled=True).select_related('device'):
        if binding.direction == 'dns':
            # Política de dominios del SOC en UniFi: sin contadores; se cuentan los dominios escritos.
            if not feed.qfeeds_dns:
                continue
            item = result.setdefault('dns', {'entries': binding.pushed_count, 'queries': 0, 'firewalls': [], 'measured': False,
                                             'measuring': False})
            if binding.device.name not in item['firewalls']:
                item['firewalls'].append(binding.device.name)
            continue
        key = keys.get(binding.direction)
        if not key or not available[key]:
            continue
        item = item_for(key)
        if binding.device.name not in item['firewalls']:
            item['firewalls'].append(binding.device.name)
        if key == 'preventive' and not item['measuring']:
            # Solo UniFi: su lista lleva un tope (IPv4); se cuenta lo escrito, no la lista entera.
            item['unifi_entries'] = max(item.get('unifi_entries', 0), binding.pushed_count)
            item['entries'] = item['unifi_entries']
    return result or None

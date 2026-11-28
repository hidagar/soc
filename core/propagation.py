"""Propagación a los firewalls: lleva enseguida las novedades de Q-Feeds y CrowdSec a cada firewall y lo comprueba.

Trabajo `propagation` (cada 5 minutos):
1. Detecta datos nuevos en las fuentes (listas de Q-Feeds, coincidencias, reputación y listas de CrowdSec,
   detecciones del motor del SOC y bloqueos manuales). Si los hay, recalcula ya las listas de los clientes y
   escribe las de UniFi, sin esperar al recálculo periódico de 15 minutos.
2. Guarda una huella de lo que se sirve de cada lista (entrada, salida, preventiva y dominios) y cuándo cambió.
3. Comprueba, firewall por firewall, que ha recibido la versión vigente: descarga posterior al cambio (OPNsense y
   modo guiado), escritura verificada (UniFi) o configuración aplicada (DNS del SOC). Si un firewall lleva más de
   su margen sin recibirla, se avisa en «Salud del SOC»; el aviso se cierra solo al ponerse al día.
4. Pide a los OPNsense con una lista DNS del SOC aprobada que recarguen sus listas (`unbound/service/dnsbl`) cuando
   cambian los dominios: es la operación que la propia lista aprobada necesita para renovarse, no un cambio de
   configuración. Como mucho una vez cada 15 minutos por equipo.
5. Prepara en borrador las actualizaciones de plantilla pendientes (core.template_updates): no se aplican solas.
"""
import hashlib
from datetime import timedelta

from django.db import transaction
from django.db.models import Max
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from .models import BlocklistFeed, ChangePlan, OperationalIssue, WorkerState

STATE = 'blocklist-propagation'
REFRESH_EVERY = timedelta(minutes=15)
DNS_RELOAD_EVERY = timedelta(minutes=15)
MARGIN = timedelta(minutes=30)
KINDS = {'in': 'Lista de entrada', 'out': 'Lista de salida (C2)', 'preventive': 'Lista preventiva', 'dns': 'Dominios'}
ISSUE_PREFIX = 'platform:propagation:'


def source_marker():
    """Huella barata de los datos de origen: cambia cuando hay algo nuevo que propagar."""
    from .models import IpReputation, ManualBlock, ThreatIntelMatch
    from .threat_intel import details
    feeds = details().get('feeds') or {}
    parts = [f'{name}:{row.get("updated_at")}:{row.get("count")}' for name, row in sorted(feeds.items())]
    parts.append(str(ThreatIntelMatch._base_manager.aggregate(m=Max('updated_at'))['m']))
    reputation = IpReputation.objects.aggregate(lists=Max('lists_checked_at'), cti=Max('cti_checked_at'))
    parts += [str(reputation['lists']), str(reputation['cti'])]
    manual = ManualBlock._base_manager.aggregate(created=Max('created_at'), revoked=Max('revoked_at'), n=Max('pk'))
    parts += [str(manual['created']), str(manual['revoked']), str(manual['n'])]
    soc = WorkerState.objects.filter(name='soc-detections').first()
    parts.append(str((soc.details or {}).get('at') if soc else ''))
    return hashlib.sha256('|'.join(parts).encode()).hexdigest()


def _fingerprint(values):
    return hashlib.sha256('\n'.join(values).encode()).hexdigest()[:24]


def served(feed):
    """Lo que se sirve ahora de cada lista activa del cliente."""
    from .blocklist import servable
    from .qfeeds_distribution import servable_dns, servable_preventive
    result = {'in': servable(feed)}
    if feed.outbound_enabled:
        result['out'] = servable(feed, outbound=True)
    if feed.qfeeds_preventive:
        result['preventive'] = servable_preventive(feed)
    if feed.qfeeds_dns:
        result['dns'] = servable_dns(feed)
    return result


def record_versions(details, now):
    """Huella por cliente y lista; `changed_at` solo avanza si el contenido cambió."""
    versions = details.setdefault('versions', {})
    for feed in BlocklistFeed.objects.filter(enabled=True, client__active=True).select_related('client'):
        lists = versions.setdefault(str(feed.client_id), {})
        for kind, values in served(feed).items():
            fp = _fingerprint(values)
            row = lists.get(kind) or {}
            if row.get('fp') != fp:
                lists[kind] = {'fp': fp, 'count': len(values), 'changed_at': now.isoformat()}


def _fetch_by_device(feed):
    """{(lista, equipo): última descarga} por las IP conocidas de cada equipo."""
    from .blocklist import device_addresses
    known = device_addresses(feed.client)
    result = {}
    for kind, items in (feed.fetch_sources or {}).items():
        for ip, at in items.items():
            stamp = parse_datetime(at or '')
            for name in known.get(ip, []):
                if stamp and (not result.get((kind, name)) or stamp > result[(kind, name)]):
                    result[(kind, name)] = stamp
    return result


def _url_margin(plan):
    try:
        days = float(((plan.preview or {}).get('alias') or {}).get('updatefreq') or 0.04)
    except (TypeError, ValueError):
        days = 0.04
    from .template_updates import applied_version
    if applied_version(plan) != plan.template_version and float(days) > 0.01:
        days = 0.01  # actualizada a 1.1: la tabla se descarga cada ~15 minutos
    return timedelta(days=days) + MARGIN


def consumers(feed, now):
    """Quién debe recibir cada lista del cliente y si ya tiene la versión vigente: filas para la página y los avisos."""
    from .blocklist import FETCH_FIELDS, plan_kind, ALL_TEMPLATES
    from .models import UnifiBlocklistBinding
    from .qfeeds_distribution import DNS_TEMPLATE
    fetched = _fetch_by_device(feed)
    rows = []
    for plan in ChangePlan._base_manager.filter(template__in=ALL_TEMPLATES + (DNS_TEMPLATE,), status='active',
                                                device__site__client=feed.client, device__active=True).select_related('device'):
        kind = 'dns' if plan.template == DNS_TEMPLATE else plan_kind(plan)
        own = fetched.get((kind, plan.device.name))
        general = getattr(feed, FETCH_FIELDS[kind])
        margin = timedelta(minutes=15) + MARGIN if kind == 'dns' else _url_margin(plan)
        rows.append({'device': plan.device, 'kind': kind, 'how': 'URL (OPNsense)', 'received_at': own or general,
                     'exact': bool(own), 'margin': margin, 'plan': plan})
    for binding in UnifiBlocklistBinding._base_manager.filter(device__site__client=feed.client, device__active=True,
                                                              enabled=True).select_related('device'):
        kind = {'in': 'in', 'out': 'out', 'qfeeds': 'preventive', 'qout': 'preventive', 'dns': 'dns'}[binding.direction]
        rows.append({'device': binding.device, 'kind': kind, 'how': 'Escritura (UniFi)',
                     'received_at': None if binding.error else binding.synced_at, 'exact': True, 'margin': MARGIN,
                     'error': binding.error})
    if feed.dns_resolver and feed.qfeeds_dns:
        from .dns_resolver import status as resolver_status
        applied = parse_datetime(resolver_status().get('applied_at') or '')
        from .models import VpnPeer
        for peer in VpnPeer._base_manager.filter(site__client=feed.client, enabled=True).select_related('site'):
            rows.append({'device': None, 'site': peer.site, 'kind': 'dns', 'how': 'DNS del SOC', 'received_at': applied,
                         'exact': True, 'margin': timedelta(minutes=15) + MARGIN})
    return rows


def evaluate(details, now):
    """Estado de cada destino frente a la versión vigente de su lista."""
    result = []
    versions = details.get('versions') or {}
    for feed in BlocklistFeed.objects.filter(enabled=True, client__active=True).select_related('client'):
        lists = versions.get(str(feed.client_id)) or {}
        for row in consumers(feed, now):
            version = lists.get(row['kind'])
            changed = parse_datetime((version or {}).get('changed_at') or '')
            received = row['received_at']
            if not version or not changed:
                state = 'unknown'
            elif received and received >= changed:
                state = 'ok'
            elif now - changed > row['margin'] and not feed.stopped:
                state = 'late'
            else:
                state = 'pending'
            result.append({**row, 'client': feed.client, 'label': KINDS[row['kind']], 'state': state, 'changed_at': changed,
                           'count': (version or {}).get('count')})
    return result


def _issues(rows, now):
    from .operations import set_issue
    late = {}
    for row in rows:
        if row['state'] == 'late':
            name = row['device'].name if row.get('device') else f'{row["site"].name} (DNS del SOC)'
            key = f'{ISSUE_PREFIX}{row["client"].pk}:{row["kind"]}:{row["device"].pk if row.get("device") else "dns-" + str(row["site"].pk)}'
            late[key] = (row, name)
    for key, (row, name) in late.items():
        set_issue(key, f'{row["label"]} sin llegar a {name}', device=row.get('device'), now=now, severity='warning',
                  details=f'La lista cambió el {timezone.localtime(row["changed_at"]).strftime("%d/%m %H:%M")} y {name} aún no '
                          f'tiene esa versión ({row["how"]}). Revisar la conexión del firewall con el SOC.')
    for issue in OperationalIssue.objects.filter(key__startswith=ISSUE_PREFIX, active=True):
        if issue.key not in late:
            OperationalIssue.objects.filter(pk=issue.pk).update(active=False, resolved_at=now)
    return len(late)


def reload_dns(details, rows, now):
    """Pide a cada OPNsense con lista DNS del SOC aprobada que la recargue cuando cambian los dominios."""
    from .change_control import api, completed
    reloads = details.setdefault('dns_reloads', {})
    done = 0
    for row in rows:
        plan = row.get('plan')
        if row['kind'] != 'dns' or not plan or row['state'] not in ('pending', 'late'):
            continue
        last = parse_datetime(reloads.get(str(plan.pk)) or '')
        if last and now - last < DNS_RELOAD_EVERY:
            continue
        reloads[str(plan.pk)] = now.isoformat()
        try:
            if completed(api(plan.device.opnsense_api, '/api/unbound/service/dnsbl', {})):
                done += 1
        except Exception:
            continue  # se verá como «pendiente» o «retrasada»; nunca el texto del proveedor
    return done


def propagate(now=None):
    """Trabajo «Propagación a los firewalls». Devuelve cuántos destinos están al día."""
    from .blocklist import refresh_feeds
    from .template_updates import prepare_all
    from .unifi_blocklist import sync_all
    now = now or timezone.now()
    state = WorkerState.objects.filter(name=STATE).first()
    details = dict(state.details) if state else {}
    marker = source_marker()
    refreshed = parse_datetime(details.get('refreshed_at') or '')
    if marker != details.get('marker') or not refreshed or now - refreshed >= REFRESH_EVERY:
        refresh_feeds(now)
        sync_all(now)
        details.update(marker=marker, refreshed_at=now.isoformat())
    record_versions(details, now)
    rows = evaluate(details, now)
    details['dns_reloaded'] = reload_dns(details, rows, now)
    details['late'] = _issues(rows, now)
    details['updates_prepared'] = prepare_all()
    details['checked_at'] = now.isoformat()
    with transaction.atomic():
        WorkerState.reserve(STATE)
        WorkerState.objects.filter(name=STATE).update(details=details)
    return sum(1 for row in rows if row['state'] == 'ok')


def overview_rows(now=None):
    """Filas para la página de listas de bloqueo, con las actualizaciones de plantilla pendientes."""
    from .template_updates import outdated, pending_update
    now = now or timezone.now()
    state = WorkerState.objects.filter(name=STATE).first()
    details = dict(state.details) if state else {}
    rows = evaluate(details, now) if details.get('versions') else []
    for row in rows:
        plan = row.get('plan')
        row['update'] = pending_update(plan) if plan and outdated(plan) else None
    return rows, parse_datetime(details.get('checked_at') or '')

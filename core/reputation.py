"""Reputación de IPs con CrowdSec (hoja de ruta 4A/C1): contexto, nunca detección.

Dos fuentes, activas según las claves del entorno y combinables:
- listas (gratuitas, `SOC_PORTAL_CROWDSEC_LAPI_KEY`): decisiones del motor CrowdSec local,
  que recibe la lista comunitaria y las listas de la consola. La IP no sale de la VM.
- API CTI (de pago, `SOC_PORTAL_CROWDSEC_KEY`): reputación detallada, con cupo diario y
  mensual. Con las dos, la CTI se reserva para lo prioritario: tráfico permitido, IPs ya
  en lista, nivel alto y repetición.

Solo el trabajo protegido `reputation` consulta, con caché fechada; la web únicamente
lee la caché. Privacidad: se consultan solo orígenes públicos de tráfico entrante hacia
redes internas o IPs de clientes, nunca IPs internas, de clientes o destinos de
conexiones salientes. La reputación no crea incidencias ni cambia la acción o la
prioridad de una detección. No figurar en una lista no significa que la IP sea benigna.
"""
import ipaddress
import json
import os
import re
import time
from collections import Counter
from datetime import datetime, timedelta
from urllib import parse as urlparse
from urllib import error as urlerror
from urllib import request as urlrequest

from django.db import transaction
from django.db.models import Count, Max, Q
from django.utils import timezone

from .models import (ExportConfiguration, IpReputation, SecureLogChannel, SecurityEvidence, SourceOwnership,
                     WorkerState)

API = 'https://cti.api.crowdsec.net/v2/smoke/'
LAPI_DEFAULT = 'http://127.0.0.1:8080'
TTL = timedelta(days=3)
LAPI_TTL = timedelta(hours=6)
LAPI_RUN_LIMIT = 500
LISTS_EVERY = timedelta(hours=1)
LISTS_MAX_BYTES = 64 * 1024 * 1024
SCENARIO = re.compile(rb'"scenario"\s{0,8}:\s{0,8}"((?:[^"\\]|\\.){0,200})"')
WINDOW = timedelta(days=7)
MAX_RESPONSE = 512 * 1024
CTI_PACE = 15  # segundos entre consultas CTI: la API responde 429 a consultas casi seguidas
CTI_BACKOFF = (timedelta(minutes=15), timedelta(hours=1), timedelta(hours=6))
JOB_SECONDS = 180  # TimeoutStartSec de soc-job@: el lote CTI debe caber con margen
CTI_FAILED_RETRY = timedelta(days=1)
BAD = ('malicious', 'suspicious')
MODES = {'lapi+cti': 'Motor local + API CTI', 'lapi': 'Motor local (gratuito)', 'cti': 'API CTI (de pago)', '': 'Sin configurar'}
CTI_EMPTY = {'reputation': '', 'confidence': '', 'background_noise': '', 'background_noise_score': None, 'scores': {},
             'behaviors': [], 'classifications': [], 'false_positives': [], 'cti_lists': [], 'as_name': '', 'country': '',
             'first_seen': '', 'last_seen': ''}
LABELS = {'malicious': 'Maliciosa', 'suspicious': 'Sospechosa', 'known': 'Conocida', 'benign': 'Benigna',
          'safe': 'Segura', 'unknown': 'Sin datos', 'listed': 'En lista de bloqueo'}
# Origen de una decisión del motor local, en palabras del SOC.
ORIGINS = {'CAPI': 'Lista comunitaria', 'lists': 'Lista de la consola', 'crowdsec': 'Detección del motor local',
           'cscli': 'Decisión manual', 'console': 'Decisión desde la consola'}
LEVELS = {'high': 'alta', 'medium': 'media', 'low': 'baja', 'none': 'ninguna'}
ACTION_ORDER = {'allowed': 0, 'unknown': 1, 'blocked': 2}


class QuotaExceeded(Exception):
    """429 de la API CTI: límite de ritmo o cupo. `retry_after` en segundos si CrowdSec lo indica."""
    def __init__(self, retry_after=None):
        super().__init__()
        self.retry_after = retry_after


class KeyRejected(Exception):
    pass


class EngineUnavailable(Exception):
    pass


class _NoRedirect(urlrequest.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def daily_limit():
    try:
        return max(0, int(os.environ.get('SOC_PORTAL_CROWDSEC_DAILY_LIMIT', '30')))
    except ValueError:
        return 30


def monthly_limit():
    """Cupo mensual del plan CTI; None si no se ha declarado."""
    try:
        value = int(os.environ.get('SOC_PORTAL_CROWDSEC_MONTHLY_LIMIT', '0'))
    except ValueError:
        return None
    return value if value > 0 else None


def lapi_url():
    """URL base del motor local. HTTP solo hacia el propio equipo: la clave no viaja en claro por la red."""
    url = os.environ.get('SOC_PORTAL_CROWDSEC_LAPI_URL', '').strip().rstrip('/') or LAPI_DEFAULT
    parts = urlparse.urlsplit(url)
    if parts.scheme not in ('http', 'https') or not parts.hostname or parts.query or parts.fragment or parts.username:
        raise ValueError('SOC_PORTAL_CROWDSEC_LAPI_URL no es una URL válida')
    if parts.scheme == 'http' and parts.hostname != 'localhost':
        try:
            local = ipaddress.ip_address(parts.hostname).is_loopback
        except ValueError:
            local = False
        if not local:
            raise ValueError('SOC_PORTAL_CROWDSEC_LAPI_URL debe usar HTTPS fuera del propio equipo')
    return url


def mode():
    """Fuentes configuradas: 'lapi+cti', 'lapi', 'cti' o ''."""
    sources = [name for name, variable in (('lapi', 'SOC_PORTAL_CROWDSEC_LAPI_KEY'), ('cti', 'SOC_PORTAL_CROWDSEC_KEY'))
               if os.environ.get(variable, '').strip()]
    return '+'.join(sources)


def protected_addresses():
    """IPs y redes propias de clientes y del SOC: nunca se envían a un tercero.

    Devuelve un conjunto de IPs con las redes de excepción de los clientes en `networks`
    (oficinas remotas, socios): estar en un conjunto basta para `ip in protected`.
    """
    from .models import BlocklistFeed, Device
    values = set(ExportConfiguration._base_manager.exclude(source_ip=None).values_list('source_ip', flat=True))
    values |= set(Device._base_manager.exclude(management_address='').values_list('management_address', flat=True))
    values |= set(SourceOwnership._base_manager.values_list('source', flat=True))
    values |= set(SecureLogChannel._base_manager.exclude(last_transport_ip=None).values_list('last_transport_ip', flat=True))
    for variable in ('SOC_PORTAL_PUBLIC_SYSLOG_IP', 'SOC_PORTAL_EXTRA_SYSLOG_IPS'):
        values |= {v.strip() for v in os.environ.get(variable, '').split(',') if v.strip()}
    result = ProtectedSet()
    for value in values:
        try:
            result.add(str(ipaddress.ip_address(value)))
        except ValueError:
            continue
    from .blocklist import parse_allowlist
    for text in BlocklistFeed._base_manager.exclude(allowlist='').values_list('allowlist', flat=True):
        try:
            result.networks.extend(parse_allowlist(text))
        except ValueError:
            continue
    return result


class ProtectedSet(set):
    """Conjunto de IPs protegidas que también considera incluidas las de sus redes."""
    def __init__(self, *args):
        super().__init__(*args)
        self.networks = []

    def __contains__(self, ip):
        if super().__contains__(ip):
            return True
        if not self.networks:
            return False
        try:
            address = ipaddress.ip_address(ip)
        except (TypeError, ValueError):
            return False
        return any(address.version == net.version and address in net for net in self.networks)


def eligible(source, destination, protected):
    """Origen público externo de tráfico que entra en una red interna o en una IP de cliente."""
    try:
        src, dst = ipaddress.ip_address(source), ipaddress.ip_address(destination)
    except (TypeError, ValueError):
        return False
    if not src.is_global or str(src) in protected:
        return False
    return not dst.is_global or str(dst) in protected


def candidates(now, limit, protected, source='lists'):
    """Orígenes a consultar para una fuente, de mayor a menor interés.

    Permitidos primero; para la CTI, después los que ya figuran en una lista; luego nivel y repetición.
    """
    if limit <= 0:
        return []
    fresh = set(IpReputation.objects.filter(**{source + '_expires_at__gt': now}).values_list('ip', flat=True))
    listed = set(IpReputation.objects.filter(listed=True).values_list('ip', flat=True)) if source == 'cti' else set()
    rows = (SecurityEvidence._base_manager.filter(observed_at__gte=now - WINDOW, source_ip__isnull=False)
            .exclude(destination_ip=None).values('source_ip', 'destination_ip', 'action')
            .annotate(level=Max('level'), count=Count('uid')))
    best = {}
    for row in rows.iterator(chunk_size=1000):
        ip = row['source_ip']
        if ip in fresh or not eligible(ip, row['destination_ip'], protected):
            continue
        key = (ACTION_ORDER.get(row['action'], 1), ip not in listed, -row['level'], -row['count'])
        if ip not in best or key < best[ip]:
            best[ip] = key
    return [ip for ip, _ in sorted(best.items(), key=lambda item: (item[1], item[0]))[:limit]]


def _read(req, label):
    with urlrequest.build_opener(_NoRedirect()).open(req, timeout=10) as response:
        raw = response.read(MAX_RESPONSE + 1)
    if len(raw) > MAX_RESPONSE:
        raise ValueError(f'Respuesta {label} demasiado grande')
    return json.loads(raw)


def fetch_lapi(ip, key, base=None):
    """Decisiones vigentes del motor local para la IP (también por rango). [] si no figura."""
    url = (base or lapi_url()) + '/v1/decisions?' + urlparse.urlencode({'ip': ip})
    req = urlrequest.Request(url, headers={'X-Api-Key': key, 'User-Agent': 'ib-red-SOC/1'})
    try:
        data = _read(req, 'LAPI')
    except urlerror.HTTPError as exc:
        if exc.code in (401, 403):
            raise KeyRejected() from exc
        raise
    except (urlerror.URLError, ConnectionError, TimeoutError) as exc:
        raise EngineUnavailable() from exc
    if data is None:
        return []
    if not isinstance(data, list):
        raise ValueError('Respuesta LAPI no válida')
    return data


def count_decisions(key, base, origin):
    """Cuenta las decisiones de un origen leyendo por bloques: memoria acotada aunque la lista sea grande."""
    url = base + '/v1/decisions?' + urlparse.urlencode({'origins': origin})
    req = urlrequest.Request(url, headers={'X-Api-Key': key, 'User-Agent': 'ib-red-SOC/1'})
    scenarios, total, buffer = Counter(), 0, b''
    try:
        with urlrequest.build_opener(_NoRedirect()).open(req, timeout=30) as response:
            while True:
                chunk = response.read(256 * 1024)
                total += len(chunk)
                if total > LISTS_MAX_BYTES:
                    raise ValueError('Lista demasiado grande para resumir')
                buffer += chunk
                # Una coincidencia que empieza antes del corte ya está completa (máximo ~420 bytes).
                cut = len(buffer) if not chunk else max(0, len(buffer) - 512)
                for match in SCENARIO.finditer(buffer, 0, len(buffer)):
                    if match.start() >= cut:
                        break
                    scenarios[match.group(1).decode('utf-8', 'replace')[:120]] += 1
                buffer = buffer[cut:]
                if not chunk:
                    break
    except urlerror.HTTPError as exc:
        if exc.code in (401, 403):
            raise KeyRejected() from exc
        raise
    except (urlerror.URLError, ConnectionError, TimeoutError) as exc:
        raise EngineUnavailable() from exc
    return {'count': sum(scenarios.values()), 'top': scenarios.most_common(10)}


def summarize_lists(key, base, now):
    """Resumen horario de las listas del motor: solo recuentos y nombres de escenario o lista."""
    origins = {}
    for origin in ORIGINS:
        try:
            origins[origin] = count_decisions(key, base, origin)
        except (KeyRejected, EngineUnavailable):
            raise
        except Exception:
            origins[origin] = {'error': True}
    return {'at': now.isoformat(), 'origins': origins}


def parse_lapi(decisions):
    """Resumen de las decisiones: listas de origen, escenarios y rango. Nada más se guarda."""
    decisions = [d for d in decisions[:100] if isinstance(d, dict)]
    if not decisions:
        return {'listed': False, 'list_origins': [], 'list_scenarios': [], 'listed_range': ''}
    origins, scenarios, ranges = [], [], []
    for decision in decisions:
        origin = ORIGINS.get(decision.get('origin'), 'Otra fuente') if isinstance(decision.get('origin'), str) else 'Otra fuente'
        scenario = _text(decision.get('scenario'), 120)
        if origin not in origins:
            origins.append(origin)
        if scenario and scenario not in scenarios:
            scenarios.append(scenario)
        if str(decision.get('scope', '')).lower() == 'range':
            try:
                ranges.append(str(ipaddress.ip_network(_text(decision.get('value'), 64), strict=False)))
            except ValueError:
                pass
    return {'listed': True, 'list_origins': origins[:10], 'list_scenarios': scenarios[:20],
            'listed_range': ranges[0] if ranges else ''}


def fetch(ip, key):
    """Consulta CTI. Devuelve el JSON, o None si CrowdSec no tiene datos de la IP."""
    req = urlrequest.Request(API + ip, headers={'x-api-key': key, 'User-Agent': 'ib-red-SOC/1'})
    try:
        data = _read(req, 'CTI')
    except urlerror.HTTPError as exc:
        if exc.code == 404:
            return None
        if exc.code == 429:
            value = (exc.headers or {}).get('Retry-After', '') if exc.headers is not None else ''
            raise QuotaExceeded(int(value) if str(value).isdigit() else None) from exc
        if exc.code in (401, 403):
            raise KeyRejected() from exc
        raise
    if not isinstance(data, dict):
        raise ValueError('Respuesta CTI no válida')
    return data


def _text(value, size):
    return value[:size] if isinstance(value, str) else ''


def _labels(items):
    if not isinstance(items, list):
        return []
    return [_text(item.get('label') or item.get('name'), 120) for item in items[:20]
            if isinstance(item, dict) and (item.get('label') or item.get('name'))]


def _small(value):
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 32767 else None


def parse(data):
    """Solo los campos que se muestran; nada más del proveedor se guarda."""
    classifications = data.get('classifications') if isinstance(data.get('classifications'), dict) else {}
    overall = (data.get('scores') or {}).get('overall') if isinstance(data.get('scores'), dict) else {}
    history = data.get('history') if isinstance(data.get('history'), dict) else {}
    location = data.get('location') if isinstance(data.get('location'), dict) else {}
    reputation = data.get('reputation') if data.get('reputation') in LABELS and data.get('reputation') != 'listed' else 'unknown'
    return {
        'cti_found': True, 'reputation': reputation, 'confidence': _text(data.get('confidence'), 16),
        'background_noise': _text(data.get('background_noise'), 16),
        'background_noise_score': _small(data.get('background_noise_score')),
        'scores': {k: v for k, v in (overall or {}).items()
                   if k in ('aggressiveness', 'threat', 'trust', 'anomaly', 'total') and _small(v) is not None},
        'behaviors': _labels(data.get('behaviors')), 'classifications': _labels(classifications.get('classifications')),
        'false_positives': _labels(classifications.get('false_positives')),
        # Listas de CrowdSec que contienen la IP («list:<nombre>»), también las no suscritas.
        'cti_lists': [_text(r.get('name'), 120)[5:] for r in (data.get('references') or [])[:30]
                      if isinstance(r, dict) and isinstance(r.get('name'), str) and r['name'].startswith('list:')],
        'as_name': _text(data.get('as_name'), 200), 'country': _text(location.get('country'), 2),
        'first_seen': _text(history.get('first_seen'), 40), 'last_seen': _text(history.get('last_seen'), 40),
    }


def _store(ip, values, now):
    """Guarda los campos de una sola fuente; la otra conserva su dato y su fecha."""
    with transaction.atomic():
        # Escribir antes de leer: update_or_create lee primero y en SQLite falla con
        # "database is locked" si otro trabajo escribe a la vez (invariante 7).
        WorkerState.reserve('reputation-cache-lock')
        IpReputation.objects.update_or_create(ip=ip, defaults={**values, 'fetched_at': now})


def _refresh_lists(now, details, protected, errors):
    if details.get('lists_paused_until', '') > now.isoformat():
        errors.append('El motor rechazó la clave; consultas a las listas en pausa hasta las '
                      + timezone.localtime(datetime.fromisoformat(details['lists_paused_until'])).strftime('%H:%M')
                      + '. Revisa SOC_PORTAL_CROWDSEC_LAPI_KEY.')
        return 0
    updated = 0
    try:
        key = os.environ['SOC_PORTAL_CROWDSEC_LAPI_KEY'].strip()
        base = lapi_url()
        lists = details.get('lists') or {}
        if lists.get('at', '') <= (now - LISTS_EVERY).isoformat():
            details['lists'] = summarize_lists(key, base, now)
        for ip in candidates(now, LAPI_RUN_LIMIT, protected, 'lists'):
            try:
                decisions = fetch_lapi(ip, key, base)
            except (KeyRejected, EngineUnavailable):
                raise
            except Exception:
                continue  # Un fallo de una IP no detiene el resto.
            _store(ip, {**parse_lapi(decisions), 'lists_checked_at': now, 'lists_expires_at': now + LAPI_TTL}, now)
            updated += 1
    except ValueError as exc:
        errors.append(str(exc))  # Configuración no válida (URL del motor); no contiene la clave.
    except EngineUnavailable:
        errors.append('No se puede contactar con el motor CrowdSec local; se reintentará en la próxima ejecución.')
    except KeyRejected:
        details['lists_paused_until'] = (now + timedelta(hours=6)).isoformat()
        errors.append('El motor CrowdSec rechazó la clave. Revisa SOC_PORTAL_CROWDSEC_LAPI_KEY.')
    return updated


def cti_per_run():
    """Consultas CTI por ejecución (cada 15 min): pocas y espaciadas para no provocar el límite de ritmo."""
    try:
        wanted = int(os.environ.get('SOC_PORTAL_CROWDSEC_CTI_PER_RUN', '2'))
    except ValueError:
        wanted = 2
    # Si systemd corta el trabajo a medias se perdería el lote: que quepa con margen en su tiempo.
    return max(1, min(wanted, 20, (JOB_SECONDS - 60) // max(1, int(CTI_PACE)) or 1))


def cti_allowance(details):
    """Consultas CTI de esta ejecución: las del lote, sin pasar del cupo diario ni del mensual."""
    left = daily_limit() - details.get('used', 0)
    month = monthly_limit()
    return max(0, min(cti_per_run(), left, month - details.get('month_used', 0) if month else left))


def _persist_counters(details):
    """Guarda el consumo antes de cada consulta: un trabajo cortado no puede saltarse el cupo."""
    with transaction.atomic():
        WorkerState.reserve('crowdsec-quota-lock')
        WorkerState.objects.filter(name='crowdsec-quota').update(details=dict(details))


def _refresh_cti(now, details, protected, errors):
    if details.get('paused_until', '') > now.isoformat():
        errors.append('Consultas CTI en pausa hasta las '
                      + timezone.localtime(datetime.fromisoformat(details['paused_until'])).strftime('%H:%M') + '.')
        return 0
    updated = 0
    key = os.environ['SOC_PORTAL_CROWDSEC_KEY'].strip()
    try:
        for index, ip in enumerate(candidates(now, cti_allowance(details), protected, 'cti')):
            if index:
                time.sleep(CTI_PACE)
            # Se cuenta antes de llamar: un fallo también consume cupo en el proveedor.
            details['used'] = details.get('used', 0) + 1
            details['month_used'] = details.get('month_used', 0) + 1
            _persist_counters(details)
            try:
                data = fetch(ip, key)
            except (QuotaExceeded, KeyRejected):
                raise
            except Exception:
                # Un fallo de una IP no detiene el resto; no se reintenta hasta mañana para no gastar cupo.
                _store(ip, {'cti_expires_at': now + CTI_FAILED_RETRY}, now)
                continue
            values = parse(data) if data is not None else {**CTI_EMPTY, 'cti_found': False}
            _store(ip, {**values, 'cti_checked_at': now, 'cti_expires_at': now + TTL}, now)
            updated += 1
            details['cti_limited'] = 0
    except QuotaExceeded as exc:
        # Pausa según Retry-After si llega; si no, creciente: 15 min, 1 h y 6 h si se repite.
        strikes = details.get('cti_limited', 0)
        wait = (timedelta(seconds=min(max(exc.retry_after, 60), 6 * 3600)) if exc.retry_after
                else CTI_BACKOFF[min(strikes, len(CTI_BACKOFF) - 1)])
        details['cti_limited'] = strikes + 1
        details['paused_until'] = (now + wait).isoformat()
        errors.append('CrowdSec limitó las consultas CTI (429: ritmo o cupo); se reintentará a las '
                      + timezone.localtime(now + wait).strftime('%H:%M') + '.')
    except KeyRejected:
        details['paused_until'] = (now + timedelta(hours=6)).isoformat()
        errors.append('CrowdSec rechazó la clave de la API CTI. Revisa SOC_PORTAL_CROWDSEC_KEY.')
    return updated


def refresh(now=None):
    """Trabajo `reputation`: listas del motor y, si hay clave, API CTI. Devuelve actualizaciones."""
    now = now or timezone.now()
    state, _ = WorkerState.objects.get_or_create(name='crowdsec-quota')
    current = mode()
    if not current:
        state.error = ''
        state.details = {**state.details, 'enabled': False, 'mode': ''}
        state.save(update_fields=['error', 'details'])
        return 0
    details = dict(state.details)
    local = timezone.localtime(now)
    today, month = local.date().isoformat(), local.strftime('%Y-%m')
    if details.get('day') != today:
        details.update(day=today, used=0)
    if details.get('month') != month:
        details.update(month=month, month_used=0)
    details.update(enabled=True, mode=current)
    errors, updated, protected = [], 0, protected_addresses()
    # Primero las listas: la CTI prioriza después las IPs que ya figuran en ellas.
    if 'lapi' in current:
        updated += _refresh_lists(now, details, protected, errors)
    if 'cti' in current:
        updated += _refresh_cti(now, details, protected, errors)
    state.error = ' '.join(errors)[:240]
    state.details = details
    state.last_run_at = now
    if not state.error:
        state.last_success_at = now
    state.save()
    return updated


def _decorate(row, now):
    """Etiquetas para la web. La CTI, si existe, describe la IP; las listas la complementan."""
    if row.cti_found:
        row.label = LABELS.get(row.reputation, 'Sin datos')
        row.css = row.reputation or 'unknown'
    elif row.listed:
        row.label, row.css = LABELS['listed'], 'listed'
    elif row.listed is False:
        row.label, row.css = 'No figura en las listas', 'unknown'
    else:
        row.label, row.css = 'Sin datos en CrowdSec', 'unknown'
    row.flagged = row.listed is True or (row.cti_found is True and row.reputation in BAD)
    row.noise = row.cti_found is True and (row.background_noise == 'high' or bool(row.false_positives))
    row.confidence_label = LEVELS.get(row.confidence, row.confidence)
    row.noise_label = LEVELS.get(row.background_noise, row.background_noise)
    row.lists_stale = bool(row.lists_expires_at and row.lists_expires_at <= now)
    row.cti_stale = bool(row.cti_expires_at and row.cti_expires_at <= now)
    row.stale = row.lists_stale or row.cti_stale
    return row


def lookup(ip, now=None):
    """Lectura para la web: la reputación en caché de una IP, o None. Nunca llama a la API."""
    try:
        ip = str(ipaddress.ip_address(ip))
    except (TypeError, ValueError):
        return None
    row = IpReputation.objects.filter(ip=ip).first()
    return _decorate(row, now or timezone.now()) if row else None


def lookup_many(ips, now=None):
    """Lectura para la web de varias IPs, por bloques (límite de parámetros de SQLite)."""
    now = now or timezone.now()
    wanted, rows = sorted({ip for ip in ips if ip}), {}
    for start in range(0, len(wanted), 1000):
        for row in IpReputation.objects.filter(ip__in=wanted[start:start + 1000]):
            rows[row.ip] = _decorate(row, now)
    return rows


def prune(now):
    return IpReputation.objects.filter(Q(fetched_at__lt=now - timedelta(days=90))).delete()[0]

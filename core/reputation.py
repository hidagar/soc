"""Reputación de IPs con CrowdSec CTI (hoja de ruta 4A/C1): contexto, nunca detección.

Solo el trabajo protegido `reputation` consulta la API, con la clave del entorno, un
cupo diario y caché con fecha del dato; la web únicamente lee la caché. Privacidad:
se consultan solo orígenes públicos de tráfico entrante hacia redes internas o IPs
de clientes, nunca IPs internas, de clientes o destinos de conexiones salientes.
La reputación no crea incidencias ni cambia la acción o la prioridad de una detección.
"""
import ipaddress
import json
import os
from datetime import timedelta
from urllib import error as urlerror
from urllib import request as urlrequest

from django.db.models import Count, Max, Q
from django.utils import timezone

from .models import (ExportConfiguration, IpReputation, SecureLogChannel, SecurityEvidence, SourceOwnership,
                     WorkerState)

API = 'https://cti.api.crowdsec.net/v2/smoke/'
TTL = timedelta(days=3)
WINDOW = timedelta(days=7)
MAX_RESPONSE = 512 * 1024
LABELS = {'malicious': 'Maliciosa', 'suspicious': 'Sospechosa', 'known': 'Conocida', 'benign': 'Benigna',
          'safe': 'Segura', 'unknown': 'Sin datos'}
LEVELS = {'high': 'alta', 'medium': 'media', 'low': 'baja', 'none': 'ninguna'}
ACTION_ORDER = {'allowed': 0, 'unknown': 1, 'blocked': 2}


class QuotaExceeded(Exception):
    pass


class KeyRejected(Exception):
    pass


class _NoRedirect(urlrequest.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def daily_limit():
    try:
        return max(0, int(os.environ.get('SOC_PORTAL_CROWDSEC_DAILY_LIMIT', '30')))
    except ValueError:
        return 30


def protected_addresses():
    """IPs propias de clientes y del SOC: nunca se envían a un tercero."""
    values = set(ExportConfiguration._base_manager.exclude(source_ip=None).values_list('source_ip', flat=True))
    values |= set(SourceOwnership._base_manager.values_list('source', flat=True))
    values |= set(SecureLogChannel._base_manager.exclude(last_transport_ip=None).values_list('last_transport_ip', flat=True))
    for variable in ('SOC_PORTAL_PUBLIC_SYSLOG_IP', 'SOC_PORTAL_EXTRA_SYSLOG_IPS'):
        values |= {v.strip() for v in os.environ.get(variable, '').split(',') if v.strip()}
    result = set()
    for value in values:
        try:
            result.add(str(ipaddress.ip_address(value)))
        except ValueError:
            continue
    return result


def eligible(source, destination, protected):
    """Origen público externo de tráfico que entra en una red interna o en una IP de cliente."""
    try:
        src, dst = ipaddress.ip_address(source), ipaddress.ip_address(destination)
    except (TypeError, ValueError):
        return False
    if not src.is_global or str(src) in protected:
        return False
    return not dst.is_global or str(dst) in protected


def candidates(now, limit, protected):
    """Orígenes a consultar, de mayor a menor interés: permitidos, nivel alto y repetición."""
    if limit <= 0:
        return []
    fresh = set(IpReputation.objects.filter(expires_at__gt=now).values_list('ip', flat=True))
    rows = (SecurityEvidence._base_manager.filter(observed_at__gte=now - WINDOW, source_ip__isnull=False)
            .exclude(destination_ip=None).values('source_ip', 'destination_ip', 'action')
            .annotate(level=Max('level'), count=Count('uid')))
    best = {}
    for row in rows.iterator(chunk_size=1000):
        ip = row['source_ip']
        if ip in fresh or not eligible(ip, row['destination_ip'], protected):
            continue
        key = (ACTION_ORDER.get(row['action'], 1), -row['level'], -row['count'])
        if ip not in best or key < best[ip]:
            best[ip] = key
    return [ip for ip, _ in sorted(best.items(), key=lambda item: (item[1], item[0]))[:limit]]


def fetch(ip, key):
    """Consulta CTI. Devuelve el JSON, o None si CrowdSec no tiene datos de la IP."""
    req = urlrequest.Request(API + ip, headers={'x-api-key': key, 'User-Agent': 'ib-red-SOC/1'})
    try:
        with urlrequest.build_opener(_NoRedirect()).open(req, timeout=10) as response:
            raw = response.read(MAX_RESPONSE + 1)
    except urlerror.HTTPError as exc:
        if exc.code == 404:
            return None
        if exc.code == 429:
            raise QuotaExceeded() from exc
        if exc.code in (401, 403):
            raise KeyRejected() from exc
        raise
    if len(raw) > MAX_RESPONSE:
        raise ValueError('Respuesta CTI demasiado grande')
    data = json.loads(raw)
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
    reputation = data.get('reputation') if data.get('reputation') in LABELS else 'unknown'
    return {
        'found': True, 'reputation': reputation, 'confidence': _text(data.get('confidence'), 16),
        'background_noise': _text(data.get('background_noise'), 16),
        'background_noise_score': _small(data.get('background_noise_score')),
        'scores': {k: v for k, v in (overall or {}).items()
                   if k in ('aggressiveness', 'threat', 'trust', 'anomaly', 'total') and _small(v) is not None},
        'behaviors': _labels(data.get('behaviors')), 'classifications': _labels(classifications.get('classifications')),
        'false_positives': _labels(classifications.get('false_positives')),
        'as_name': _text(data.get('as_name'), 200), 'country': _text(location.get('country'), 2),
        'first_seen': _text(history.get('first_seen'), 40), 'last_seen': _text(history.get('last_seen'), 40),
    }


def refresh(now=None):
    """Trabajo `reputation`: consulta los candidatos dentro del cupo diario. Devuelve IPs actualizadas."""
    now = now or timezone.now()
    state, _ = WorkerState.objects.get_or_create(name='crowdsec-quota')
    key = os.environ.get('SOC_PORTAL_CROWDSEC_KEY', '').strip()
    if not key:
        state.error = ''
        state.details = {**state.details, 'enabled': False}
        state.save(update_fields=['error', 'details'])
        return 0
    today = now.date().isoformat()
    details = state.details if state.details.get('day') == today else {'day': today, 'used': 0}
    details['enabled'] = True
    if details.get('paused_until', '') > now.isoformat():
        return 0
    updated = 0
    try:
        for ip in candidates(now, daily_limit() - details.get('used', 0), protected_addresses()):
            # Se cuenta antes de llamar: un fallo también consume cupo en el proveedor.
            details['used'] = details.get('used', 0) + 1
            try:
                data = fetch(ip, key)
            except (QuotaExceeded, KeyRejected):
                raise
            except Exception:
                continue  # Un fallo de una IP no detiene el resto; se reintentará cuando caduque.
            values = parse(data) if data is not None else {'found': False, 'reputation': 'unknown'}
            defaults = {field.name: field.get_default() for field in IpReputation._meta.concrete_fields
                        if field.name not in ('id', 'ip', 'fetched_at', 'expires_at')}
            IpReputation.objects.update_or_create(ip=ip, defaults={**defaults, **values, 'fetched_at': now,
                                                                   'expires_at': now + TTL})
            updated += 1
        state.error = ''
    except QuotaExceeded:
        details['paused_until'] = (now + timedelta(hours=6)).isoformat()
        state.error = 'CrowdSec indicó cupo agotado; consultas en pausa seis horas.'
    except KeyRejected:
        details['paused_until'] = (now + timedelta(hours=6)).isoformat()
        state.error = 'CrowdSec rechazó la clave de la API. Revisa SOC_PORTAL_CROWDSEC_KEY.'
    state.details = details
    state.last_run_at = now
    if not state.error:
        state.last_success_at = now
    state.save()
    return updated


def _decorate(row):
    row.label = LABELS.get(row.reputation, 'Sin datos') if row.found else 'Sin datos en CrowdSec'
    row.confidence_label = LEVELS.get(row.confidence, row.confidence)
    row.noise_label = LEVELS.get(row.background_noise, row.background_noise)
    return row


def lookup(ip, now=None):
    """Lectura para la web: la reputación en caché de una IP, o None. Nunca llama a la API."""
    try:
        ip = str(ipaddress.ip_address(ip))
    except (TypeError, ValueError):
        return None
    row = IpReputation.objects.filter(ip=ip).first()
    if row:
        _decorate(row).stale = row.expires_at <= (now or timezone.now())
    return row


def lookup_many(ips):
    rows = {}
    for row in IpReputation.objects.filter(ip__in={ip for ip in ips if ip}):
        rows[row.ip] = _decorate(row)
    return rows


def prune(now):
    return IpReputation.objects.filter(Q(fetched_at__lt=now - timedelta(days=90))).delete()[0]

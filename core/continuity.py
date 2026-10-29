"""Continuidad del servicio: IP real de los accesos, silencio global, ensayo de recuperación y monitor exterior.

Lo comprueba el trabajo `health` cada minuto. Los avisos van a «Salud del SOC» como el resto de
`platform:*`; los críticos, además, por correo de operaciones (`notify_issues`).

Si la VM entera cae, nada de esto puede avisar desde dentro. Para eso hay dos piezas para un servicio
externo (p. ej. Healthchecks.io o el monitor de la red):
- `/healthz/`: responde 200 «ok» o 503 «revisar», sin más detalle, para monitores que consultan;
- latido saliente: con SOC_PORTAL_HEARTBEAT_URL, el SOC llama a esa URL cada 5 minutos si está sano
  y a `<URL>/fail` si no. El servicio externo avisa cuando deja de recibir llamadas.
"""
import ipaddress
import logging
from collections import defaultdict
from datetime import timedelta
from urllib import error as url_error, request as http
from urllib.parse import urlsplit

from django.conf import settings
from django.db.models import Max, Sum
from django.http import HttpResponse
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.views.decorators.http import require_GET

from .models import DeviceHealth, FeedBucket, OperationalIssue, RecoverySettings, WorkerState
from .operations import set_issue

logger = logging.getLogger(__name__)

LOGIN_WINDOW = timedelta(days=7)
LOGIN_MIN_ATTEMPTS = 3
GLOBAL_FAST = timedelta(minutes=30)        # nunca antes de media hora sin nada
GLOBAL_FAST_MIN_HOURLY = 60                # …y solo si a esas horas siempre llegan más de 60 eventos por hora
GLOBAL_HOUR_MIN = 10                       # una hora completa sin nada que siempre tuvo al menos 10
GLOBAL_NO_HISTORY = timedelta(hours=6)     # sin una semana de historia
GLOBAL_BACKSTOP = timedelta(hours=24)      # en cualquier caso
REHEARSAL_MAX_AGE = timedelta(days=180)
HEARTBEAT_EVERY = timedelta(minutes=5)
HEALTH_JOB_MAX_AGE = timedelta(minutes=5)
# Fallos que significan «el SOC no está haciendo su trabajo»: los que cambian /healthz y el latido.
CORE_ISSUES = ('platform:soc-portal', 'platform:wazuh-manager', 'platform:wazuh-indexer', 'platform:disk',
               'platform:ingest-silence', 'platform:urgent-monitor')


def _resolve(key, now):
    OperationalIssue.objects.filter(key=key, active=True).update(active=False, resolved_at=now)


def _stamp(value):
    try:
        stamp = parse_datetime(value or '')
    except (TypeError, ValueError):
        return None
    return stamp if stamp and timezone.is_aware(stamp) else None


# -- IP real ------------------------------------------------------------------------------------------
def note_login_origin(ip, now=None):
    """Anota si un intento de acceso llegó con IP pública o interna (solo se guardan las internas)."""
    now = now or timezone.now()
    state, _ = WorkerState.objects.get_or_create(name='login-origin')
    details = dict(state.details)
    if ip is None:
        details['unattributed_at'] = now.isoformat()
    elif ipaddress.ip_address(ip).is_global:
        details['public_at'] = now.isoformat()
    else:
        internal = {k: v for k, v in (details.get('internal') or {}).items()
                    if (_stamp(v.get('at')) or now) > now - LOGIN_WINDOW}
        row = internal.get(ip) or {'n': 0}
        internal[ip] = {'at': now.isoformat(), 'n': int(row.get('n', 0)) + 1}
        details['internal'] = dict(sorted(internal.items(), key=lambda kv: kv[1]['at'])[-20:])
    state.details = details
    state.save(update_fields=['details'])


def check_login_origin(now):
    """Todos los accesos de la semana desde una única IP interna: casi seguro, un proxy sin IP real."""
    state = WorkerState.objects.filter(name='login-origin').first()
    details = state.details if state else {}
    public = _stamp(details.get('public_at'))
    internal = {ip: row for ip, row in (details.get('internal') or {}).items()
                if (_stamp(row.get('at')) or now - LOGIN_WINDOW) > now - LOGIN_WINDOW}
    if (not public or public < now - LOGIN_WINDOW) and len(internal) == 1:
        ip, row = next(iter(internal.items()))
        if int(row.get('n', 0)) >= LOGIN_MIN_ATTEMPTS:
            set_issue('platform:real-ip', 'Los accesos al portal no traen la IP real',
                      details=f'En 7 días todos los accesos llegan desde {ip}, una IP interna. Si el portal se publica '
                              'a través de otro proxy, este no pasa la IP del visitante: el límite de intentos trata a '
                              'todos como uno y la auditoría no ve el origen. Solución: deploy/configurar_ip_real.sh '
                              f'{ip} (véase docs/deployment.md). Si todo el equipo entra por VPN, se puede ignorar.',
                      severity='warning', now=now)
            return
    _resolve('platform:real-ip', now)


# -- Silencio global ----------------------------------------------------------------------------------
def _hourly_counts(start, end):
    """Eventos recibidos de todos los equipos activos por (fecha local, hora local)."""
    rows = (FeedBucket._base_manager.filter(hour__gte=start, hour__lt=end, device__active=True, device__site__active=True,
                                            device__site__client__active=True)
            .values('hour').annotate(n=Sum('event_count')).order_by())
    counts = defaultdict(int)
    for row in rows:
        local = timezone.localtime(row['hour'])
        counts[(local.date(), local.hour)] += row['n']
    return counts


def _usual(counts, hour):
    """Lo mínimo recibido en esa misma franja horaria cada uno de los 7 días anteriores."""
    local = timezone.localtime(hour)
    return min(counts.get((local.date() - timedelta(days=day), local.hour), 0) for day in range(1, 8))


def silence_reason(latest, now):
    """Motivo para avisar de que no llega nada de ningún equipo, o '' si ese silencio es normal a estas horas.

    `last_log_at` solo avanza con alertas de Wazuh (varias reglas del SOC son de nivel 0): de noche puede
    pasar una hora sin nada sin que falle nada. Antes se avisaba con un umbral fijo de 30 minutos, que podía
    dar avisos críticos falsos. Ahora se compara con la misma franja horaria de los 7 días anteriores.
    """
    silence = now - latest
    if silence < GLOBAL_FAST:
        return ''
    minutes = int(silence.total_seconds() // 60)
    if silence >= GLOBAL_BACKSTOP:
        return f'No llega ningún evento de ningún equipo desde hace {minutes // 60} horas.'
    if not FeedBucket._base_manager.filter(hour__lte=now - timedelta(days=7)).exists():
        if silence >= GLOBAL_NO_HISTORY:
            return (f'No llega ningún evento de ningún equipo desde hace {minutes // 60} horas (aún no hay una semana '
                    'de historia para conocer el ritmo normal).')
        return ''
    counts = _hourly_counts(now - timedelta(days=8), now)
    first = latest.replace(minute=0, second=0, microsecond=0)
    overlapped = [first + timedelta(hours=i) for i in range(int((now - first).total_seconds() // 3600) + 1)]
    # Instalación muy activa: a estas horas siempre llegan más de 60 eventos por hora.
    if all(_usual(counts, hour) >= GLOBAL_FAST_MIN_HOURLY for hour in overlapped):
        return (f'No llega ningún evento de ningún equipo desde hace {minutes} minutos, y a estas horas siempre '
                f'llegan más de {GLOBAL_FAST_MIN_HOURLY} por hora.')
    # Una hora completa sin nada que los 7 días anteriores siempre tuvo actividad.
    for hour in overlapped:
        usual = _usual(counts, hour)
        if hour >= latest and hour + timedelta(hours=1) <= now and usual >= GLOBAL_HOUR_MIN:
            local = timezone.localtime(hour)
            return (f'La franja de {local:%H}:00 a {(local + timedelta(hours=1)):%H}:00 ha pasado sin ningún evento de '
                    f'ningún equipo; los 7 días anteriores siempre tuvo al menos {usual}.')
    return ''


def check_ingest_silence(now):
    """Ningún equipo envía registros: suele ser el receptor, el disco o la red del SOC, no los clientes."""
    latest = DeviceHealth.objects.filter(device__active=True, device__site__active=True,
                                         device__site__client__active=True).aggregate(m=Max('last_log_at'))['m']
    reason = silence_reason(latest, now) if latest else ''
    if reason:
        set_issue('platform:ingest-silence', 'No llegan registros de ningún equipo',
                  details=reason + ' Revisar el receptor syslog, Wazuh, el disco y la red de la VM antes que los '
                                   'equipos de los clientes.',
                  severity='critical', now=now)
    else:
        _resolve('platform:ingest-silence', now)


# -- Ensayo de recuperación ---------------------------------------------------------------------------
def check_restore_rehearsal(now):
    """Con copias de VM, la copia solo está demostrada si se ha restaurado y medido hace menos de 6 meses."""
    cfg = RecoverySettings.objects.filter(pk=1).first()
    if not cfg or cfg.transport != 'vm':
        _resolve('platform:restore-rehearsal', now)
        return
    done = _stamp(cfg.vm_backup.get('vm_last_restore_at'))
    measured = cfg.vm_backup.get('vm_restore_rpo_hours') is not None and cfg.vm_backup.get('vm_restore_rto_minutes') is not None
    if done and now - done <= REHEARSAL_MAX_AGE and measured:
        _resolve('platform:restore-rehearsal', now)
        return
    reason = ('No hay ningún ensayo registrado' if not done else
              'El último ensayo tiene más de 6 meses' if now - done > REHEARSAL_MAX_AGE else
              'Al último ensayo le faltan la pérdida de datos y el tiempo medidos')
    set_issue('platform:restore-rehearsal', 'Ensayo de recuperación de la VM pendiente',
              details=f'{reason}. Restaurar la copia en una red aislada (docs/recovery.md), ejecutar '
                      'manage.py comprobar_restauracion y registrar el resultado en Copias y recuperación.',
              severity='warning', now=now)


# -- Monitor exterior ---------------------------------------------------------------------------------
def healthy(now=None):
    """El SOC hace su trabajo: el trabajo de salud ha corrido hace poco y no hay fallos básicos abiertos."""
    now = now or timezone.now()
    # Sin ámbito de cliente: la vista es pública y estos datos son de la plataforma.
    job = WorkerState._base_manager.filter(name='job:health').first()
    if not job or not job.last_success_at or now - job.last_success_at > HEALTH_JOB_MAX_AGE:
        return False
    return not OperationalIssue._base_manager.filter(key__in=CORE_ISSUES, active=True).exists()


def heartbeat_url():
    url = (getattr(settings, 'SOC_HEARTBEAT_URL', '') or '').strip().rstrip('/')
    parts = urlsplit(url)
    return url if parts.scheme == 'https' and parts.hostname and not parts.username and not parts.password else ''


class _NoRedirect(http.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def send_heartbeat(now, ok):
    """Latido saliente cada 5 minutos. Nunca envía datos: solo la URL configurada o su variante /fail."""
    url = heartbeat_url()
    if not url:
        return None
    state, _ = WorkerState.objects.get_or_create(name='heartbeat')
    if state.last_run_at and now - state.last_run_at < HEARTBEAT_EVERY and state.details.get('ok') == ok:
        return None
    state.last_run_at = now
    state.details = {'ok': ok}
    try:
        target = url if ok else url + '/fail'
        with http.build_opener(_NoRedirect()).open(http.Request(target, headers={'User-Agent': 'SOC-Heartbeat/1'}),
                                                   timeout=10) as response:
            sent = 200 <= response.status < 300
    except (OSError, url_error.URLError, ValueError):
        sent = False
    state.error = '' if sent else 'El servicio de latido no respondió.'
    if sent:
        state.last_success_at = now
    state.save()
    return sent


def run(now=None):
    now = now or timezone.now()
    check_login_origin(now)
    check_ingest_silence(now)
    check_restore_rehearsal(now)
    # El latido refleja el estado sin contar esta misma ejecución del trabajo, que aún no ha terminado.
    send_heartbeat(now, not OperationalIssue.objects.filter(key__in=CORE_ISSUES, active=True).exists())


@require_GET
def healthz(request):
    """Para monitores externos: sin sesión, sin detalles y sin caché."""
    try:
        ok = healthy()
    except Exception:  # la base no responde: también es una caída
        logger.exception('healthz')
        ok = False
    response = HttpResponse('ok' if ok else 'revisar', status=200 if ok else 503, content_type='text/plain')
    response['Cache-Control'] = 'no-store'
    response['X-Robots-Tag'] = 'noindex'
    return response

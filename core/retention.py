"""Conservación de datos operativos: borra por bloques lo que ha superado su plazo.

Lo ejecuta cada hora el trabajo `housekeeping`, sin depender de las copias. Antes solo se limpiaba
al final de una copia correcta: con varios días de copias fallidas la base crecía sin límite, y con
ella el espacio que necesita la copia siguiente.

Cada bloque es una transacción corta: en SQLite, un DELETE de cientos de miles de filas retenía el
escritor y bloqueaba la recepción de eventos y el portal. Si se agota el tiempo, sigue en la
próxima hora. Primero lo pequeño (intentos de acceso, contadores por hora, registros operativos) y después
las detecciones.

Plazos de los registros operativos (constantes; cambiarlos aquí y en docs/operations.md):
- avisos por Teams o Telegram ya terminados: 365 días (el aviso urgente se conserva por su lado);
- caídas de Internet: 400 días (la línea de tiempo llega a 365 y el informe mensual mira el mes anterior);
- solicitudes de clientes resueltas, con su conversación: 730 días desde la resolución;
- propuestas de política «Ya no aplica»: 180 días sin cambios;
- consultas de contexto de Q-Feeds: 90 días (son una caché);
- antivirus de equipos: detecciones revisadas sin incidencia, con el plazo de las evidencias; agentes sin
  asignar sin eventos en 90 días; equipos retirados (con sus detecciones), 400 días.
"""
import time
from datetime import timedelta

from django.db import transaction
from django.utils import timezone

from .models import AuthAttempt, FeedBucket, RecoverySettings, SecurityEvidence, WorkerState

CHUNK = 1000
BUDGET = 60  # segundos por ejecución; el trabajo dispone de 180
DEFAULT_EVIDENCE_DAYS = 90
AUTH_ATTEMPT_DAYS = 1  # los límites de intentos miran 15 minutos
CHAT_NOTICE_DAYS = 365
CONNECTIVITY_DAYS = 400
RESOLVED_REQUEST_DAYS = 730
OBSOLETE_PROPOSAL_DAYS = 180
CONTEXT_LOOKUP_DAYS = 90
STALE_PENDING_AGENT_DAYS = 90
RETIRED_AGENT_DAYS = 400
CHAT_FINAL = ('accepted', 'delivered', 'suppressed', 'failed', 'uncertain', 'expired')


def _prune(queryset, deadline):
    """Borra las filas de `queryset` por bloques. Devuelve (borradas, terminado)."""
    model = queryset.model
    key = model._meta.pk.attname
    deleted = 0
    while time.monotonic() < deadline:
        ids = list(queryset.values_list(key, flat=True)[:CHUNK])
        if not ids:
            return deleted, True
        with transaction.atomic():
            deleted += model._base_manager.filter(**{key + '__in': ids}).delete()[0]
    return deleted, False


def prune(now=None, budget=BUDGET):
    """Detecciones sin incidencia y contadores por hora más antiguos que «Retención de evidencias»
    (Copias y recuperación, 90 días por defecto) e intentos de acceso de más de un día."""
    now = now or timezone.now()
    cfg = RecoverySettings.objects.filter(pk=1).first()
    days = cfg.evidence_days if cfg else DEFAULT_EVIDENCE_DAYS
    cutoff = now - timedelta(days=days)
    deadline = time.monotonic() + budget
    result = {'checked_at': now.isoformat(), 'evidence_days': days, 'pending': False}
    from .models import (ChatNotice, ConnectivityEvent, CustomerRequest, EndpointAgent, EndpointDetection, PolicyProposal,
                         ThreatIntelLookup)
    for name, queryset in (
            ('auth_attempts', AuthAttempt._base_manager.filter(
                occurred_at__lt=now - timedelta(days=AUTH_ATTEMPT_DAYS)).order_by('occurred_at')),
            ('feed_buckets', FeedBucket._base_manager.filter(hour__lt=cutoff).order_by()),
            ('chat_notices', ChatNotice._base_manager.filter(
                created_at__lt=now - timedelta(days=CHAT_NOTICE_DAYS), status__in=CHAT_FINAL).order_by('created_at')),
            ('connectivity', ConnectivityEvent._base_manager.filter(
                observed_at__lt=now - timedelta(days=CONNECTIVITY_DAYS)).order_by('observed_at')),
            # Al borrar la solicitud se borra su conversación (CASCADE); una incidencia enlazada se conserva.
            ('resolved_requests', CustomerRequest._base_manager.filter(
                status='resolved', resolved_at__lt=now - timedelta(days=RESOLVED_REQUEST_DAYS)).order_by('resolved_at')),
            ('obsolete_proposals', PolicyProposal._base_manager.filter(
                status='obsolete', updated_at__lt=now - timedelta(days=OBSOLETE_PROPOSAL_DAYS)).order_by('updated_at')),
            ('endpoint_detections', EndpointDetection._base_manager.filter(
                review='reviewed', incident__isnull=True, observed_at__lt=cutoff).order_by('observed_at')),
            ('pending_agents', EndpointAgent._base_manager.filter(
                status='pending', last_seen_at__lt=now - timedelta(days=STALE_PENDING_AGENT_DAYS)).order_by('last_seen_at')),
            ('retired_agents', EndpointAgent._base_manager.filter(
                status='retired', retired_at__lt=now - timedelta(days=RETIRED_AGENT_DAYS)).order_by('retired_at')),
            ('context_lookups', ThreatIntelLookup._base_manager.filter(
                requested_at__lt=now - timedelta(days=CONTEXT_LOOKUP_DAYS)).exclude(status='queued').order_by('requested_at')),
            # Las evidencias de una incidencia se conservan con ella.
            ('evidence', SecurityEvidence._base_manager.filter(observed_at__lt=cutoff,
                                                                incident__isnull=True).order_by('observed_at'))):
        result[name], done = _prune(queryset, deadline)
        if not done:
            result['pending'] = True  # sigue en la próxima ejecución
            break
    with transaction.atomic():
        WorkerState.reserve('retention')
        WorkerState.objects.filter(name='retention').update(details=result, last_run_at=now, last_success_at=now)
    return result

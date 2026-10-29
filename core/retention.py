"""Conservación de datos operativos: borra por bloques lo que ha superado su plazo.

Lo ejecuta cada hora el trabajo `housekeeping`, sin depender de las copias. Antes solo se limpiaba
al final de una copia correcta: con varios días de copias fallidas la base crecía sin límite, y con
ella el espacio que necesita la copia siguiente.

Cada bloque es una transacción corta: en SQLite, un DELETE de cientos de miles de filas retenía el
escritor y bloqueaba la recepción de eventos y el portal. Si se agota el tiempo, sigue en la
próxima hora. Primero lo pequeño (intentos de acceso, contadores por hora) y después las detecciones.
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
    for name, queryset in (
            ('auth_attempts', AuthAttempt._base_manager.filter(
                occurred_at__lt=now - timedelta(days=AUTH_ATTEMPT_DAYS)).order_by('occurred_at')),
            ('feed_buckets', FeedBucket._base_manager.filter(hour__lt=cutoff).order_by()),
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

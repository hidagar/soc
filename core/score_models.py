"""Índice de seguridad de cada cliente: una foto diaria para ver su evolución."""
from django.db import models
from django.utils import timezone

from .scope import ScopedManager


class SecurityScore(models.Model):
    """Resultado del índice (0–100) de un cliente en un día. Se actualiza durante el día y queda fijo después.

    `factors` es la proyección para el cliente: estado y puntos de cada factor, en texto claro, sin
    datos internos del SOC (invariante 3).
    """
    client = models.ForeignKey('core.Client', on_delete=models.CASCADE, related_name='security_scores')
    day = models.DateField()
    score = models.PositiveSmallIntegerField(null=True)
    level = models.CharField(max_length=12, blank=True)
    factors = models.JSONField(default=list, blank=True)
    computed_at = models.DateTimeField(default=timezone.now)
    objects = ScopedManager()
    customer_lookup = 'client_id'

    class Meta:
        ordering = ['-day']
        constraints = [models.UniqueConstraint(fields=['client', 'day'], name='unique_security_score_day')]

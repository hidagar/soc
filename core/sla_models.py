"""Plazos de atención (SLA) de las incidencias: activación y objetivos por gravedad, globales o por cliente."""
from django.db import models
from django.db.models import Q

SEVERITIES = (('critical', 'Crítica'), ('high', 'Alta'), ('medium', 'Media'), ('low', 'Baja'))


class SlaSettings(models.Model):
    """Fila única (pk=1). Solo cuentan los casos creados desde `enabled_at`: activar los plazos no
    convierte en vencidos los casos que ya estaban abiertos."""
    enabled = models.BooleanField(default=False)
    enabled_at = models.DateTimeField(null=True, blank=True)


class SlaPolicy(models.Model):
    """Objetivos en minutos desde que el caso entra en el SOC. Sin cliente: valor global de esa gravedad."""
    client = models.ForeignKey('core.Client', null=True, blank=True, on_delete=models.CASCADE, related_name='sla_policies')
    severity = models.CharField(max_length=12, choices=SEVERITIES)
    acknowledge_minutes = models.PositiveIntegerField()
    investigate_minutes = models.PositiveIntegerField()
    resolve_minutes = models.PositiveIntegerField()
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=['severity'], condition=Q(client=None), name='unique_global_sla'),
                       models.UniqueConstraint(fields=['client', 'severity'], name='unique_client_sla')]

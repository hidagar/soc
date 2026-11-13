"""Plazos de atención (SLA) de las incidencias: activación y objetivos por gravedad, globales o por cliente."""
import datetime

from django.db import models
from django.db.models import Q

SEVERITIES = (('critical', 'Crítica'), ('high', 'Alta'), ('medium', 'Media'), ('low', 'Baja'))


class SlaSettings(models.Model):
    """Fila única (pk=1). Solo cuentan los casos creados desde `enabled_at`: activar los plazos no
    convierte en vencidos los casos que ya estaban abiertos."""
    enabled = models.BooleanField(default=False)
    enabled_at = models.DateTimeField(null=True, blank=True)
    # Solicitudes de clientes: plazos de primera respuesta y de resolución, normales y urgentes (minutos).
    requests_enabled = models.BooleanField(default=False)
    requests_enabled_at = models.DateTimeField(null=True, blank=True)
    requests_visible = models.BooleanField(default=False)  # enseñar al cliente el plazo de primera respuesta
    request_response_minutes = models.PositiveIntegerField(default=8 * 60)
    request_resolve_minutes = models.PositiveIntegerField(default=5 * 24 * 60)
    request_urgent_response_minutes = models.PositiveIntegerField(default=60)
    request_urgent_resolve_minutes = models.PositiveIntegerField(default=24 * 60)
    # Horario laboral: los plazos solo corren dentro de la jornada (ver core/business_hours.py).
    business_hours_enabled = models.BooleanField(default=False)
    business_days = models.CharField(max_length=20, default='0,1,2,3,4')  # lunes = 0
    business_start = models.TimeField(default=datetime.time(8, 0))
    business_end = models.TimeField(default=datetime.time(18, 0))
    business_holidays = models.JSONField(default=list, blank=True)  # fechas ISO
    business_urgent_requests = models.BooleanField(default=False)  # también las solicitudes urgentes
    business_minor_incidents = models.BooleanField(default=False)  # incidencias de gravedad media y baja
    # Pausar la resolución de una incidencia mientras el cliente tiene una actuación pendiente de su parte.
    pause_incidents_waiting = models.BooleanField(default=False)


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

"""Equipos de los clientes con agente Wazuh (PC y servidores) y las detecciones de su antivirus (Defender)."""
from django.conf import settings
from django.db import models
from django.utils import timezone

from .scope import ScopedManager


class EndpointAgent(models.Model):
    """Agente Wazuh de un PC o servidor de un cliente.

    Se descubre al llegar sus eventos («sin asignar», sin cliente) y el SOC lo asigna a un cliente. La
    pertenencia empieza en `assigned_at`: los eventos anteriores no se atribuyen a nadie (invariante 2).
    Retirarlo cierra el registro (`retired_at`); si el mismo identificador vuelve, es un registro nuevo.
    El estado del antivirus sale de sus eventos de Defender (informe de salud 1151 y cambios de protección).
    """
    STATUSES = [('pending', 'Sin asignar'), ('assigned', 'Asignado'), ('retired', 'Retirado')]
    agent_id = models.CharField(max_length=16, db_index=True)
    name = models.CharField(max_length=120)
    ip = models.GenericIPAddressField(null=True, blank=True)
    status = models.CharField(max_length=10, choices=STATUSES, default='pending', db_index=True)
    client = models.ForeignKey('core.Client', on_delete=models.CASCADE, null=True, blank=True, related_name='endpoints')
    site = models.ForeignKey('core.Site', on_delete=models.SET_NULL, null=True, blank=True, related_name='endpoints')
    assigned_at = models.DateTimeField(null=True, blank=True)
    assigned_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='+')
    retired_at = models.DateTimeField(null=True, blank=True)
    first_seen_at = models.DateTimeField(default=timezone.now)
    last_seen_at = models.DateTimeField(default=timezone.now)
    # Antivirus (Microsoft Defender), según sus eventos.
    defender_seen_at = models.DateTimeField(null=True, blank=True)
    health_at = models.DateTimeField(null=True, blank=True)  # último informe de salud (1151)
    realtime_enabled = models.BooleanField(null=True, blank=True)
    realtime_changed_at = models.DateTimeField(null=True, blank=True)
    scanning_disabled_at = models.DateTimeField(null=True, blank=True)
    signature_age_days = models.PositiveIntegerField(null=True, blank=True)
    signature_version = models.CharField(max_length=40, blank=True)
    quick_scan_age_days = models.PositiveIntegerField(null=True, blank=True)
    update_failed_at = models.DateTimeField(null=True, blank=True)
    objects = ScopedManager()
    customer_lookup = 'client_id'

    class Meta:
        ordering = ['name', 'agent_id']
        constraints = [models.UniqueConstraint(fields=['agent_id'], condition=models.Q(retired_at__isnull=True),
                                               name='unique_current_endpoint_agent')]


class EndpointDetection(models.Model):
    """Detección del antivirus de un equipo (Defender 1116/1006 y sus acciones 1117/1007, 1118/1119/1008).

    La detección y la acción posterior se unen por el identificador de detección de Defender. `action`
    queda «detectada» mientras no haya evidencia de lo que hizo el antivirus (invariante 4): una detección
    contenida no prueba que no hubiera ejecución previa, y una sin acción no prueba compromiso.
    """
    ACTIONS = [('detected', 'Detectada, sin acción confirmada'), ('contained', 'Contenida (cuarentena o eliminación)'),
               ('allowed', 'Permitida por el usuario o una exclusión'), ('failed', 'El antivirus no pudo actuar')]
    REVIEW = [('pending', 'Por revisar'), ('reviewed', 'Revisada'), ('incident', 'Incidencia abierta')]
    agent = models.ForeignKey(EndpointAgent, on_delete=models.CASCADE, related_name='detections')
    client_scope_id = models.PositiveBigIntegerField(db_index=True, editable=False)  # cliente al observarla
    detection_key = models.CharField(max_length=80)
    observed_at = models.DateTimeField(db_index=True)
    updated_at = models.DateTimeField(default=timezone.now)
    threat = models.CharField(max_length=200)
    severity = models.CharField(max_length=40, blank=True)
    category = models.CharField(max_length=80, blank=True)
    action = models.CharField(max_length=12, choices=ACTIONS, default='detected')
    action_name = models.CharField(max_length=80, blank=True)  # literal de Defender (Quarantine, Remove, Allow…)
    path = models.CharField(max_length=400, blank=True)  # dato interno: nunca se publica al cliente
    process = models.CharField(max_length=260, blank=True)
    user = models.CharField(max_length=120, blank=True)
    review = models.CharField(max_length=10, choices=REVIEW, default='pending', db_index=True)
    reviewed_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='+')
    reviewed_at = models.DateTimeField(null=True, blank=True)
    incident = models.ForeignKey('core.Incident', on_delete=models.SET_NULL, null=True, blank=True, related_name='+')
    objects = ScopedManager()
    customer_lookup = 'client_scope_id'

    class Meta:
        ordering = ['-observed_at', '-pk']
        constraints = [models.UniqueConstraint(fields=['agent', 'detection_key'], name='unique_endpoint_detection')]

    @property
    def urgent(self):
        return self.action in ('allowed', 'failed')

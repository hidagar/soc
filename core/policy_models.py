"""Políticas de firewall propuestas por el SOC a cada cliente, con su aprobación y verificación."""
from django.conf import settings
from django.db import models
from django.utils import timezone

from .scope import ScopedManager


class PolicyProposal(models.Model):
    """Un cambio de política que el SOC propone a partir de la configuración y de las detecciones.

    Ciclo: el motor la crea («proposed») → el SOC la descarta o la ofrece al cliente con una ventana
    («offered») → el cliente la aprueba o la rechaza en su portal → el SOC la aplica («applied») → el
    trabajo comprueba si ha tenido efecto («verified» o «not_effective»). Nada se aplica sin aprobación
    del cliente, y la evidencia que ve el cliente se congela al ofrecérsela (`customer_summary`).
    """
    KINDS = [('restrict_service', 'Restringir un servicio publicado'), ('geo_filter', 'Filtrar por país un servicio publicado'),
             ('ips_block', 'IPS en modo bloqueo'), ('outbound_c2', 'Bloquear la salida hacia malware y control remoto'),
             ('inbound_blocklist', 'Bloquear atacantes conocidos')]
    STATUSES = [('proposed', 'Propuesta del motor'), ('dismissed', 'Descartada por el SOC'), ('obsolete', 'Ya no aplica'),
                ('offered', 'Pendiente del cliente'), ('approved', 'Aprobada por el cliente'), ('rejected', 'Rechazada por el cliente'),
                ('applied', 'Aplicada, en verificación'), ('verified', 'Verificada'), ('not_effective', 'Sin efecto comprobado')]
    CONFIDENCE = [('high', 'Alta'), ('medium', 'Media'), ('low', 'Baja')]
    NOTICE = [('', 'Sin aviso'), ('queued', 'En cola'), ('sending', 'Enviando'), ('accepted', 'Aceptado por SendGrid'),
              ('failed', 'No enviado'), ('uncertain', 'Por comprobar'), ('skipped', 'Ya no aplica')]

    client = models.ForeignKey('core.Client', on_delete=models.CASCADE, related_name='policy_proposals')
    device = models.ForeignKey('core.Device', on_delete=models.CASCADE, null=True, blank=True, related_name='policy_proposals')
    exposure = models.ForeignKey('core.ExposureFinding', on_delete=models.SET_NULL, null=True, blank=True, related_name='policy_proposals')
    kind = models.CharField(max_length=24, choices=KINDS)
    key = models.CharField(max_length=160)  # qué cubre: no se duplica para el mismo cliente
    status = models.CharField(max_length=16, choices=STATUSES, default='proposed', db_index=True)
    confidence = models.CharField(max_length=8, choices=CONFIDENCE, default='medium')
    title = models.CharField(max_length=220)
    evidence = models.JSONField(default=dict)  # cifras del motor (uso interno)
    change = models.TextField()  # qué se cambia, con pasos para el fabricante
    risk = models.TextField()  # qué podría dejar de funcionar
    customer_title = models.CharField('Título para el cliente', max_length=220, blank=True)
    customer_text = models.TextField('Explicación para el cliente', blank=True, max_length=3000)
    customer_summary = models.JSONField(default=dict, blank=True)  # cifras congeladas al ofrecerla
    planned_for = models.DateTimeField('Ventana propuesta', null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)
    evaluated_at = models.DateTimeField(default=timezone.now)
    offered_at = models.DateTimeField(null=True, blank=True)
    offered_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='+')
    decided_at = models.DateTimeField(null=True, blank=True)
    decided_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='+')
    decision_note = models.TextField(blank=True, max_length=2000)
    applied_at = models.DateTimeField(null=True, blank=True)
    applied_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='+')
    applied_note = models.CharField(max_length=500, blank=True)
    change_plan = models.ForeignKey('core.ChangePlan', on_delete=models.SET_NULL, null=True, blank=True, related_name='+')
    verified_at = models.DateTimeField(null=True, blank=True)
    verification = models.JSONField(default=dict, blank=True)
    dismissed_reason = models.CharField(max_length=240, blank=True)
    notice_status = models.CharField(max_length=16, choices=NOTICE, blank=True)
    notice_recipient = models.EmailField(blank=True)
    notice_error = models.CharField(max_length=240, blank=True)
    notice_attempted_at = models.DateTimeField(null=True, blank=True)
    notice_sent_at = models.DateTimeField(null=True, blank=True)
    provider_id = models.CharField(max_length=180, blank=True)
    soc_notified_at = models.DateTimeField(null=True, blank=True)  # aviso interno de la decisión del cliente
    objects = ScopedManager()
    customer_lookup = 'client_id'

    class Meta:
        ordering = ['-updated_at', '-pk']
        constraints = [models.UniqueConstraint(fields=['client', 'key'], name='policy_proposal_client_key')]

    @property
    def reference(self):
        return f'POL-{self.pk:05d}'

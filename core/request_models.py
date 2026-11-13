"""Solicitudes del cliente al SOC desde el portal: consultas, cambios, desbloqueos y sospechas."""
from django.conf import settings
from django.db import models
from django.utils import timezone

from .scope import ScopedManager


class CustomerRequest(models.Model):
    KINDS = [('question', 'Consulta'), ('change', 'Cambio en el firewall o la red'),
             ('unblock', 'Algo está bloqueado y lo necesitamos'), ('incident', 'Sospecha de incidente de seguridad')]
    STATUSES = [('new', 'Recibida'), ('in_progress', 'En curso'), ('waiting', 'Esperando vuestra respuesta'),
                ('resolved', 'Resuelta')]
    client = models.ForeignKey('core.Client', on_delete=models.CASCADE, related_name='requests')
    site = models.ForeignKey('core.Site', on_delete=models.SET_NULL, null=True, blank=True, related_name='requests')
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='+')
    contact_email = models.EmailField(blank=True)  # quien la abrió: recibe los avisos de respuesta
    kind = models.CharField('Tipo', max_length=16, choices=KINDS)
    subject = models.CharField('Asunto', max_length=160)
    urgent = models.BooleanField('Afecta al trabajo ahora', default=False)
    status = models.CharField(max_length=16, choices=STATUSES, default='new', db_index=True)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='+')
    incident = models.ForeignKey('core.Incident', on_delete=models.SET_NULL, null=True, blank=True, related_name='customer_requests')
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)
    first_response_at = models.DateTimeField(null=True, blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    soc_notified_at = models.DateTimeField(null=True, blank=True)  # aviso interno al equipo SOC (como mucho una vez)
    # Plazos: el tiempo esperando al cliente no cuenta para la resolución.
    waiting_since = models.DateTimeField(null=True, blank=True)
    waited_seconds = models.PositiveIntegerField(default=0)
    sla_breaches = models.JSONField(default=dict, blank=True, editable=False)
    objects = ScopedManager()
    customer_lookup = 'client_id'

    class Meta:
        ordering = ['-updated_at', '-pk']

    @property
    def reference(self):
        return f'SOL-{self.pk:05d}'

    @property
    def open(self):
        return self.status != 'resolved'


class CustomerRequestEntry(models.Model):
    """Un mensaje de la conversación. Las notas internas del SOC nunca se muestran al cliente (invariante 3).

    Cada respuesta del SOC visible para el cliente genera un aviso por correo, sin el texto: enlaza al portal.
    """
    KINDS = [('customer', 'Cliente'), ('soc', 'SOC'), ('internal', 'Nota interna del SOC')]
    NOTICE = [('', 'Sin aviso'), ('queued', 'En cola'), ('sending', 'Enviando'), ('accepted', 'Aceptado por SendGrid'),
              ('failed', 'No enviado'), ('uncertain', 'Por comprobar'), ('skipped', 'Ya no aplica')]
    request = models.ForeignKey(CustomerRequest, on_delete=models.CASCADE, related_name='entries')
    kind = models.CharField(max_length=16, choices=KINDS)
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='+')
    text = models.TextField()
    status = models.CharField(max_length=16, blank=True)  # estado en el que quedó la solicitud
    created_at = models.DateTimeField(default=timezone.now)
    notice_status = models.CharField(max_length=16, choices=NOTICE, blank=True)
    notice_error = models.CharField(max_length=240, blank=True)
    notice_attempted_at = models.DateTimeField(null=True, blank=True)
    notice_sent_at = models.DateTimeField(null=True, blank=True)
    provider_id = models.CharField(max_length=180, blank=True)
    objects = ScopedManager()
    customer_lookup = 'request__client_id'

    class Meta:
        ordering = ['created_at', 'pk']

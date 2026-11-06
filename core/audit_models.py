"""Anclas externas de la cadena de auditoría (bloque 8)."""
from django.db import models
from django.utils import timezone


class AuditAnchor(models.Model):
    """Huella del último evento de auditoría enviada fuera de la VM (correo).

    La cadena HMAC detecta cambios internos, pero no que se borre su final. Con el ancla enviada, el
    SOC comprueba que el evento anclado sigue existiendo con la misma huella y el mismo número de
    eventos hasta él. Si se borran también las anclas de la base, el correo permite comprobarlo a mano.
    """
    STATUSES = [('queued', 'En cola'), ('accepted', 'Aceptada por SendGrid'), ('failed', 'No enviada'),
                ('uncertain', 'Por comprobar')]
    created_at = models.DateTimeField(default=timezone.now)
    event_id = models.PositiveBigIntegerField()
    digest = models.CharField(max_length=64)
    event_count = models.PositiveBigIntegerField()
    recipient = models.EmailField(blank=True)
    status = models.CharField(max_length=12, choices=STATUSES, default='queued')
    error = models.CharField(max_length=240, blank=True)
    provider_id = models.CharField(max_length=180, blank=True)

    class Meta:
        ordering = ['-created_at', '-pk']

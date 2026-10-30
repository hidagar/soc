"""Bandeja de salida de los avisos al cliente sobre sus actuaciones del portal (hoja de ruta 6)."""
from django.db import models
from django.utils import timezone

from .scope import ScopedManager


class CustomerNotice(models.Model):
    """Un aviso por cambio de una actuación. Se envía desde el trabajo de avisos operativos; un resultado
    dudoso no se reintenta solo (invariante 6): queda «por comprobar» para que el SOC decida."""
    KINDS = [('assigned', 'Nueva actuación'), ('rework', 'Actuación devuelta'), ('accepted', 'Actuación validada')]
    STATUSES = [('queued', 'En cola'), ('sending', 'Enviando'), ('accepted', 'Aceptado por SendGrid'),
                ('failed', 'No enviado'), ('uncertain', 'Por comprobar'), ('skipped', 'Ya no aplica')]
    client = models.ForeignKey('core.Client', on_delete=models.CASCADE, related_name='notices')
    task = models.ForeignKey('core.CustomerTask', on_delete=models.CASCADE, related_name='notices')
    kind = models.CharField(max_length=16, choices=KINDS)
    recipient = models.EmailField()
    status = models.CharField(max_length=16, choices=STATUSES, default='queued')
    error = models.CharField(max_length=240, blank=True)
    provider_id = models.CharField(max_length=180, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    attempted_at = models.DateTimeField(null=True)
    sent_at = models.DateTimeField(null=True)
    objects = ScopedManager()
    customer_lookup = 'client_id'

    class Meta:
        ordering = ['-created_at', '-pk']

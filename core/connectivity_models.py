"""Caídas de conexión notificadas por los firewalls de cada sede."""
from django.db import models

from .scope import ScopedManager


class ConnectivityEvent(models.Model):
    """Una caída notificada por el propio firewall (hoy, UniFi). No incluye su duración: el fabricante
    no envía la recuperación, así que no se calcula un porcentaje de disponibilidad."""
    KINDS = [('internet_down', 'Caída de Internet'), ('repeated', 'Desconexiones repetidas de Internet'),
             ('device_offline', 'Equipo de red desconectado')]
    client = models.ForeignKey('core.Client', on_delete=models.CASCADE, related_name='connectivity_events')
    device = models.ForeignKey('core.Device', on_delete=models.SET_NULL, null=True, blank=True, related_name='connectivity_events')
    kind = models.CharField(max_length=16, choices=KINDS)
    observed_at = models.DateTimeField(db_index=True)
    event_key = models.CharField(max_length=64, unique=True)  # índice + id de Wazuh, resumidos: no se cuenta dos veces
    objects = ScopedManager()
    customer_lookup = 'client_id'

    class Meta:
        ordering = ['-observed_at']

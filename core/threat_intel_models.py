"""Inteligencia de amenazas descargada (Q-Feeds): copia local de las listas y coincidencias con los clientes."""
from django.db import models
from django.utils import timezone

from .scope import ScopedManager


class ThreatIndicator(models.Model):
    """Indicador de una lista descargada. Dato global, sin cliente: solo lo ve el equipo SOC.

    La tabla se sustituye con cada descarga (las entradas que desaparecen de la lista se borran) y no se
    usa si la última comprobación correcta es antigua: ver `threat_intel.usable`.
    """
    KINDS = [('ip', 'IP'), ('net', 'Red'), ('domain', 'Dominio')]
    feed = models.CharField(max_length=32)
    kind = models.CharField(max_length=8, choices=KINDS)
    value = models.CharField(max_length=253, db_index=True)
    categories = models.JSONField(default=list, blank=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=['feed', 'value'], name='unique_threat_indicator')]
        indexes = [models.Index(fields=['kind', 'value'], name='threat_indicator_kind_idx')]


class ThreatIntelMatch(models.Model):
    """IP pública de las detecciones de un cliente (7 días) que figura en una lista descargada.

    `role` indica de qué lado estaba: «source» (origen que entra) o «destination» (destino al que se
    conecta un equipo del cliente). Es contexto para investigar: no acredita ataque ni compromiso.
    """
    ROLES = [('source', 'Origen (entrante)'), ('destination', 'Destino (saliente)')]
    client = models.ForeignKey('core.Client', on_delete=models.CASCADE, related_name='threat_matches')
    ip = models.GenericIPAddressField()
    role = models.CharField(max_length=12, choices=ROLES)
    feeds = models.JSONField(default=list, blank=True)
    categories = models.JSONField(default=list, blank=True)
    events = models.PositiveIntegerField(default=0)
    allowed = models.PositiveIntegerField(default=0)
    first_seen = models.DateTimeField()
    last_seen = models.DateTimeField()
    peers = models.JSONField(default=list, blank=True)  # hasta 3 IPs internas implicadas (solo destinos)
    crowdsec_listed = models.BooleanField(default=False)
    updated_at = models.DateTimeField(default=timezone.now)
    objects = ScopedManager()
    customer_lookup = 'client_id'

    class Meta:
        ordering = ['-allowed', '-events', 'ip']
        constraints = [models.UniqueConstraint(fields=['client', 'ip', 'role'], name='unique_threat_match')]

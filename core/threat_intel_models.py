"""Inteligencia de amenazas descargada (Q-Feeds): copia local de las listas y coincidencias con los clientes."""
from django.conf import settings
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


class ThreatIntelReview(models.Model):
    """Decisión del SOC sobre un destino saliente de un cliente que figura en las listas (plan A de Q-Feeds).

    `ThreatIntelMatch` se recalcula entero en cada ejecución; la decisión se guarda aparte para no perderla.
    Vuelve a la cola si aparece tráfico hacia ese destino después de la decisión (descartado) o después de
    resolver la incidencia abierta. Dato interno del SOC: el cliente solo ve lo que se publique de la incidencia.
    """
    DECISIONS = [('dismissed', 'Sin riesgo'), ('incident', 'Incidencia abierta')]
    client = models.ForeignKey('core.Client', on_delete=models.CASCADE, related_name='threat_reviews')
    ip = models.GenericIPAddressField()
    decision = models.CharField(max_length=12, choices=DECISIONS)
    reason = models.CharField(max_length=160, blank=True)
    incident = models.ForeignKey('core.Incident', on_delete=models.SET_NULL, null=True, blank=True, related_name='+')
    reviewed_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='+')
    reviewed_at = models.DateTimeField(default=timezone.now)
    objects = ScopedManager()
    customer_lookup = 'client_id'

    class Meta:
        constraints = [models.UniqueConstraint(fields=['client', 'ip'], name='unique_threat_review')]


class QFeedsLicense(models.Model):
    """Plan B de Q-Feeds: licencia del propio cliente para un firewall OPNsense, vendida por ib-red.

    El titular de la licencia es el cliente (EULA de Q-Feeds: uso interno del usuario final); el SOC guarda
    la clave cifrada para configurarla en el plugin oficial con el control de cambios y vigila su caducidad.
    La clave nunca se muestra ni se registra. `plugin_status` guarda la última lectura del plugin (sin la clave).
    """
    PLANS = [('plus', 'Plus'), ('premium', 'Premium')]
    BANDS = [('lt50', 'Menos de 50 usuarios'), ('50_250', '50 a 250'), ('250_1000', '250 a 1000'), ('gt1000', 'Más de 1000')]
    device = models.OneToOneField('core.Device', on_delete=models.CASCADE, related_name='qfeeds_license')
    plan = models.CharField('Plan', max_length=12, choices=PLANS)
    users_band = models.CharField('Usuarios protegidos', max_length=12, choices=BANDS)
    encrypted_key = models.TextField(editable=False)
    key_hint = models.CharField(max_length=8, blank=True, editable=False)  # últimos 4 caracteres, para reconocerla
    starts_on = models.DateField('Inicio')
    expires_on = models.DateField('Caducidad')
    purchase_price = models.DecimalField('Coste anual (€)', max_digits=9, decimal_places=2, null=True, blank=True)
    sale_price = models.DecimalField('Precio al cliente (€)', max_digits=9, decimal_places=2, null=True, blank=True)
    reference = models.CharField('Pedido o factura', max_length=120, blank=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='+')
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    checked_at = models.DateTimeField(null=True, blank=True)
    plugin_status = models.JSONField(default=dict, blank=True)
    # Comprobación de la clave en Q-Feeds (licenses.php, una vez al día): caducidad, listas y si la acepta.
    vendor_status = models.JSONField(default=dict, blank=True)
    vendor_checked_at = models.DateTimeField(null=True, blank=True)
    objects = ScopedManager()
    customer_lookup = 'device__site__client_id'

    class Meta:
        ordering = ['expires_on', 'pk']

    @property
    def margin(self):
        if self.purchase_price is None or self.sale_price is None:
            return None
        return self.sale_price - self.purchase_price


class ThreatIntelLookup(models.Model):
    """Consulta de contexto de un indicador en la API IOC Lookup de Q-Feeds (si la licencia la incluye).

    La web solo la encola; el trabajo protegido `qfeeds_lookup` la envía con la clave del SOC. Solo se admiten
    indicadores que ya figuran en las listas descargadas: a Q-Feeds no se le revela ninguna IP o destino nuevo
    de los clientes. `result` guarda un resumen acotado de la respuesta, nunca la respuesta cruda.
    """
    STATUSES = [('queued', 'En cola'), ('done', 'Hecha'), ('failed', 'Fallida')]
    value = models.CharField(max_length=253, db_index=True)
    status = models.CharField(max_length=12, choices=STATUSES, default='queued')
    matched = models.BooleanField(default=False)
    result = models.JSONField(default=dict, blank=True)
    error = models.CharField(max_length=160, blank=True)
    requested_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='+')
    requested_at = models.DateTimeField(default=timezone.now)
    done_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-requested_at', '-pk']


class SocReputation(models.Model):
    """Reputación propia del SOC: IP pública que ataca a varios clientes (30 días), con su nivel.

    Se recalcula cada hora con las detecciones de todos los clientes. Dato del SOC con acceso global:
    resume ataques a varios clientes, así que solo lo ve quien tiene acceso a todos.
    `flagged_at`/`flagged_clients` guardan cuándo alcanzó un nivel bloqueable y a quién había atacado;
    `later_clients` son los clientes atacados después, la medida de si bloquearla habría protegido a otros.
    """
    LEVELS = [('confirmed', 'Confirmada'), ('own', 'Propia'), ('watch', 'En observación')]
    ip = models.GenericIPAddressField(unique=True)
    level = models.CharField(max_length=12, choices=LEVELS)
    score = models.PositiveIntegerField(default=0)
    clients = models.PositiveIntegerField(default=0)
    strong_clients = models.PositiveIntegerField(default=0)
    days = models.PositiveIntegerField(default=0)
    events = models.PositiveIntegerField(default=0)
    allowed = models.PositiveIntegerField(default=0)
    families = models.JSONField(default=list, blank=True)
    sources = models.JSONField(default=list, blank=True)  # confirmación externa: crowdsec, cti, qfeeds
    note = models.CharField(max_length=120, blank=True)
    first_seen = models.DateTimeField()
    last_seen = models.DateTimeField()
    flagged_at = models.DateTimeField(null=True, blank=True)
    flagged_clients = models.JSONField(default=list, blank=True)
    later_clients = models.JSONField(default=list, blank=True)
    updated_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ['-score', 'ip']

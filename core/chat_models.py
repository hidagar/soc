"""Avisos urgentes también por Microsoft Teams y Telegram (canales de chat del cliente)."""
from django.db import models

from .scope import ScopedManager


class ChatChannel(models.Model):
    """Canal de chat de un cliente para recibir sus avisos urgentes, además del correo.

    Teams: URL de un flujo de Workflows («Publicar en un canal cuando se recibe una solicitud de
    webhook»). La URL lleva su firma y basta para publicar, así que se guarda cifrada y no se muestra.
    Telegram: identificador del grupo; el bot es único para todo el SOC (SOC_PORTAL_TELEGRAM_BOT_TOKEN).
    """
    class Kind(models.TextChoices):
        TEAMS = 'teams', 'Microsoft Teams'
        TELEGRAM = 'telegram', 'Telegram'

    client = models.ForeignKey('core.Client', on_delete=models.CASCADE, related_name='chat_channels')
    kind = models.CharField(max_length=16, choices=Kind.choices)
    enabled = models.BooleanField(default=False)
    # Solo se envían los avisos creados desde la activación: activar no vacía la cola antigua en el chat.
    enabled_at = models.DateTimeField(null=True, blank=True)
    encrypted_target = models.TextField(blank=True)
    chat_id = models.CharField(max_length=64, blank=True)
    label = models.CharField('Nombre del canal o grupo', max_length=120, blank=True)
    last_test_at = models.DateTimeField(null=True, blank=True)
    last_test_ok = models.BooleanField(null=True)
    last_test_error = models.CharField(max_length=250, blank=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = ScopedManager()
    customer_lookup = 'client_id'

    class Meta:
        ordering = ['client', 'kind']
        constraints = [models.UniqueConstraint(fields=['client', 'kind'], name='chat_channel_client_kind')]

    @property
    def configured(self):
        return bool(self.encrypted_target) if self.kind == self.Kind.TEAMS else bool(self.chat_id)


class ChatNotice(models.Model):
    """Un aviso urgente publicado (o intentado) en un canal de chat. Uno por aviso y canal: repetir el
    trabajo no lo vuelve a enviar."""
    class Status(models.TextChoices):
        PENDING = 'pending', 'Pendiente'
        SENDING = 'sending', 'Enviando'
        ACCEPTED = 'accepted', 'Aceptado por Teams'
        DELIVERED = 'delivered', 'Publicado en Telegram'
        SUPPRESSED = 'suppressed', 'Agrupado o desactivado'
        FAILED = 'failed', 'Error de envío'
        UNCERTAIN = 'uncertain', 'Entrega por comprobar'
        EXPIRED = 'expired', 'Fuera de plazo'

    alert = models.ForeignKey('core.UrgentAlert', on_delete=models.CASCADE, related_name='chat_notices')
    channel = models.ForeignKey(ChatChannel, on_delete=models.CASCADE, related_name='notices')
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.PENDING, db_index=True)
    attempts = models.PositiveSmallIntegerField(default=0)
    next_retry_at = models.DateTimeField(null=True, blank=True)
    last_attempt_at = models.DateTimeField(null=True, blank=True)
    sent_at = models.DateTimeField(null=True, blank=True)
    provider_id = models.CharField(max_length=64, blank=True)
    last_error = models.CharField(max_length=250, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    objects = ScopedManager()
    customer_lookup = 'alert__client_id'

    class Meta:
        ordering = ['-created_at']
        constraints = [models.UniqueConstraint(fields=['alert', 'channel'], name='chat_notice_alert_channel')]

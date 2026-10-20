from django.conf import settings
from django.db import models
from django.utils import timezone
from .scope import ScopedManager

class UserInvitation(models.Model):
    user=models.OneToOneField(settings.AUTH_USER_MODEL,on_delete=models.CASCADE,related_name='soc_invitation')
    recipient=models.EmailField()
    token_hash=models.CharField(max_length=64)
    encrypted_token=models.TextField(blank=True)
    created_at=models.DateTimeField(default=timezone.now)
    expires_at=models.DateTimeField()
    accepted_at=models.DateTimeField(null=True)
    sent_at=models.DateTimeField(null=True)
    attempted_at=models.DateTimeField(null=True)
    status=models.CharField(max_length=16,default='queued')
    error=models.CharField(max_length=240,blank=True)
    provider_id=models.CharField(max_length=180,blank=True)
    @property
    def status_label(self):
        if self.accepted_at:return 'Contraseña establecida'
        if self.expires_at<=timezone.now():return 'Enlace caducado'
        return {'queued':'Pendiente de envío','sending':'Enviando','accepted':'Aceptado por SendGrid','failed':'Error de envío; reenviar','uncertain':'Envío sin confirmar; revisar antes de reenviar'}.get(self.status,'Pendiente')

class SecureLogChannel(models.Model):
    import uuid
    id=models.UUIDField(primary_key=True,default=uuid.uuid4,editable=False)
    device=models.OneToOneField('core.Device',on_delete=models.PROTECT,related_name='secure_log_channel')
    client_scope_id=models.PositiveBigIntegerField(editable=False)
    source_identity=models.GenericIPAddressField(unique=True,editable=False)
    token_hash=models.CharField(max_length=64)
    encrypted_token=models.TextField()
    enabled=models.BooleanField(default=True)
    receiver_ready=models.BooleanField(default=False)
    created_at=models.DateTimeField(default=timezone.now)
    last_received_at=models.DateTimeField(null=True)
    last_transport_ip=models.GenericIPAddressField(null=True)
    objects=ScopedManager()
    customer_lookup='client_scope_id'
    def save(self,*args,**kwargs):
        if not self._state.adding:
            previous=type(self)._base_manager.filter(pk=self.pk).values_list('client_scope_id',flat=True).first()
            if previous is not None and previous!=self.client_scope_id:raise ValueError('La empresa del canal no puede cambiar.')
        super().save(*args,**kwargs)

class SecureLogReceipt(models.Model):
    channel=models.ForeignKey(SecureLogChannel,on_delete=models.CASCADE)
    batch_id=models.UUIDField()
    digest=models.CharField(max_length=64)
    received_at=models.DateTimeField(default=timezone.now,db_index=True)
    bytes_count=models.PositiveIntegerField()
    messages_count=models.PositiveIntegerField()
    # Existing receipts prove only the old UDP attempt, never durable payload storage.
    status=models.CharField(max_length=16,default='legacy',db_index=True)
    encrypted_payload=models.TextField(blank=True)
    forwarded_count=models.PositiveIntegerField(default=0)
    inflight_index=models.PositiveIntegerField(null=True)
    attempts=models.PositiveIntegerField(default=0)
    attempted_at=models.DateTimeField(null=True)
    next_attempt_at=models.DateTimeField(null=True,db_index=True)
    forwarded_at=models.DateTimeField(null=True)
    error=models.CharField(max_length=240,blank=True)
    transport_version=models.PositiveSmallIntegerField(default=1)
    confirmed_at=models.DateTimeField(null=True)
    @property
    def status_label(self):
        if self.status=='confirmed':return 'Procesado por Wazuh; alertas indexadas'
        if self.transport_version==2 and self.status=='awaiting':return 'Enviado; esperando confirmación de Wazuh'
        return {'legacy':'Recibo anterior; persistencia no acreditada','queued':'Guardado; pendiente de reenvío',
            'delivering':'Reenviando','retry':'Guardado; reintento programado','forwarded':'Reenviado por UDP; Wazuh sin confirmar',
            'uncertain':'Entrega interrumpida; revisar antes de reintentar','failed':'Guardado; requiere revisión'}.get(self.status,'Requiere revisión')
    class Meta:
        constraints=[models.UniqueConstraint(fields=['channel','batch_id'],name='unique_secure_log_batch')]

class SecureLogMessage(models.Model):
    uid=models.CharField(max_length=64,primary_key=True)
    receipt=models.ForeignKey(SecureLogReceipt,on_delete=models.CASCADE,related_name='delivery_messages')
    position=models.PositiveSmallIntegerField()
    frame_digest=models.CharField(max_length=64)
    status=models.CharField(max_length=16,default='queued',db_index=True)
    attempts=models.PositiveSmallIntegerField(default=0)
    sent_at=models.DateTimeField(null=True)
    next_attempt_at=models.DateTimeField(null=True,db_index=True)
    processed_at=models.DateTimeField(null=True)
    indexed_at=models.DateTimeField(null=True)
    projected_at=models.DateTimeField(null=True)
    rule_level=models.PositiveSmallIntegerField(null=True)
    decoder=models.CharField(max_length=120,blank=True)
    encrypted_event=models.TextField(blank=True)
    error=models.CharField(max_length=240,blank=True)
    @property
    def status_label(self):
        if self.indexed_at:return 'Alerta nativa indexada'
        if self.processed_at:return 'Procesado; alerta pendiente de indexar' if self.rule_level>=3 else 'Procesado; sin alerta'
        return {'queued':'Guardado','awaiting':'Esperando recepción nativa','failed':'Requiere revisión'}.get(self.status,'Pendiente')
    class Meta:
        constraints=[models.UniqueConstraint(fields=['receipt','position'],name='unique_secure_log_message_position')]

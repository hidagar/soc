from django.conf import settings
from django.db import models
from django.utils import timezone
from .scope import ScopedManager

class RunbookStep(models.Model):
    incident=models.ForeignKey('core.Incident',on_delete=models.CASCADE,related_name='runbook_steps')
    position=models.PositiveSmallIntegerField()
    title=models.CharField(max_length=220)
    done=models.BooleanField(default=False)
    evidence=models.TextField(blank=True)
    completed_by=models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.SET_NULL,null=True)
    completed_at=models.DateTimeField(null=True)
    objects=ScopedManager();customer_lookup='incident__client_id'
    class Meta:
        ordering=['position','pk']
        constraints=[models.UniqueConstraint(fields=['incident','position'],name='unique_runbook_step')]

class ProtectionValidation(models.Model):
    network=models.ForeignKey('core.NetworkCoverage',on_delete=models.SET_NULL,null=True,blank=True,related_name='validations')
    test_ip=models.GenericIPAddressField(null=True,blank=True)
    network_snapshot=models.JSONField(default=list,blank=True)
    configuration_fingerprint=models.CharField(max_length=64,blank=True)
    device=models.ForeignKey('core.Device',on_delete=models.CASCADE,related_name='validations')
    engine=models.CharField(max_length=16,choices=[('suricata','Suricata'),('zenarmor','Zenarmor'),('clamav','ClamAV'),('unifi','UniFi'),('hillstone','Hillstone: detección de amenaza')])
    networks=models.CharField(max_length=500)
    expected_signature=models.CharField(max_length=240)
    started_at=models.DateTimeField(default=timezone.now)
    expires_at=models.DateTimeField()
    evidence=models.ForeignKey('core.SecurityEvidence',on_delete=models.SET_NULL,null=True,blank=True)
    requested_by=models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.SET_NULL,null=True)
    objects=ScopedManager();customer_lookup='device__site__client_id'
    class Meta:ordering=['-started_at']

class ZenarmorExportRequest(models.Model):
    device=models.OneToOneField('core.Device',on_delete=models.CASCADE,related_name='zenarmor_export_request')
    status=models.CharField(max_length=24,default='queued')
    requested_at=models.DateTimeField(default=timezone.now)
    checked_at=models.DateTimeField(null=True)
    confirmed_at=models.DateTimeField(null=True)
    requested_by=models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.SET_NULL,null=True)
    note=models.TextField(blank=True)
    encrypted_previous=models.TextField(blank=True)
    objects=ScopedManager();customer_lookup='device__site__client_id'
    @property
    def status_label(self):
        return {'queued':'Pendiente de comprobar','waiting_license':'Esperando licencia compatible','configured':'Configuración confirmada; validar recepción','error':'Requiere revisión'}.get(self.status,'Sin comprobar')

class CustomerTask(models.Model):
    incident=models.ForeignKey('core.Incident',on_delete=models.PROTECT,related_name='customer_tasks')
    action=models.OneToOneField('core.IncidentAction',on_delete=models.SET_NULL,null=True,blank=True,related_name='customer_task')
    title=models.CharField('Título para el cliente',max_length=220)
    instructions=models.TextField('Pasos que debe realizar el cliente')
    due_at=models.DateTimeField('Fecha acordada',null=True,blank=True)
    visible=models.BooleanField('Publicar en el portal del cliente',default=False)
    status=models.CharField('Estado',max_length=16,choices=[('pending','Pendiente'),('submitted','Respuesta recibida'),('accepted','Validada por el SOC'),('rework','Requiere más información'),('cancelled','Cancelada por el SOC')],default='pending')
    response=models.TextField(blank=True)
    submitted_at=models.DateTimeField(null=True)
    reviewed_by=models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.SET_NULL,null=True)
    review_note=models.TextField('Respuesta del SOC para el cliente',blank=True)
    reviewed_at=models.DateTimeField(null=True)
    updated_at=models.DateTimeField(auto_now=True)
    objects=ScopedManager();customer_lookup='incident__client_id'
    class Meta:ordering=['due_at','pk']

class CustomerTaskEntry(models.Model):
    """Historial completo de la conversación de una tarea: cada respuesta y cada revisión.

    CustomerTask.response y review_note conservan solo la última; este registro no se edita.
    """
    task=models.ForeignKey(CustomerTask,on_delete=models.CASCADE,related_name='entries')
    kind=models.CharField(max_length=16,choices=[('response','Respuesta del cliente'),('review','Revisión del SOC')])
    status=models.CharField(max_length=16)
    text=models.TextField()
    author=models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.SET_NULL,null=True)
    created_at=models.DateTimeField(default=timezone.now)
    objects=ScopedManager();customer_lookup='task__incident__client_id'
    class Meta:ordering=['created_at','pk']

class DeliverySettings(models.Model):
    public_key=models.TextField('Clave pública de verificación de SendGrid',blank=True)
    enabled=models.BooleanField('Recibir eventos firmados de SendGrid',default=False)
    ack_minutes=models.PositiveIntegerField('Minutos para recordar avisos urgentes sin atender',default=30)
    last_signed_at=models.DateTimeField(null=True,blank=True)
    last_matched_at=models.DateTimeField(null=True,blank=True)

class AdvancedReview(models.Model):
    device=models.ForeignKey('core.Device',on_delete=models.CASCADE,related_name='advanced_reviews')
    note=models.TextField('Qué se revisó y resultado',max_length=2000)
    valid_until=models.DateTimeField('Revisar de nuevo antes de')
    baseline=models.CharField(max_length=64)
    created_at=models.DateTimeField(default=timezone.now)
    reviewed_by=models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.SET_NULL,null=True)
    objects=ScopedManager();customer_lookup='device__site__client_id'

class MailDispatch(models.Model):
    token=models.UUIDField(unique=True,editable=False)
    client=models.ForeignKey('core.Client',on_delete=models.CASCADE,null=True,blank=True)
    report=models.ForeignKey('core.WeeklyReport',on_delete=models.SET_NULL,null=True,blank=True)
    urgent=models.ForeignKey('core.UrgentAlert',on_delete=models.SET_NULL,null=True,blank=True)
    recipient=models.EmailField()
    kind=models.CharField(max_length=16,default='other')
    provider_id=models.CharField(max_length=180,blank=True)
    status=models.CharField(max_length=16,default='sending')
    event_at=models.DateTimeField(null=True)
    created_at=models.DateTimeField(default=timezone.now)
    objects=ScopedManager();customer_lookup='client_id'
    class Meta:ordering=['-created_at']
    @property
    def status_label(self):
        return {'sending':'En proceso','accepted':'Aceptado por SendGrid; entrega sin confirmar','processed':'Procesado por SendGrid','delivered':'Entregado al servidor de correo','deferred':'Entrega aplazada','bounce':'Rebotado','dropped':'Descartado por SendGrid','failed':'Solicitud fallida','uncertain':'Resultado por comprobar'}.get(self.status,'Sin confirmar')

class MailEvent(models.Model):
    event_hash=models.CharField(max_length=64,unique=True)
    dispatch=models.ForeignKey(MailDispatch,on_delete=models.CASCADE,related_name='events')
    kind=models.CharField(max_length=16)
    occurred_at=models.DateTimeField()
    objects=ScopedManager();customer_lookup='dispatch__client_id'
    class Meta:ordering=['occurred_at','pk']
    @property
    def label(self):
        return {'processed':'Procesado','delivered':'Entregado al servidor','deferred':'Aplazado','bounce':'Rebotado','dropped':'Descartado'}.get(self.kind,'Sin confirmar')

class ConfigurationArchive(models.Model):
    reviewed_at=models.DateTimeField(null=True,blank=True)
    reviewed_by=models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.SET_NULL,null=True,blank=True)
    review_note=models.TextField(blank=True)
    device=models.ForeignKey('core.Device',on_delete=models.CASCADE,related_name='configuration_archives')
    created_at=models.DateTimeField(default=timezone.now)
    status=models.CharField(max_length=16)
    kind=models.CharField(max_length=24,default='opnsense_full')
    sha256=models.CharField(max_length=64,blank=True)
    summary=models.JSONField(default=dict)
    changes=models.JSONField(default=list)
    note=models.CharField(max_length=250,blank=True)
    objects=ScopedManager();customer_lookup='device__site__client_id'
    class Meta:ordering=['-created_at']

class ReportVersion(models.Model):
    """Versión publicada de un informe semanal: HTML y PDF tal como los recibió el cliente.

    Se crea al enviar el informe o al mostrarlo por primera vez al cliente, y no se edita.
    Una rectificación añade la versión siguiente con su motivo y conserva las anteriores.
    """
    report=models.ForeignKey('core.WeeklyReport',on_delete=models.CASCADE,related_name='versions')
    number=models.PositiveIntegerField()
    html=models.TextField()
    pdf=models.BinaryField()
    html_sha256=models.CharField(max_length=64)
    pdf_sha256=models.CharField(max_length=64)
    reason=models.TextField(blank=True)
    created_by=models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.SET_NULL,null=True)
    created_at=models.DateTimeField(default=timezone.now)
    objects=ScopedManager();customer_lookup='report__client_id'
    class Meta:
        ordering=['report','number']
        constraints=[models.UniqueConstraint(fields=['report','number'],name='unique_report_version_number')]

class IpReputation(models.Model):
    """Reputación CrowdSec de una IP pública externa (contexto, no detección).

    Dato global de la IP, sin cliente: se consulta solo para orígenes de tráfico entrante y
    solo lo ve el equipo SOC. Dos fuentes con su propia fecha y caducidad:
    - listas del motor local (gratuitas): `listed` y siguientes; None = sin comprobar;
    - API CTI (de pago): `cti_found` y los campos de reputación; None = sin consultar.
    `fetched_at` es la última actualización de cualquiera de las dos.
    """
    ip=models.GenericIPAddressField(unique=True)
    listed=models.BooleanField(null=True)
    list_origins=models.JSONField(default=list,blank=True)
    list_scenarios=models.JSONField(default=list,blank=True)
    listed_range=models.CharField(max_length=64,blank=True)
    lists_checked_at=models.DateTimeField(null=True,blank=True)
    lists_expires_at=models.DateTimeField(null=True,blank=True)
    cti_found=models.BooleanField(null=True)
    reputation=models.CharField(max_length=16,blank=True)
    confidence=models.CharField(max_length=16,blank=True)
    background_noise=models.CharField(max_length=16,blank=True)
    background_noise_score=models.PositiveSmallIntegerField(null=True)
    scores=models.JSONField(default=dict,blank=True)
    behaviors=models.JSONField(default=list,blank=True)
    classifications=models.JSONField(default=list,blank=True)
    false_positives=models.JSONField(default=list,blank=True)
    as_name=models.CharField(max_length=200,blank=True)
    country=models.CharField(max_length=2,blank=True)
    first_seen=models.CharField(max_length=40,blank=True)
    last_seen=models.CharField(max_length=40,blank=True)
    cti_checked_at=models.DateTimeField(null=True,blank=True)
    cti_expires_at=models.DateTimeField(null=True,blank=True)
    fetched_at=models.DateTimeField(default=timezone.now)

class BlocklistFeed(models.Model):
    """Lista de bloqueo del SOC para un cliente (hoja de ruta 7A/C2), servida a sus firewalls.

    El trabajo `blocklists` la calcula a partir de la reputación CrowdSec de orígenes que han
    atacado a algún cliente; el firewall la descarga con un token propio. `stopped` es el
    freno de emergencia: la URL sirve una lista vacía y el firewall deja de bloquear.
    """
    client=models.OneToOneField('core.Client',on_delete=models.CASCADE,related_name='blocklist_feed')
    enabled=models.BooleanField('Publicar la lista para los firewalls',default=False)
    stopped=models.BooleanField(default=False)
    stopped_at=models.DateTimeField(null=True,blank=True)
    include_lists=models.BooleanField('Incluir IPs en listas de CrowdSec',default=True)
    include_cti=models.BooleanField('Incluir IPs maliciosas según la API CTI',default=True)
    allowlist=models.TextField('Excepciones (nunca bloquear)',blank=True,help_text='Una IP o red CIDR por línea: proveedores, socios, oficinas remotas.')
    max_entries=models.PositiveIntegerField('Máximo de entradas',default=2000)
    token_hash=models.CharField(max_length=64,blank=True)
    encrypted_token=models.TextField(blank=True)
    entries=models.JSONField(default=list,blank=True)
    generated_at=models.DateTimeField(null=True,blank=True)
    last_fetch_at=models.DateTimeField(null=True,blank=True)
    observation=models.JSONField(default=dict,blank=True)
    updated_at=models.DateTimeField(auto_now=True)
    objects=ScopedManager();customer_lookup='client_id'

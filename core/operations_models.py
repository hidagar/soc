from django.conf import settings
from django.db import models
from django.utils import timezone
from .scope import ScopedManager

class IncidentAction(models.Model):
    incident=models.ForeignKey('core.Incident',on_delete=models.PROTECT,related_name='action_items')
    title=models.CharField('Acción',max_length=240)
    description=models.TextField('Pasos recomendados',blank=True)
    owner=models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.SET_NULL,null=True,blank=True,related_name='soc_actions',verbose_name='Responsable de seguimiento SOC')
    responsible_party=models.CharField('Quién debe actuar',max_length=16,choices=[('soc','Equipo SOC'),('client','Cliente'),('provider','Proveedor')],default='soc')
    due_at=models.DateTimeField('Fecha límite',null=True,blank=True)
    status=models.CharField('Estado',max_length=20,choices=[('pending','Pendiente'),('in_progress','En curso'),('awaiting_client','Esperando al cliente'),('done','Completada'),('cancelled','Cancelada')],default='pending')
    resolution=models.TextField('Evidencia de resolución o motivo de cancelación',blank=True)
    completed_at=models.DateTimeField(null=True,blank=True)
    created_at=models.DateTimeField(default=timezone.now)
    updated_at=models.DateTimeField(auto_now=True)
    objects=ScopedManager()
    customer_lookup='incident__client_id'
    @property
    def overdue(self):
        return bool(self.due_at and self.due_at<timezone.now() and self.status not in ('done','cancelled'))
    class Meta:
        ordering=['due_at','-created_at']
    def __str__(self):return self.title

class ProtectionPolicy(models.Model):
    device=models.OneToOneField('core.Device',on_delete=models.CASCADE,related_name='protection_policy')
    require_ips=models.BooleanField('Exigir IPS en modo bloqueo',default=False)
    require_zenarmor=models.BooleanField('Exigir Zenarmor',default=False)
    require_clamav=models.BooleanField('Exigir ClamAV',default=False)
    notes=models.TextField('Redes y servicios que deben quedar protegidos',blank=True)
    updated_at=models.DateTimeField(auto_now=True)
    objects=ScopedManager()
    customer_lookup='device__site__client_id'

class ExposureCheck(models.Model):
    device=models.OneToOneField('core.Device',on_delete=models.CASCADE,related_name='exposure_check')
    external_interfaces=models.JSONField(default=list,blank=True)
    checked_at=models.DateTimeField(null=True)
    last_success_at=models.DateTimeField(null=True)
    requested_at=models.DateTimeField(null=True)
    status=models.CharField(max_length=20,default='pending')
    coverage=models.JSONField(default=dict)
    notes=models.TextField(blank=True)
    objects=ScopedManager()
    customer_lookup='device__site__client_id'

class ExposureFinding(models.Model):
    device=models.ForeignKey('core.Device',on_delete=models.CASCADE,related_name='exposure_findings')
    section=models.CharField(max_length=20)
    remote_id=models.CharField(max_length=180)
    kind=models.CharField(max_length=30)
    title=models.CharField(max_length=240)
    severity=models.CharField(max_length=12,choices=[('high','Alta'),('medium','Media'),('info','Informativa')])
    evidence=models.JSONField(default=dict)
    recommendation=models.TextField()
    fingerprint=models.CharField(max_length=64)
    history=models.JSONField(default=list)
    present=models.BooleanField(default=True)
    first_seen_at=models.DateTimeField(default=timezone.now)
    last_seen_at=models.DateTimeField(default=timezone.now)
    removed_at=models.DateTimeField(null=True)
    review=models.CharField(max_length=20,choices=[('pending','Pendiente de revisión'),('accepted','Excepción documentada')],default='pending')
    review_note=models.TextField(blank=True)
    review_until=models.DateTimeField(null=True)
    reviewed_by=models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.SET_NULL,null=True)
    reviewed_at=models.DateTimeField(null=True)
    incident=models.ForeignKey('core.Incident',on_delete=models.SET_NULL,null=True,blank=True,related_name='exposures')
    objects=ScopedManager()
    customer_lookup='device__site__client_id'
    class Meta:
        constraints=[models.UniqueConstraint(fields=['device','section','remote_id','kind'],name='unique_exposure_finding')]
        ordering=['-present','severity','-last_seen_at']
    @property
    def exception_active(self):
        return bool(self.review=='accepted' and self.review_until and self.review_until>timezone.now())

class StaffAccess(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='soc_access')
    clients = models.ManyToManyField('core.Client', blank=True, related_name='staff_grants')
    role = models.CharField(max_length=16, choices=[('reader','Consulta'),('operator','Operador'),('manager','Administrador SOC'),('customer','Cliente: portal privado')], default='reader')
    all_clients = models.BooleanField(default=False)

class MfaProfile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='soc_mfa')
    encrypted_secret = models.TextField(blank=True)
    enabled = models.BooleanField(default=False)
    last_counter = models.BigIntegerField(default=-1)
    recovery_hashes = models.JSONField(default=list)
    version = models.PositiveIntegerField(default=1)
    updated_at = models.DateTimeField(auto_now=True)

class AuthAttempt(models.Model):
    identifier = models.CharField(max_length=64, db_index=True)
    occurred_at = models.DateTimeField(default=timezone.now, db_index=True)

class AuditEvent(models.Model):
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    actor_name = models.CharField(max_length=150, blank=True)
    action = models.CharField(max_length=100)
    object_type = models.CharField(max_length=80, blank=True)
    object_id = models.CharField(max_length=80, blank=True)
    details = models.JSONField(default=dict)
    previous_hash = models.CharField(max_length=64, blank=True)
    digest = models.CharField(max_length=64)
    created_at = models.DateTimeField(default=timezone.now)
    class Meta:
        ordering = ['-pk']
        permissions = [('manage_security','Puede gestionar seguridad del SOC'),('view_all_clients','Puede consultar todos los clientes'),('manage_operations','Puede gestionar salud e inventario'),('apply_changes','Puede aprobar cambios de firewall'),('manage_recovery','Puede gestionar copias y recuperacion')]

class DeviceHealth(models.Model):
    device = models.OneToOneField('core.Device', on_delete=models.CASCADE, related_name='health')
    api_ok = models.BooleanField(null=True)
    checked_at = models.DateTimeField(null=True)
    protection_checked_at = models.DateTimeField(null=True)
    api_error = models.CharField(max_length=240, blank=True)
    certificate_expires = models.DateTimeField(null=True)
    engines = models.JSONField(default=dict)
    issues = models.JSONField(default=list)
    inventory_checked_at = models.DateTimeField(null=True)
    expected_silence_minutes = models.PositiveIntegerField(default=0, help_text='0: adaptar al historial; no inferir caida de un flujo solo de alertas.')
    maintenance_until = models.DateTimeField(null=True, blank=True)
    maintenance_reason = models.CharField(max_length=200, blank=True)
    status = models.CharField(max_length=24, default='pending')
    last_log_at = models.DateTimeField(null=True)
    security_verified_at = models.DateTimeField(null=True)
    security_evidence_uid = models.CharField(max_length=64, blank=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = ScopedManager()
    customer_lookup = 'device__site__client_id'

class DeviceFeed(models.Model):
    device = models.ForeignKey('core.Device', on_delete=models.CASCADE, related_name='feeds')
    kind = models.CharField(max_length=16)
    first_seen_at = models.DateTimeField(null=True)
    last_seen_at = models.DateTimeField(null=True)
    security_at = models.DateTimeField(null=True)
    event_count = models.PositiveBigIntegerField(default=0)
    objects = ScopedManager()
    customer_lookup = 'device__site__client_id'
    class Meta:
        constraints = [models.UniqueConstraint(fields=['device','kind'], name='unique_device_feed')]

class FeedBucket(models.Model):
    device = models.ForeignKey('core.Device', on_delete=models.CASCADE)
    kind = models.CharField(max_length=16)
    hour = models.DateTimeField()
    event_count = models.PositiveIntegerField(default=0)
    objects = ScopedManager()
    customer_lookup = 'device__site__client_id'
    class Meta:
        constraints = [models.UniqueConstraint(fields=['device','kind','hour'], name='unique_feed_hour')]

class Asset(models.Model):
    identified_at = models.DateTimeField(null=True,blank=True)
    identity_conflict = models.BooleanField(default=False)
    identity_history = models.JSONField(default=list,blank=True)
    device = models.ForeignKey('core.Device', on_delete=models.CASCADE, related_name='assets')
    ip = models.GenericIPAddressField()
    name = models.CharField(max_length=160, blank=True)
    discovered_name = models.CharField(max_length=160, blank=True)
    mac = models.CharField(max_length=32, blank=True)
    vlan = models.CharField(max_length=40, blank=True)
    critical = models.BooleanField('Equipo crítico para el negocio', default=False)
    function = models.CharField(max_length=160, blank=True)
    owner_contact = models.CharField(max_length=160, blank=True)
    source = models.CharField(max_length=24, default='observed')
    first_seen_at = models.DateTimeField(default=timezone.now)
    last_seen_at = models.DateTimeField(default=timezone.now)
    objects = ScopedManager()
    customer_lookup = 'device__site__client_id'
    @property
    def label(self):
        return (self.ip+' (identidad por revisar)') if self.identity_conflict else (self.name or self.discovered_name or self.ip)
    @property
    def identity_status(self):
        if self.identity_conflict:return 'Por revisar: la IP cambió de MAC'
        if self.name:return 'Identificación manual'
        if not self.discovered_name or not self.identified_at:return 'Equipo sin identificar'
        if timezone.now()-self.identified_at>timezone.timedelta(days=1):return 'Identificación antigua'
        return 'Identificación automática reciente'
    class Meta:
        constraints = [models.UniqueConstraint(fields=['device','ip'], name='unique_asset_device_ip')]
        ordering = ['device__site__client__name','device__site__name','ip']

class SecurityEvidence(models.Model):
    interpretation = models.JSONField(default=dict,blank=True)
    client_scope_id = models.PositiveBigIntegerField(null=True,editable=False,db_index=True)
    wazuh_published_at = models.DateTimeField(null=True,editable=False)
    flow = models.JSONField(default=dict,blank=True)
    identity = models.JSONField(default=dict,blank=True)
    geography = models.JSONField(default=dict, blank=True)
    uid = models.CharField(max_length=64, primary_key=True)
    device = models.ForeignKey('core.Device', on_delete=models.PROTECT, related_name='security_events')
    asset = models.ForeignKey(Asset, on_delete=models.SET_NULL, null=True, blank=True)
    incident = models.ForeignKey('core.Incident', on_delete=models.SET_NULL, null=True, blank=True, related_name='evidence')
    observed_at = models.DateTimeField(db_index=True)
    engine = models.CharField(max_length=16)
    category = models.CharField(max_length=80, blank=True)
    signature = models.CharField(max_length=240)
    action = models.CharField(max_length=24, default='unknown')
    source_ip = models.GenericIPAddressField(null=True)
    destination_ip = models.GenericIPAddressField(null=True)
    destination_port = models.CharField(max_length=16, blank=True)
    level = models.PositiveSmallIntegerField(default=0)
    wazuh_id = models.CharField(max_length=180, blank=True)
    recommendation = models.TextField(blank=True)
    objects = ScopedManager()
    customer_lookup = 'client_scope_id'
    def save(self,*args,**kwargs):
        if self._state.adding and self.client_scope_id is None and self.device_id:
            self.client_scope_id=self.device.site.client_id
        elif not self._state.adding and (kwargs.get('update_fields') is None or 'client_scope_id' in kwargs['update_fields']):
            previous=type(self)._base_manager.filter(pk=self.pk).values_list('client_scope_id',flat=True).first()
            if previous is not None and previous!=self.client_scope_id:raise ValueError('La empresa histórica de una evidencia no puede cambiar.')
        super().save(*args,**kwargs)
    @property
    def identified_label(self):
        return self.identity.get('label') or (self.asset.ip if self.asset_id else 'Destino observado: '+self.destination_ip if self.destination_ip else 'Por identificar')
    @property
    def action_label(self):
        return {'allowed':'Permitida','blocked':'Bloqueada'}.get(self.action,'Sin confirmar')
    class Meta:
        ordering = ['-observed_at']
        # Consultas que se repiten por evento o cada pocos minutos con cientos de miles de filas.
        indexes = [models.Index(fields=['device','signature','observed_at'],name='evidence_episode_idx'),
                   models.Index(fields=['incident','observed_at'],name='evidence_incident_idx'),
                   models.Index(fields=['client_scope_id','wazuh_published_at','observed_at'],name='evidence_unpublished_idx'),
                   models.Index(fields=['client_scope_id','wazuh_id'],name='evidence_wazuh_id_idx')]

class AttributionCatalog(models.Model):
    device=models.OneToOneField('core.Device',on_delete=models.CASCADE,related_name='attribution_catalog')
    checked_at=models.DateTimeField(null=True)
    last_success_at=models.DateTimeField(null=True)
    status=models.CharField(max_length=16,default='unavailable')
    data=models.JSONField(default=dict,blank=True)
    fingerprint=models.CharField(max_length=64,blank=True)
    objects=ScopedManager()
    customer_lookup='device__site__client_id'
    @property
    def current(self):
        from datetime import timedelta
        return bool(self.status in ('checked','partial') and self.last_success_at and timedelta(0)<=timezone.now()-self.last_success_at<=timedelta(minutes=45))

class IncidentUpdate(models.Model):
    incident = models.ForeignKey('core.Incident', on_delete=models.CASCADE, related_name='timeline')
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    text = models.TextField()
    created_at = models.DateTimeField(default=timezone.now)
    objects = ScopedManager()
    customer_lookup = 'incident__client_id'
    class Meta:
        ordering = ['created_at','pk']

class OperationalIssue(models.Model):
    device = models.ForeignKey('core.Device', on_delete=models.CASCADE, null=True, blank=True, related_name='operational_issues')
    key = models.CharField(max_length=120, unique=True)
    title = models.CharField(max_length=240)
    severity = models.CharField(max_length=16, default='warning')
    details = models.TextField(blank=True)
    active = models.BooleanField(default=True)
    opened_at = models.DateTimeField(default=timezone.now)
    checked_at = models.DateTimeField(default=timezone.now)
    resolved_at = models.DateTimeField(null=True)
    notified_at = models.DateTimeField(null=True)
    objects = ScopedManager()
    customer_lookup = 'device__site__client_id'

class WorkerState(models.Model):
    name = models.CharField(max_length=80, primary_key=True)
    inode = models.CharField(max_length=80, blank=True)
    offset = models.PositiveBigIntegerField(default=0)
    last_run_at = models.DateTimeField(null=True)
    last_success_at = models.DateTimeField(null=True)
    error = models.CharField(max_length=240, blank=True)
    details = models.JSONField(default=dict)

    @classmethod
    def reserve(cls, name):
        """Serializa escritores con una fila de bloqueo; llamar dentro de transaction.atomic().

        Escribe antes de leer: en SQLite, un SELECT previo (como get_or_create) deja un
        bloqueo de lectura que no puede ascender y devuelve "database is locked" sin
        esperar cuando hay otro escritor. En PostgreSQL el UPDATE bloquea la fila.
        """
        cls.objects.bulk_create([cls(name=name)], ignore_conflicts=True)
        cls.objects.filter(name=name).update(offset=models.F('offset') + 1)

class ChangePlan(models.Model):
    device = models.ForeignKey('core.Device', on_delete=models.PROTECT, related_name='change_plans')
    template = models.CharField(max_length=32)
    template_version = models.CharField(max_length=16, default='1.0')
    title = models.CharField(max_length=240)
    parameters = models.JSONField(default=dict)
    preview = models.JSONField(default=dict)
    status = models.CharField(max_length=32, default='draft')
    encrypted_backup = models.TextField(blank=True)
    remote_objects = models.JSONField(default=list)
    baseline_hash = models.CharField(max_length=64, blank=True)
    requested_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='+')
    approved_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='+')
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    result = models.CharField(max_length=240, blank=True)
    rollback_revision = models.CharField(max_length=80, blank=True)
    confirmation_deadline = models.DateTimeField(null=True)
    objects = ScopedManager()
    customer_lookup = 'device__site__client_id'
    @property
    def status_label(self):
        return {'draft':'Vista previa','stage_queued':'Preparación pendiente','staging':'Preparando borradores',
            'staged':'Borradores desactivados','apply_queued':'Activación pendiente','applying':'Aplicando',
            'awaiting_confirmation':'Esperando confirmación','active':'Reglas activas',
            'rollback_queued':'Reversión pendiente','confirm_queued':'Comprobando confirmación','rolled_back':'Revertida',
            'failed':'Requiere revisión','needs_review':'Revisión necesaria','manual':'Configuración manual'}.get(self.status,'En revisión')

class VpnPeer(models.Model):
    site = models.OneToOneField('core.Site', on_delete=models.PROTECT, related_name='vpn_peer')
    address = models.GenericIPAddressField(unique=True)
    public_key = models.CharField(max_length=64, unique=True)
    encrypted_private_key = models.TextField()
    encrypted_preshared_key = models.TextField()
    enabled = models.BooleanField(default=False)
    status = models.CharField(max_length=24, default='prepared')
    handshake_at = models.DateTimeField(null=True)
    transport = models.JSONField(default=dict,blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    objects = ScopedManager()
    customer_lookup = 'site__client_id'
    @property
    def status_label(self):
        return {'prepared':'Configuración preparada','waiting':'Esperando conexión',
            'connected':'Conexión comprobada','paused':'Sede desactivada'}.get(self.status,'Pendiente de comprobar')

class RecoverySettings(models.Model):
    transport = models.CharField(max_length=16, default='sftp',choices=[('vm','Copia completa de VM gestionada externamente'),('sftp','Copia cifrada del SOC por SFTP')])
    vm_backup = models.JSONField(default=dict,blank=True)
    hostname = models.CharField(max_length=253, blank=True)
    port = models.PositiveIntegerField(default=22)
    username = models.CharField(max_length=120, blank=True)
    encrypted_password = models.TextField(blank=True)
    host_key_type = models.CharField(max_length=80, blank=True)
    host_key_base64 = models.TextField(blank=True)
    fingerprint = models.CharField(max_length=100, blank=True)
    remote_path = models.CharField(max_length=255, blank=True)
    enabled = models.BooleanField(default=False)
    verified = models.BooleanField(default=False)
    retention_days = models.PositiveIntegerField(default=30)
    evidence_days = models.PositiveIntegerField(default=90)
    operational_email = models.EmailField(default='noc@ibred.es')
    notify_enabled = models.BooleanField(default=True)

class BackupRun(models.Model):
    created_at = models.DateTimeField(default=timezone.now)
    status = models.CharField(max_length=24, default='queued')
    filename = models.CharField(max_length=180, blank=True)
    sha256 = models.CharField(max_length=64, blank=True)
    size = models.PositiveBigIntegerField(default=0)
    external_verified = models.BooleanField(default=False)
    restore_tested_at = models.DateTimeField(null=True)
    details = models.JSONField(default=dict)
    error = models.CharField(max_length=240, blank=True)
    @property
    def native_restore_checked_at(self):
        return self.restore_tested_at if self.details.get('native_restore')=='ok' else None
    @property
    def status_label(self):
        return {'queued':'En cola','running':'En curso','local_verified':'Copia local verificada',
            'verified':'Copia externa verificada','failed':'Verificación fallida',
            'expired':'Retirada por retención'}.get(self.status,'Pendiente de comprobar')



class CustomerPublication(models.Model):
    client=models.ForeignKey('core.Client',on_delete=models.CASCADE)
    title=models.CharField('Título para el cliente',max_length=220)
    summary=models.TextField('Explicación para el cliente')
    next_steps=models.TextField('Qué debe hacer el cliente',blank=True)
    status=models.CharField('Estado',max_length=20,choices=[('open','Pendiente'),('investigating','En seguimiento'),('resolved','Resuelto')],default='open')
    incident=models.ForeignKey('core.Incident',on_delete=models.SET_NULL,null=True,blank=True)
    weekly_report=models.ForeignKey('core.WeeklyReport',on_delete=models.SET_NULL,null=True,blank=True)
    visible=models.BooleanField('Publicado en el portal del cliente',default=False)
    created_at=models.DateTimeField(default=timezone.now)
    updated_at=models.DateTimeField(auto_now=True)
    objects=ScopedManager()
    customer_lookup='client_id'
    class Meta: ordering=['-updated_at']

class DeviceObservation(models.Model):
    device=models.ForeignKey('core.Device',on_delete=models.CASCADE,related_name='observations')
    observed_at=models.DateTimeField(default=timezone.now)
    snapshot=models.JSONField(default=dict)
    changes=models.JSONField(default=list)
    objects=ScopedManager()
    customer_lookup='device__site__client_id'
    class Meta: ordering=['-observed_at','-pk']

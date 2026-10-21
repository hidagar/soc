from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone
import uuid
from .scope import ScopedManager
from .device_identity import MacAddressField, normalize_mac


class Client(models.Model):
    objects = ScopedManager()
    customer_lookup = 'pk'
    name = models.CharField("Nombre", max_length=180)
    code = models.SlugField("Código", max_length=50, unique=True)
    contact_email = models.EmailField("Correo de contacto", blank=True)
    report_email = models.EmailField("Correo para informes semanales", blank=True)
    weekly_reports_enabled = models.BooleanField("Enviar informe semanal automáticamente", default=False)
    customer_live_map_enabled = models.BooleanField('Mostrar mapa agregado en el portal del cliente',default=False)
    customer_portal_detail_enabled = models.BooleanField('Mostrar firewalls y detecciones en el portal del cliente',default=False,
        help_text='El cliente verá el estado de sus firewalls y sus detecciones: firma, categoría, acción, IPs y país. Nunca notas internas ni recomendaciones del SOC.')
    urgent_email = models.EmailField("Correo para avisos urgentes", blank=True)
    urgent_alerts_enabled = models.BooleanField("Enviar avisos urgentes automáticamente", default=False)
    urgent_availability_enabled = models.BooleanField("Incluir caídas de Internet en avisos urgentes", default=False)
    active = models.BooleanField("Activo", default=True)
    notes = models.TextField("Notas internas", blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["name"]
        verbose_name = "Cliente"
        verbose_name_plural = "Clientes"

    def __str__(self):
        return self.name


class WeeklyReport(models.Model):
    objects = ScopedManager()
    customer_lookup = 'client_id'
    coverage = models.JSONField(default=dict)
    client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name="weekly_reports")
    week_start = models.DateField()
    sources = models.JSONField(default=list)
    wazuh_alert_count = models.PositiveIntegerField(default=0)
    security_count = models.PositiveIntegerField(default=0)
    availability_count = models.PositiveIntegerField(default=0)
    other_high_count = models.PositiveIntegerField(default=0)
    allowed_count = models.PositiveIntegerField(default=0)
    blocked_count = models.PositiveIntegerField(default=0)
    notable_alerts = models.JSONField(default=list)
    findings = models.JSONField(default=list)
    details_limited = models.BooleanField(default=False)
    collected_at = models.DateTimeField(default=timezone.now)
    sent_at = models.DateTimeField(null=True, blank=True)
    sent_to = models.EmailField(blank=True)
    provider_message_id = models.CharField(max_length=180, blank=True)
    last_send_error = models.CharField(max_length=250, blank=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["client", "week_start"], name="unique_weekly_report_client_week")]
        ordering = ["-week_start", "client__name"]


class MailSettings(models.Model):
    class Region(models.TextChoices):
        GLOBAL = "global", "SendGrid global"
        EU = "eu", "SendGrid EU regional"

    region = models.CharField("Región de la cuenta", max_length=10, choices=Region.choices, default=Region.GLOBAL)
    encrypted_api_key = models.TextField(blank=True)
    from_email = models.EmailField("Correo remitente")
    reply_to_email = models.EmailField("Correo para respuestas", blank=True)
    report_copy_email = models.EmailField("Copia oculta de informes", blank=True)
    public_reports_url = models.URLField("URL pública de informes", max_length=255, blank=True)
    public_reports_verified = models.BooleanField(default=False)
    enabled = models.BooleanField(default=False)
    last_tested_at = models.DateTimeField(null=True, blank=True)
    last_test_ok = models.BooleanField(default=False)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Correo de informes"

    def __str__(self):
        return self.from_email


class ReportShare(models.Model):
    report = models.OneToOneField(WeeklyReport, on_delete=models.CASCADE, related_name="customer_share")
    nonce = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    expires_at = models.DateTimeField()
    revoked = models.BooleanField(default=False)


class UrgentMonitorCursor(models.Model):
    last_checked_at = models.DateTimeField(default=timezone.now)
    checkpoint = models.JSONField(default=dict,blank=True)


class SourceOwnership(models.Model):
    """Temporal source ownership. Null owner means ambiguous, never public data."""
    source = models.GenericIPAddressField(db_index=True)
    client_scope_id = models.PositiveBigIntegerField(null=True,editable=False,db_index=True)
    valid_from = models.DateTimeField()
    valid_until = models.DateTimeField(null=True,blank=True)
    objects = ScopedManager()
    customer_lookup = 'client_scope_id'
    class Meta:
        constraints=[models.UniqueConstraint(fields=['source'],condition=models.Q(valid_until__isnull=True),name='unique_current_source_owner')]


class UrgentAlert(models.Model):
    interpretation = models.JSONField(default=dict,blank=True)
    acknowledged_at = models.DateTimeField(null=True,blank=True)
    acknowledged_by = models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.SET_NULL,null=True,blank=True,related_name='+')
    objects = ScopedManager()
    customer_lookup = 'client_id'
    class Kind(models.TextChoices):
        SECURITY_ALLOWED = "security_allowed", "Seguridad permitida"
        SECURITY_CRITICAL = "security_critical", "Seguridad crítica"
        AVAILABILITY = "availability", "Caída de Internet"

    class Status(models.TextChoices):
        PENDING = "pending", "Pendiente"
        SENDING = "sending", "Enviando"
        ACCEPTED = "accepted", "Aceptado por SendGrid"
        SUPPRESSED = "suppressed", "Agrupado con otro aviso"
        FAILED = "failed", "Error de envío"
        UNCERTAIN = "uncertain", "Entrega por comprobar"
        EXPIRED = "expired", "Fuera de plazo"

    client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name="urgent_alerts")
    event_uid = models.CharField(max_length=64, unique=True)
    fingerprint = models.CharField(max_length=64, db_index=True)
    kind = models.CharField(max_length=24, choices=Kind.choices)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.PENDING, db_index=True)
    observed_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    source_ip = models.GenericIPAddressField()
    external_ip = models.GenericIPAddressField(null=True, blank=True)
    destination_ip = models.GenericIPAddressField(null=True, blank=True)
    destination_port = models.CharField(max_length=16, blank=True)
    site_name = models.CharField(max_length=160, blank=True)
    asset_name = models.CharField(max_length=160, blank=True)
    signature = models.CharField(max_length=240, blank=True)
    action = models.CharField(max_length=32, blank=True)
    rule_level = models.PositiveSmallIntegerField(default=0)
    recipient = models.EmailField()
    attempts = models.PositiveSmallIntegerField(default=0)
    next_retry_at = models.DateTimeField(null=True, blank=True)
    last_attempt_at = models.DateTimeField(null=True, blank=True)
    sent_at = models.DateTimeField(null=True, blank=True)
    provider_message_id = models.CharField(max_length=180, blank=True)
    last_error = models.CharField(max_length=250, blank=True)

    class Meta:
        ordering = ["-observed_at"]
        indexes = [models.Index(fields=["client", "observed_at"], name="urgent_client_seen_idx")]


class Site(models.Model):
    objects = ScopedManager()
    customer_lookup = 'client_id'
    client = models.ForeignKey(Client, on_delete=models.PROTECT, related_name="sites", verbose_name="Cliente")
    name = models.CharField("Nombre", max_length=160)
    code = models.SlugField("Código", max_length=50)
    address = models.CharField("Ubicación", max_length=250, blank=True)
    notes = models.TextField("Notas internas", blank=True)
    active = models.BooleanField("Activa", default=True)

    class Meta:
        ordering = ["client__name", "name"]
        constraints = [models.UniqueConstraint(fields=["client", "code"], name="unique_site_code_per_client")]
        verbose_name = "Sede"
        verbose_name_plural = "Sedes"

    def __str__(self):
        return f"{self.client.name} · {self.name}"


class Device(models.Model):
    objects = ScopedManager()
    customer_lookup = 'site__client_id'
    class Vendor(models.TextChoices):
        OPNSENSE = "opnsense", "OPNsense"
        UNIFI = "unifi", "UniFi"
        HILLSTONE = "hillstone", "Hillstone"
        GRANDSTREAM_GCC = "grandstream_gcc", "Grandstream GCC"
        OTHER = "other", "Otro"

    class Integration(models.TextChoices):
        PENDING = "pending", "Pendiente"
        CONNECTED = "connected", "Conectado"
        PAUSED = "paused", "Pausado"

    class ManagementMethod(models.TextChoices):
        NONE = "none", "Pendiente"
        API = "api", "API"
        SSH = "ssh", "SSH"

    class LogMethod(models.TextChoices):
        NONE = "none", "Pendiente"
        SYSLOG = "syslog", "Syslog"
        WAZUH_AGENT = "wazuh_agent", "Agente Wazuh"

    site = models.ForeignKey(Site, on_delete=models.PROTECT, related_name="devices", verbose_name="Sede")
    name = models.CharField("Nombre", max_length=160)
    vendor = models.CharField("Fabricante", max_length=20, choices=Vendor.choices)
    model = models.CharField("Modelo", max_length=120, blank=True)
    software_version = models.CharField("Versión", max_length=120, blank=True)
    management_method = models.CharField("Acceso de gestión", max_length=16, choices=ManagementMethod.choices, default=ManagementMethod.NONE)
    log_method = models.CharField("Envío de eventos", max_length=16, choices=LogMethod.choices, default=LogMethod.NONE)
    zenarmor_edition = models.CharField("Edición de Zenarmor", max_length=120, blank=True)
    zenarmor_enabled = models.BooleanField("Incluye Zenarmor", default=False)
    zenarmor_version = models.CharField("Versión de Zenarmor", max_length=120, blank=True)
    management_address = models.CharField("IP o nombre de gestión", max_length=255, blank=True)
    ssh_username = models.CharField("Usuario SSH", max_length=120, blank=True)
    serial_number = models.CharField("Número de serie", max_length=120, blank=True)
    mac_address = MacAddressField('MAC del equipo', max_length=17, null=True, blank=True, unique=True,
        help_text='MAC principal de la etiqueta del equipo o del inventario GDMS. Opcional; identifica el equipo, no la IP que envía los logs.',
        error_messages={'unique': 'Esta MAC ya está registrada en otro equipo.'})
    inventory_checked_at = models.DateTimeField(null=True, blank=True)
    inventory_metadata = models.JSONField(default=dict, blank=True)
    wazuh_identifier = models.CharField("Identificador en Wazuh", max_length=160, blank=True)
    integration = models.CharField("Integración", max_length=20, choices=Integration.choices, default=Integration.PENDING)
    notes = models.TextField("Notas internas", blank=True)
    active = models.BooleanField("Activo", default=True)

    class Meta:
        ordering = ["site__client__name", "site__name", "name"]
        verbose_name = "Equipo"
        verbose_name_plural = "Equipos"
        permissions = [("manage_connections", "Puede gestionar credenciales y conexiones de equipos")]

    @property
    def client(self):
        return self.site.client

    @property
    def connection_profile_label(self):
        return 'OPNsense + Zenarmor' if self.vendor == self.Vendor.OPNSENSE and self.zenarmor_enabled else self.get_vendor_display()

    def __str__(self):
        return f"{self.site.name} · {self.name}"

    def clean(self):
        errors = {}
        try:
            self.mac_address = normalize_mac(self.mac_address)
            if self.mac_address and Device._base_manager.filter(mac_address=self.mac_address).exclude(pk=self.pk).exists():
                errors['mac_address'] = 'Esta MAC ya está registrada en otro equipo.'
        except ValidationError as exc:
            errors['mac_address'] = exc
        if self.zenarmor_enabled and self.vendor != self.Vendor.OPNSENSE:
            errors['zenarmor_enabled'] = 'El perfil Zenarmor está disponible aquí para OPNsense.'
        if self.management_method == self.ManagementMethod.API and self.vendor not in (self.Vendor.UNIFI, self.Vendor.OPNSENSE, self.Vendor.HILLSTONE, self.Vendor.GRANDSTREAM_GCC):
            errors["management_method"] = "La conexión API de este fabricante aún no está disponible."
        if self.log_method == self.LogMethod.WAZUH_AGENT and self.vendor != self.Vendor.OPNSENSE:
            errors["log_method"] = "El agente Wazuh está disponible aquí solo para OPNsense."
        if errors:
            raise ValidationError(errors)


class UnifiCloudConnection(models.Model):
    device = models.OneToOneField(Device, on_delete=models.CASCADE, related_name="unifi_cloud")
    encrypted_api_key = models.TextField()
    remote_site_id = models.CharField(max_length=160, blank=True)
    remote_host_id = models.CharField(max_length=200, blank=True)
    remote_site_name = models.CharField(max_length=200, blank=True)
    last_checked_at = models.DateTimeField(null=True, blank=True)
    last_ok = models.BooleanField(default=False)

    def __str__(self):
        return f"UniFi Cloud · {self.device}"


class OpnsenseConnection(models.Model):
    device = models.OneToOneField(Device, on_delete=models.CASCADE, related_name="opnsense_api")
    api_url = models.URLField(max_length=255)
    encrypted_api_key = models.TextField()
    encrypted_api_secret = models.TextField()
    ca_certificate = models.TextField(blank=True)
    last_checked_at = models.DateTimeField(null=True, blank=True)
    last_ok = models.BooleanField(default=False)

    def __str__(self):
        return f"OPNsense API · {self.device}"


class HillstoneConnection(models.Model):
    device = models.OneToOneField(Device, on_delete=models.CASCADE, related_name="hillstone_api")
    api_url = models.URLField(max_length=255)
    username = models.CharField(max_length=120)
    encrypted_password = models.TextField()
    ca_certificate = models.TextField(blank=True)
    last_checked_at = models.DateTimeField(null=True, blank=True)
    last_ok = models.BooleanField(default=False)

    def __str__(self):
        return f"Hillstone API · {self.device}"


class GdmsConnection(models.Model):
    objects = ScopedManager()
    customer_lookup = 'device__site__client_id'
    device = models.OneToOneField(Device, on_delete=models.CASCADE, related_name='gdms_cloud')
    client_scope_id = models.PositiveBigIntegerField()
    region = models.CharField(max_length=2, choices=[('eu', 'Europa'), ('us', 'Estados Unidos')], default='eu')
    app_id = models.CharField(max_length=120)
    encrypted_secret = models.TextField()
    restricted = models.BooleanField(default=False)
    username = models.CharField(max_length=254, blank=True)
    encrypted_password = models.TextField(blank=True)
    last_checked_at = models.DateTimeField(null=True, blank=True)
    last_ok = models.BooleanField(default=False)

    def __str__(self):
        return f'GDMS Networking · {self.device}'


class SshConnection(models.Model):
    device = models.OneToOneField(Device, on_delete=models.CASCADE, related_name="ssh_connection")
    hostname = models.CharField(max_length=253)
    port = models.PositiveIntegerField(default=22)
    username = models.CharField(max_length=120)
    encrypted_password = models.TextField()
    host_key_type = models.CharField(max_length=80)
    host_key_base64 = models.TextField()
    fingerprint = models.CharField(max_length=80)
    last_checked_at = models.DateTimeField(null=True, blank=True)
    last_ok = models.BooleanField(default=False)

    def __str__(self):
        return f"SSH · {self.device}"


def default_receiver_ip():
    return settings.SOC_RECEIVER_IP


def default_receiver_port():
    return settings.SOC_RECEIVER_PORT


class ExportConfiguration(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Pendiente"
        CONFIGURING = "configuring", "Configurando"
        CONFIGURED = "configured", "Configurado"
        ERROR = "error", "Error"

    device = models.OneToOneField(Device, on_delete=models.CASCADE, related_name="export_configuration")
    destination = models.GenericIPAddressField(protocol="IPv4", default=default_receiver_ip)
    port = models.PositiveIntegerField(default=default_receiver_port)
    source_ip = models.GenericIPAddressField(protocol="IPv4", null=True, blank=True)
    receiver_ready = models.BooleanField(default=False)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.PENDING)
    remote_identifier = models.CharField(max_length=160, blank=True)
    last_error = models.TextField(blank=True)
    configured_at = models.DateTimeField(null=True, blank=True)
    last_attempt_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"Exportación · {self.device}"


class FirewallOnboarding(models.Model):
    """Resumable onboarding. Only the Wazuh worker can confirm reception."""
    class Method(models.TextChoices):
        MANUAL = "manual", "Solo envío de logs"
        API = "api", "API"
        SSH = "ssh", "SSH"
        HTTPS = "https", "HTTPS con clave del equipo"

    device = models.OneToOneField(Device, on_delete=models.CASCADE, related_name="onboarding")
    method = models.CharField(max_length=12, choices=Method.choices, default=Method.MANUAL)
    step = models.PositiveSmallIntegerField(default=3)
    verification_started_at = models.DateTimeField(null=True, blank=True)
    checked_at = models.DateTimeField(null=True, blank=True)
    verified_at = models.DateTimeField(null=True, blank=True)
    event_at = models.DateTimeField(null=True, blank=True)
    event_decoder = models.CharField(max_length=120, blank=True)
    event_rule = models.CharField(max_length=24, blank=True)
    zenarmor_event_at = models.DateTimeField(null=True, blank=True)
    verification_error = models.CharField(max_length=250, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)


class Incident(models.Model):
    episode_key = models.CharField(max_length=64,blank=True,db_index=True)
    objects = ScopedManager()
    customer_lookup = 'client_id'
    fingerprint = models.CharField(max_length=96, blank=True, db_index=True)
    occurrence_count = models.PositiveIntegerField(default=1)
    last_seen_at = models.DateTimeField(null=True, blank=True)
    recommendation = models.TextField(blank=True)
    class Severity(models.TextChoices):
        LOW = "low", "Baja"
        MEDIUM = "medium", "Media"
        HIGH = "high", "Alta"
        CRITICAL = "critical", "Crítica"

    class Status(models.TextChoices):
        OPEN = "open", "Abierta"
        INVESTIGATING = "investigating", "En investigación"
        RESOLVED = "resolved", "Resuelta"

    client = models.ForeignKey(Client, on_delete=models.PROTECT, related_name="incidents", verbose_name="Cliente")
    site = models.ForeignKey(Site, on_delete=models.PROTECT, related_name="incidents", verbose_name="Sede", null=True, blank=True)
    device = models.ForeignKey(Device, on_delete=models.PROTECT, related_name="incidents", verbose_name="Equipo", null=True, blank=True)
    title = models.CharField("Título", max_length=220)
    description = models.TextField("Descripción")
    severity = models.CharField("Severidad", max_length=12, choices=Severity.choices, default=Severity.MEDIUM)
    status = models.CharField("Estado", max_length=16, choices=Status.choices, default=Status.OPEN)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, verbose_name="Responsable")
    observed_at = models.DateTimeField("Detectada", default=timezone.now)
    resolved_at = models.DateTimeField("Resuelta", null=True, blank=True)
    wazuh_alert_id = models.CharField("ID de alerta Wazuh", max_length=180, blank=True)
    actions = models.TextField("Acciones y seguimiento", blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-observed_at"]
        verbose_name = "Incidencia"
        verbose_name_plural = "Incidencias"
        constraints = [models.UniqueConstraint(fields=['fingerprint'],condition=~models.Q(fingerprint=''),name='unique_incident_fingerprint')]

    def clean(self):
        errors = {}
        if self.site_id and self.client_id and self.site.client_id != self.client_id:
            errors["site"] = "La sede no pertenece al cliente."
        if self.device_id:
            if self.device.site.client_id != self.client_id:
                errors["device"] = "El equipo no pertenece al cliente."
            elif self.site_id and self.device.site_id != self.site_id:
                errors["device"] = "El equipo no pertenece a la sede."
        if errors:
            raise ValidationError(errors)

    def __str__(self):
        return self.title


from .operations_models import (StaffAccess, MfaProfile, AuthAttempt, AuditEvent, DeviceHealth,
    DeviceFeed, FeedBucket, Asset, SecurityEvidence, IncidentUpdate, OperationalIssue,
    WorkerState, ChangePlan, VpnPeer, RecoverySettings, BackupRun, IncidentAction, ExposureCheck, ExposureFinding, ProtectionPolicy, CustomerPublication, DeviceObservation)
from .improvement_models import (RunbookStep,ProtectionValidation,CustomerTask,CustomerTaskEntry,DeliverySettings,MailDispatch,MailEvent,ConfigurationArchive)
from .network_models import NetworkCheck, NetworkCoverage
from .operations_models import AttributionCatalog
from .improvement_models import ZenarmorExportRequest
from .improvement_models import ReportVersion, IpReputation, BlocklistFeed
from .improvement_models import AdvancedReview
from .vpn_security import VpnAccessEvent
from .access_models import UserInvitation,SecureLogChannel,SecureLogReceipt,SecureLogMessage

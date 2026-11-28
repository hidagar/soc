"""Equipos de los clientes con agente Wazuh (PC y servidores) y las detecciones de su antivirus (Defender)."""
from django.conf import settings
from django.db import models
from django.utils import timezone

from .scope import ScopedManager


class EndpointAgent(models.Model):
    """Agente Wazuh de un PC o servidor de un cliente.

    Se descubre al llegar sus eventos («sin asignar», sin cliente) y el SOC lo asigna a un cliente. La
    pertenencia empieza en `assigned_at`: los eventos anteriores no se atribuyen a nadie (invariante 2).
    Retirarlo cierra el registro (`retired_at`); si el mismo identificador vuelve, es un registro nuevo.
    El estado del antivirus sale de sus eventos de Defender (informe de salud 1151 y cambios de protección).
    """
    STATUSES = [('pending', 'Sin asignar'), ('assigned', 'Asignado'), ('retired', 'Retirado')]
    agent_id = models.CharField(max_length=16, db_index=True)
    name = models.CharField(max_length=120)
    ip = models.GenericIPAddressField(null=True, blank=True)
    status = models.CharField(max_length=10, choices=STATUSES, default='pending', db_index=True)
    client = models.ForeignKey('core.Client', on_delete=models.CASCADE, null=True, blank=True, related_name='endpoints')
    site = models.ForeignKey('core.Site', on_delete=models.SET_NULL, null=True, blank=True, related_name='endpoints')
    assigned_at = models.DateTimeField(null=True, blank=True)
    assigned_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='+')
    retired_at = models.DateTimeField(null=True, blank=True)
    first_seen_at = models.DateTimeField(default=timezone.now)
    last_seen_at = models.DateTimeField(default=timezone.now)
    # Antivirus (Microsoft Defender), según sus eventos.
    defender_seen_at = models.DateTimeField(null=True, blank=True)
    health_at = models.DateTimeField(null=True, blank=True)  # último informe de salud (1151)
    realtime_enabled = models.BooleanField(null=True, blank=True)
    realtime_changed_at = models.DateTimeField(null=True, blank=True)
    scanning_disabled_at = models.DateTimeField(null=True, blank=True)
    signature_age_days = models.PositiveIntegerField(null=True, blank=True)
    signature_version = models.CharField(max_length=40, blank=True)
    quick_scan_age_days = models.PositiveIntegerField(null=True, blank=True)
    update_failed_at = models.DateTimeField(null=True, blank=True)
    # Sistema y datos que llegan, según sus eventos (también antes de asignarlo: no son datos del cliente).
    PLATFORMS = [('', 'Sin determinar'), ('windows', 'Windows'), ('linux', 'Linux'), ('macos', 'macOS')]
    platform = models.CharField(max_length=10, choices=PLATFORMS, blank=True)
    auth_seen_at = models.DateTimeField(null=True, blank=True)  # último evento de acceso (correcto o fallido)
    sca_seen_at = models.DateTimeField(null=True, blank=True)  # última alerta de configuración segura
    fim_seen_at = models.DateTimeField(null=True, blank=True)  # último cambio de archivos
    objects = ScopedManager()
    customer_lookup = 'client_id'

    class Meta:
        ordering = ['name', 'agent_id']
        constraints = [models.UniqueConstraint(fields=['agent_id'], condition=models.Q(retired_at__isnull=True),
                                               name='unique_current_endpoint_agent')]


class EndpointDetection(models.Model):
    """Detección del antivirus de un equipo (Defender 1116/1006 y sus acciones 1117/1007, 1118/1119/1008).

    La detección y la acción posterior se unen por el identificador de detección de Defender. `action`
    queda «detectada» mientras no haya evidencia de lo que hizo el antivirus (invariante 4): una detección
    contenida no prueba que no hubiera ejecución previa, y una sin acción no prueba compromiso.
    """
    ACTIONS = [('detected', 'Detectada, sin acción confirmada'), ('contained', 'Contenida (cuarentena o eliminación)'),
               ('allowed', 'Permitida por el usuario o una exclusión'), ('failed', 'El antivirus no pudo actuar')]
    REVIEW = [('pending', 'Por revisar'), ('reviewed', 'Revisada'), ('incident', 'Incidencia abierta')]
    agent = models.ForeignKey(EndpointAgent, on_delete=models.CASCADE, related_name='detections')
    client_scope_id = models.PositiveBigIntegerField(db_index=True, editable=False)  # cliente al observarla
    detection_key = models.CharField(max_length=80)
    observed_at = models.DateTimeField(db_index=True)
    updated_at = models.DateTimeField(default=timezone.now)
    threat = models.CharField(max_length=200)
    severity = models.CharField(max_length=40, blank=True)
    category = models.CharField(max_length=80, blank=True)
    action = models.CharField(max_length=12, choices=ACTIONS, default='detected')
    action_name = models.CharField(max_length=80, blank=True)  # literal de Defender (Quarantine, Remove, Allow…)
    path = models.CharField(max_length=400, blank=True)  # dato interno: nunca se publica al cliente
    process = models.CharField(max_length=260, blank=True)
    user = models.CharField(max_length=120, blank=True)
    review = models.CharField(max_length=10, choices=REVIEW, default='pending', db_index=True)
    reviewed_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='+')
    reviewed_at = models.DateTimeField(null=True, blank=True)
    incident = models.ForeignKey('core.Incident', on_delete=models.SET_NULL, null=True, blank=True, related_name='+')
    objects = ScopedManager()
    customer_lookup = 'client_scope_id'

    class Meta:
        ordering = ['-observed_at', '-pk']
        constraints = [models.UniqueConstraint(fields=['agent', 'detection_key'], name='unique_endpoint_detection')]

    @property
    def urgent(self):
        return self.action in ('allowed', 'failed')


class EndpointVulnerability(models.Model):
    """Vulnerabilidad conocida (CVE) del software de un equipo, según la detección de vulnerabilidades de Wazuh.

    Es una fotografía del estado actual del equipo, no un evento: el trabajo `endpoint_vulnerabilities` la
    sustituye con cada lectura completa del índice de Wazuh. Lo que deja de aparecer se marca resuelto
    (`resolved_at`); con una lectura incompleta no se resuelve nada (invariante 5). El cliente es el del equipo
    en el momento de la lectura (estado actual, no histórico).
    """
    SEVERITIES = [('critical', 'Crítica'), ('high', 'Alta'), ('medium', 'Media'), ('low', 'Baja'), ('none', 'Sin clasificar')]
    agent = models.ForeignKey(EndpointAgent, on_delete=models.CASCADE, related_name='vulnerabilities')
    client = models.ForeignKey('core.Client', on_delete=models.CASCADE, related_name='endpoint_vulnerabilities')
    cve = models.CharField(max_length=40)
    package = models.CharField(max_length=200)
    version = models.CharField(max_length=120, blank=True)
    severity = models.CharField(max_length=10, choices=SEVERITIES, default='none', db_index=True)
    score = models.FloatField(null=True, blank=True)
    title = models.CharField(max_length=300, blank=True)
    published_at = models.DateTimeField(null=True, blank=True)
    detected_at = models.DateTimeField(null=True, blank=True)
    first_seen_at = models.DateTimeField(default=timezone.now)
    last_seen_at = models.DateTimeField(default=timezone.now)
    resolved_at = models.DateTimeField(null=True, blank=True, db_index=True)
    objects = ScopedManager()
    customer_lookup = 'client_id'

    class Meta:
        ordering = ['-score', 'cve']
        constraints = [models.UniqueConstraint(fields=['agent', 'cve', 'package'], name='unique_endpoint_vulnerability')]


class EndpointAccessAlert(models.Model):
    """Intentos de acceso fallidos a un equipo (Windows, SSH, sudo, PAM), agrupados por ráfaga.

    Una ráfaga reúne los fallos del mismo equipo y el mismo origen (o del mismo usuario si el evento no trae
    origen) separados menos de una hora. `kind` solo empeora: fallos aislados → repetidos (5 o más, o la
    correlación de Wazuh) → cuenta bloqueada → acceso correcto tras los fallos. Un acceso correcto tras fallos no
    prueba que alguien adivinara la contraseña (puede ser el usuario que se equivocó) ni un fallo prueba un
    ataque (invariante 4). Usuario e IP interna son datos internos: el cliente no los ve (invariante 3).
    """
    KINDS = [('isolated', 'Fallos aislados'), ('repeated', 'Fallos repetidos'), ('lockout', 'Cuenta bloqueada'),
             ('success', 'Acceso correcto tras los fallos')]
    REVIEW = [('pending', 'Por revisar'), ('reviewed', 'Revisado'), ('incident', 'Incidencia abierta')]
    agent = models.ForeignKey(EndpointAgent, on_delete=models.CASCADE, related_name='access_alerts')
    client_scope_id = models.PositiveBigIntegerField(db_index=True, editable=False)  # cliente al observarlo
    source_ip = models.GenericIPAddressField(null=True, blank=True)  # origen del intento (dato interno si es privado)
    source_public = models.BooleanField(default=False)  # origen en Internet
    group_user = models.CharField(max_length=120, blank=True)  # solo sin origen: agrupa por usuario
    users = models.JSONField(default=list, blank=True)  # cuentas probadas (máximo 20; dato interno)
    first_at = models.DateTimeField(db_index=True)
    last_at = models.DateTimeField(db_index=True)
    failures = models.PositiveIntegerField(default=0)  # intentos fallidos distintos (por identificador de alerta)
    correlated = models.BooleanField(default=False)  # Wazuh también lo correlacionó (grupo authentication_failures)
    locked_out_at = models.DateTimeField(null=True, blank=True)
    succeeded_at = models.DateTimeField(null=True, blank=True)
    success_user = models.CharField(max_length=120, blank=True)  # dato interno
    kind = models.CharField(max_length=10, choices=KINDS, default='isolated', db_index=True)
    updated_at = models.DateTimeField(default=timezone.now)
    review = models.CharField(max_length=10, choices=REVIEW, default='pending', db_index=True)
    reviewed_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='+')
    reviewed_at = models.DateTimeField(null=True, blank=True)
    incident = models.ForeignKey('core.Incident', on_delete=models.SET_NULL, null=True, blank=True, related_name='+')
    objects = ScopedManager()
    customer_lookup = 'client_scope_id'

    class Meta:
        ordering = ['-last_at', '-pk']
        indexes = [models.Index(fields=['agent', 'last_at'], name='endpoint_access_agent_last')]

    @property
    def urgent(self):
        """Aviso urgente al cliente: acceso correcto tras los fallos desde Internet."""
        return self.kind == 'success' and self.source_public


class EndpointAccessEvent(models.Model):
    """Identificador de cada alerta de Wazuh ya contada en una ráfaga: repetir la lectura no infla los intentos."""
    agent = models.ForeignKey(EndpointAgent, on_delete=models.CASCADE, related_name='+')
    alert = models.ForeignKey(EndpointAccessAlert, on_delete=models.CASCADE, related_name='events')
    event_id = models.CharField(max_length=64)
    observed_at = models.DateTimeField(db_index=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=['agent', 'event_id'], name='unique_endpoint_access_event')]


class EndpointPolicy(models.Model):
    """Política de configuración segura (SCA de Wazuh, p. ej. un benchmark CIS) evaluada en un equipo.

    El resumen de cada análisis (puntuación, superadas, fallidas) llega como alerta `sca` de tipo «summary».
    Wazuh solo lo envía cuando cambia algo, así que `scanned_at` es el último resumen recibido, no el último análisis.
    """
    agent = models.ForeignKey(EndpointAgent, on_delete=models.CASCADE, related_name='policies')
    client_scope_id = models.PositiveBigIntegerField(db_index=True, editable=False)
    policy_id = models.CharField(max_length=120)
    name = models.CharField(max_length=200, blank=True)
    score = models.PositiveSmallIntegerField(null=True, blank=True)  # la de Wazuh: superadas / (superadas + fallidas)
    passed = models.PositiveIntegerField(null=True, blank=True)
    failed = models.PositiveIntegerField(null=True, blank=True)
    invalid = models.PositiveIntegerField(null=True, blank=True)
    total = models.PositiveIntegerField(null=True, blank=True)
    scan_id = models.CharField(max_length=40, blank=True)
    scanned_at = models.DateTimeField(null=True, blank=True)
    first_seen_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)
    objects = ScopedManager()
    customer_lookup = 'client_scope_id'

    class Meta:
        ordering = ['agent', 'policy_id']
        constraints = [models.UniqueConstraint(fields=['agent', 'policy_id'], name='unique_endpoint_policy')]


class EndpointPolicyCheck(models.Model):
    """Resultado de una comprobación de configuración segura en un equipo, según la última alerta SCA recibida.

    Wazuh envía la alerta de una comprobación en el primer análisis y cuando su resultado cambia; un evento más
    antiguo que llega tarde no pisa uno posterior. Una comprobación fallida es una recomendación de bastionado, no
    una prueba de que el equipo haya sido atacado (invariante 4).
    """
    RESULTS = [('failed', 'No cumple'), ('passed', 'Cumple'), ('not_applicable', 'No aplica')]
    agent = models.ForeignKey(EndpointAgent, on_delete=models.CASCADE, related_name='policy_checks')
    client_scope_id = models.PositiveBigIntegerField(db_index=True, editable=False)
    policy_id = models.CharField(max_length=120)
    check_id = models.CharField(max_length=20)
    title = models.CharField(max_length=300)
    result = models.CharField(max_length=16, choices=RESULTS, db_index=True)
    previous_result = models.CharField(max_length=16, blank=True)
    description = models.TextField(blank=True)
    rationale = models.TextField(blank=True)
    remediation = models.TextField(blank=True)  # texto del benchmark: solo para el SOC
    compliance = models.JSONField(default=dict, blank=True)  # p. ej. {'cis': '1.1.1', 'pci_dss_v3.2.1': '8.2.3'}
    first_seen_at = models.DateTimeField(default=timezone.now)
    observed_at = models.DateTimeField()
    changed_at = models.DateTimeField(null=True, blank=True, db_index=True)
    objects = ScopedManager()
    customer_lookup = 'client_scope_id'

    class Meta:
        ordering = ['policy_id', 'check_id']
        constraints = [models.UniqueConstraint(fields=['agent', 'policy_id', 'check_id'], name='unique_endpoint_policy_check')]

    @property
    def regressed(self):
        """Antes cumplía y ahora no."""
        return self.result == 'failed' and self.previous_result == 'passed'


class EndpointFileChange(models.Model):
    """Cambio en un archivo o una clave del registro de un equipo (integridad de archivos, syscheck de Wazuh).

    Uno por alerta de Wazuh (único por equipo e identificador de alerta: releer no duplica). `category` sale de la
    ruta: los sensibles (arranque automático, usuarios y permisos, resolución de nombres) se revisan uno a uno; el
    resto (binarios del sistema, configuración) se resume por equipo y día, porque una actualización cambia miles.
    Un cambio no prueba una intrusión (invariante 4). Ruta, usuario y proceso son datos internos (invariante 3).
    """
    EVENTS = [('added', 'Añadido'), ('modified', 'Modificado'), ('deleted', 'Eliminado')]
    CATEGORIES = [('persistence', 'Arranque automático'), ('identity', 'Usuarios y permisos'),
                  ('network', 'Resolución de nombres'), ('config', 'Configuración'), ('binary', 'Programas del sistema'),
                  ('other', 'Otros')]
    REVIEW = [('pending', 'Por revisar'), ('reviewed', 'Revisado'), ('incident', 'Incidencia abierta')]
    agent = models.ForeignKey(EndpointAgent, on_delete=models.CASCADE, related_name='file_changes')
    client_scope_id = models.PositiveBigIntegerField(db_index=True, editable=False)
    event_id = models.CharField(max_length=64)
    observed_at = models.DateTimeField(db_index=True)
    path = models.CharField(max_length=500)
    value_name = models.CharField(max_length=200, blank=True)  # registro de Windows
    registry = models.BooleanField(default=False)
    event = models.CharField(max_length=10, choices=EVENTS)
    category = models.CharField(max_length=12, choices=CATEGORIES, db_index=True)
    sensitive = models.BooleanField(default=False, db_index=True)
    mode = models.CharField(max_length=12, blank=True)  # scheduled, realtime, whodata
    changed = models.JSONField(default=list, blank=True)  # atributos cambiados (size, sha256, perm…)
    sha256 = models.CharField(max_length=64, blank=True)
    actor = models.CharField(max_length=120, blank=True)  # usuario (whodata)
    process = models.CharField(max_length=260, blank=True)  # proceso (whodata)
    review = models.CharField(max_length=10, choices=REVIEW, default='pending', db_index=True)
    reviewed_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='+')
    reviewed_at = models.DateTimeField(null=True, blank=True)
    incident = models.ForeignKey('core.Incident', on_delete=models.SET_NULL, null=True, blank=True, related_name='+')
    objects = ScopedManager()
    customer_lookup = 'client_scope_id'

    class Meta:
        ordering = ['-observed_at', '-pk']
        constraints = [models.UniqueConstraint(fields=['agent', 'event_id'], name='unique_endpoint_file_change')]
        indexes = [models.Index(fields=['sensitive', 'review'], name='endpoint_fim_review')]

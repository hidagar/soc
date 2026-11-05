"""Informe mensual para dirección (bloque 6): publicación con versiones inmutables y envío opcional."""
import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone

from .scope import ScopedManager


class MonthlyReport(models.Model):
    """Mes de un cliente. Solo existe para el cliente cuando el SOC lo publica (`published_at`).

    El contenido se congela en `MonthlyReportVersion`; esta fila guarda la valoración del SOC y el
    estado del envío por correo, que es una bandeja: un resultado dudoso no se reintenta solo (invariante 6).
    """
    SEND_STATUSES = [('', 'Sin envío'), ('queued', 'En cola'), ('sending', 'Enviando'), ('accepted', 'Aceptado por SendGrid'),
                     ('failed', 'No enviado'), ('uncertain', 'Por comprobar')]
    client = models.ForeignKey('core.Client', on_delete=models.CASCADE, related_name='monthly_reports')
    month = models.DateField()  # primer día del mes
    soc_summary = models.TextField('Valoración del SOC', blank=True)
    published_at = models.DateTimeField(null=True, blank=True)
    published_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='+')
    send_status = models.CharField(max_length=12, choices=SEND_STATUSES, blank=True, default='')
    send_error = models.CharField(max_length=240, blank=True)
    sent_to = models.EmailField(blank=True)
    provider_id = models.CharField(max_length=180, blank=True)
    attempted_at = models.DateTimeField(null=True, blank=True)
    sent_at = models.DateTimeField(null=True, blank=True)
    objects = ScopedManager()
    customer_lookup = 'client_id'

    class Meta:
        ordering = ['-month', 'client__name']
        constraints = [models.UniqueConstraint(fields=['client', 'month'], name='unique_monthly_report_client_month')]


class MonthlyReportVersion(models.Model):
    """HTML y PDF tal como se publicaron. No se editan: una rectificación añade la versión siguiente."""
    report = models.ForeignKey(MonthlyReport, on_delete=models.CASCADE, related_name='versions')
    number = models.PositiveIntegerField()
    html = models.TextField()
    pdf = models.BinaryField()
    html_sha256 = models.CharField(max_length=64)
    pdf_sha256 = models.CharField(max_length=64)
    reason = models.TextField(blank=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='+')
    created_at = models.DateTimeField(default=timezone.now)
    objects = ScopedManager()
    customer_lookup = 'report__client_id'

    class Meta:
        ordering = ['report', 'number']
        constraints = [models.UniqueConstraint(fields=['report', 'number'], name='unique_monthly_version_number')]


class MonthlyReportShare(models.Model):
    """Enlace firmado del correo mensual, revocable y con caducidad, limitado a ese informe."""
    report = models.OneToOneField(MonthlyReport, on_delete=models.CASCADE, related_name='share')
    nonce = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    expires_at = models.DateTimeField()
    revoked = models.BooleanField(default=False)

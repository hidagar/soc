from django.db import models
from django.utils import timezone
from .scope import ScopedManager


class NetworkCheck(models.Model):
    device = models.OneToOneField('core.Device', on_delete=models.CASCADE, related_name='network_check')
    checked_at = models.DateTimeField(null=True)
    last_success_at = models.DateTimeField(null=True)
    status = models.CharField(max_length=16, default='pending')
    objects = ScopedManager()
    customer_lookup = 'device__site__client_id'


class NetworkCoverage(models.Model):
    device = models.ForeignKey('core.Device', on_delete=models.CASCADE, related_name='networks')
    remote_id = models.CharField(max_length=120)
    name = models.CharField(max_length=180)
    interface = models.CharField(max_length=120, blank=True)
    physical_interface = models.CharField(max_length=120, blank=True)
    cidrs = models.JSONField(default=list)
    role = models.CharField(max_length=20, default='network')
    enabled = models.BooleanField(null=True)
    inspection_selected = models.BooleanField(null=True)
    present = models.BooleanField(default=True)
    last_seen_at = models.DateTimeField(default=timezone.now)
    scope = models.CharField('Ámbito del servicio', max_length=16,
        choices=[('pending', 'Pendiente de definir'), ('included', 'Incluida'), ('excluded', 'Exclusión documentada')], default='pending')
    require_ips = models.BooleanField('Exigir inspección IPS en esta red', default=False)
    require_zenarmor = models.BooleanField('Exigir Zenarmor en esta red', default=False)
    review_note = models.TextField('Justificación / requisitos', blank=True)
    review_until = models.DateTimeField('Revisar exclusión antes de', null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = ScopedManager()
    customer_lookup = 'device__site__client_id'

    class Meta:
        ordering = ['device_id', 'name', 'pk']
        constraints = [models.UniqueConstraint(fields=['device', 'remote_id'], name='unique_device_network')]

    def __str__(self):
        return self.name + (' · ' + ', '.join(self.cidrs) if self.cidrs else '')

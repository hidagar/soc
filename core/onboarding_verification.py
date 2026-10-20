"""Read actual Wazuh output as root; expose only receipt metadata to the portal."""
import json
from datetime import timedelta
from pathlib import Path

from django.utils import timezone
from django.db import transaction
from django.utils.dateparse import parse_datetime

from .models import Device, ExportConfiguration, FirewallOnboarding

ALERTS_PATH = Path('/var/ossec/logs/alerts/alerts.json')
MAX_TAIL_BYTES = 8 * 1024 * 1024


def _tail_lines(path):
    with path.open('rb') as stream:
        stream.seek(0, 2)
        start = max(0, stream.tell() - MAX_TAIL_BYTES)
        stream.seek(start)
        if start:
            stream.readline()  # exclude a truncated JSON line
        for line in stream:
            yield line


def confirm_onboarding_events(lines, now=None):
    now = now or timezone.now()
    pending = list(FirewallOnboarding.objects.filter(
        step=5, verified_at__isnull=True, verification_started_at__isnull=False,
        device__active=True, device__site__active=True,
        device__integration=Device.Integration.PENDING,
    ).select_related('device'))
    by_source = {}
    for row in pending:
        row.checked_at = now
        config = ExportConfiguration.objects.filter(device=row.device).first()
        if not config or not config.receiver_ready or config.status != ExportConfiguration.Status.CONFIGURED:
            row.verification_error = 'El receptor todavía no está preparado. La sincronización se ejecuta cada minuto.'
        elif ExportConfiguration.objects.filter(source_ip=config.source_ip, device__active=True,
                                                device__site__active=True).exclude(device=row.device).exists():
            row.verification_error = 'Origen compartido con otro equipo. Revisa la IP de salida antes de activar.'
        elif not config.source_ip:
            row.verification_error = 'Falta la IP de origen de los logs.'
        else:
            row.verification_error = ''
            by_source[config.source_ip] = row
        row.save(update_fields=['checked_at', 'verification_error'])
    confirmed = 0
    for line in lines:
        try:
            event = json.loads(line)
            if not isinstance(event, dict):
                continue
            row = by_source.get(event.get('location'))
            if not row:
                continue
            event_at = parse_datetime(event.get('timestamp', ''))
            decoder = event.get('decoder', {}).get('name', '')
            rule = str(event.get('rule', {}).get('id', ''))
            if (not event_at or timezone.is_naive(event_at) or event_at < row.verification_started_at
                    or event_at > now + timedelta(seconds=5) or not decoder or not rule.isdecimal()):
                continue
            if row.device.vendor == Device.Vendor.UNIFI and decoder != 'soc-unifi-cef':
                continue
            is_zenarmor = decoder in ('zenarmor', 'zenarmor-iso', 'soc-zenarmor', 'zen-dec', 'zen-conn')
            if is_zenarmor and not row.device.zenarmor_enabled:
                continue
            with transaction.atomic():
                current = FirewallOnboarding.objects.select_for_update().filter(
                    pk=row.pk, step=5, verified_at__isnull=True,
                    verification_started_at=row.verification_started_at,
                    device__export_configuration__source_ip=event['location'],
                    device__export_configuration__receiver_ready=True,
                    device__integration=Device.Integration.PENDING,
                    device__zenarmor_enabled=row.device.zenarmor_enabled,
                ).first()
                if current is None:
                    continue
                if is_zenarmor:
                    current.zenarmor_event_at = event_at
                else:
                    current.event_at = event_at
                    current.event_decoder = decoder[:120]
                    current.event_rule = rule[:24]
                complete = bool(current.event_at and (not row.device.zenarmor_enabled or current.zenarmor_event_at))
                if complete:
                    current.verified_at = now
                    Device.objects.filter(pk=row.device_id, integration=Device.Integration.PENDING).update(
                        integration=Device.Integration.CONNECTED, log_method=Device.LogMethod.SYSLOG)
                current.verification_error = ''
                current.save(update_fields=['event_at', 'event_decoder', 'event_rule', 'zenarmor_event_at', 'verified_at', 'verification_error'])
                version = event.get('data', {}).get('unifi', {}).get('version')
                if row.device.vendor == 'unifi' and isinstance(version, str) and 0 < len(version) <= 120:
                    Device.objects.filter(pk=row.device_id, software_version='').update(software_version=version)
            if complete:
                by_source.pop(event['location'])
                confirmed += 1
        except (ValueError, TypeError, AttributeError, OverflowError):
            continue
    return confirmed


def verify_pending_onboardings():
    if not FirewallOnboarding.objects.filter(step=5, verified_at__isnull=True,
                                             verification_started_at__isnull=False).exists():
        return 0
    try:
        return confirm_onboarding_events(_tail_lines(ALERTS_PATH))
    except OSError:
        FirewallOnboarding.objects.filter(step=5, verified_at__isnull=True).update(
            checked_at=timezone.now(), verification_error='No se pudo leer la salida de Wazuh. El equipo SOC debe revisar el receptor.')
        return 0

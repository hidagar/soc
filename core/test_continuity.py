"""Continuidad: IP real de los accesos, silencio global, ensayo de recuperación y monitor exterior."""
from datetime import timedelta
from io import StringIO
from unittest import mock

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from . import continuity
from .models import (Client, Device, DeviceHealth, OperationalIssue, RecoverySettings, Site, StaffAccess,
                     WorkerState)


def active(key):
    return OperationalIssue.objects.filter(key=key, active=True).first()


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class RealIpTests(TestCase):
    def login(self, ip):
        return self.client.post(reverse('login'), {'username': 'nadie@example.test', 'password': 'x'},
                                REMOTE_ADDR='127.0.0.1', HTTP_X_REAL_IP=ip)

    def test_all_logins_from_one_internal_ip_raise_a_warning(self):
        for _ in range(3):
            self.login('172.20.10.112')
        continuity.check_login_origin(timezone.now())
        issue = active('platform:real-ip')
        self.assertEqual(issue.severity, 'warning')
        self.assertIn('172.20.10.112', issue.details)
        self.assertIn('configurar_ip_real.sh', issue.details)

    def test_public_ips_or_several_internal_ones_are_fine(self):
        for _ in range(3):
            self.login('172.20.10.112')
        self.login('45.155.205.233')
        continuity.check_login_origin(timezone.now())
        self.assertIsNone(active('platform:real-ip'))
        WorkerState.objects.filter(name='login-origin').delete()
        for ip in ('10.204.1.162', '10.204.1.170', '10.204.1.162'):
            self.login(ip)
        continuity.check_login_origin(timezone.now())
        self.assertIsNone(active('platform:real-ip'))

    def test_the_warning_resolves_once_the_real_ip_arrives(self):
        for _ in range(3):
            self.login('172.20.10.112')
        continuity.check_login_origin(timezone.now())
        self.assertIsNotNone(active('platform:real-ip'))
        self.login('185.191.171.45')
        continuity.check_login_origin(timezone.now())
        self.assertIsNone(active('platform:real-ip'))

    def test_only_internal_addresses_are_stored(self):
        self.login('45.155.205.233')
        self.login('192.168.1.5')
        details = WorkerState.objects.get(name='login-origin').details
        self.assertEqual(list(details['internal']), ['192.168.1.5'])
        self.assertNotIn('45.155.205.233', str(details))


class IngestSilenceTests(TestCase):
    def setUp(self):
        site = Site.objects.create(client=Client.objects.create(name='Cliente', code='c'), name='Sede', code='s')
        self.health = DeviceHealth.objects.create(device=Device.objects.create(site=site, name='FW', vendor='opnsense'))

    def test_no_logs_from_any_device_is_critical(self):
        now = timezone.now()
        self.health.last_log_at = now - timedelta(minutes=45)
        self.health.save()
        continuity.check_ingest_silence(now)
        self.assertEqual(active('platform:ingest-silence').severity, 'critical')
        self.health.last_log_at = now - timedelta(minutes=2)
        self.health.save()
        continuity.check_ingest_silence(now)
        self.assertIsNone(active('platform:ingest-silence'))

    def test_a_new_installation_without_logs_does_not_alarm(self):
        continuity.check_ingest_silence(timezone.now())
        self.assertIsNone(active('platform:ingest-silence'))


class RestoreRehearsalTests(TestCase):
    def test_vm_backups_need_a_recent_measured_rehearsal(self):
        now = timezone.now()
        cfg, _ = RecoverySettings.objects.update_or_create(pk=1, defaults={'transport': 'vm', 'vm_backup': {}})
        continuity.check_restore_rehearsal(now)
        self.assertIn('No hay ningún ensayo', active('platform:restore-rehearsal').details)
        cfg.vm_backup = {'vm_last_restore_at': (now - timedelta(days=10)).isoformat()}
        cfg.save()
        continuity.check_restore_rehearsal(now)
        self.assertIn('faltan', active('platform:restore-rehearsal').details)
        cfg.vm_backup.update(vm_restore_rpo_hours=20.5, vm_restore_rto_minutes=90)
        cfg.save()
        continuity.check_restore_rehearsal(now)
        self.assertIsNone(active('platform:restore-rehearsal'))
        continuity.check_restore_rehearsal(now + timedelta(days=200))
        self.assertIn('más de 6 meses', active('platform:restore-rehearsal').details)

    def test_sftp_mode_is_not_affected(self):
        RecoverySettings.objects.update_or_create(pk=1, defaults={'transport': 'sftp'})
        continuity.check_restore_rehearsal(timezone.now())
        self.assertIsNone(active('platform:restore-rehearsal'))

    def test_the_form_requires_the_measurements(self):
        from .control_views import RecoveryForm
        data = {'transport': 'vm', 'retention_days': 30, 'evidence_days': 90, 'operational_email': 'noc@example.test',
                'vm_last_restore_at': '2026-10-01T10:00', 'vm_restore_isolated': 'on',
                'vm_restore_reference': 'Ensayo en Proxmox aislado, todo correcto'}
        form = RecoveryForm(data)
        self.assertFalse(form.is_valid())
        self.assertIn('vm_restore_rpo_hours', form.errors)
        self.assertIn('vm_restore_rto_minutes', form.errors)
        self.assertTrue(RecoveryForm({**data, 'vm_restore_rpo_hours': '20.5', 'vm_restore_rto_minutes': '90'}).is_valid())


@override_settings(SECURE_SSL_REDIRECT=False)
class HealthzTests(TestCase):
    def mark_job(self, ago):
        WorkerState.objects.update_or_create(name='job:health', defaults={'last_success_at': timezone.now() - ago})

    def test_healthy_soc_answers_ok_without_session(self):
        self.mark_job(timedelta(minutes=1))
        response = self.client.get(reverse('healthz'))
        self.assertEqual((response.status_code, response.content), (200, b'ok'))
        self.assertIn('no-store', response['Cache-Control'])

    def test_stalled_jobs_or_core_failures_answer_503_without_details(self):
        self.mark_job(timedelta(minutes=20))
        self.assertEqual(self.client.get(reverse('healthz')).status_code, 503)
        self.mark_job(timedelta(minutes=1))
        OperationalIssue.objects.create(key='platform:ingest-silence', title='x', details='secreto', severity='critical')
        response = self.client.get(reverse('healthz'))
        self.assertEqual((response.status_code, response.content), (503, b'revisar'))

    def test_minor_warnings_do_not_fail_the_monitor(self):
        self.mark_job(timedelta(minutes=1))
        OperationalIssue.objects.create(key='platform:real-ip', title='x', severity='warning')
        self.assertEqual(self.client.get(reverse('healthz')).status_code, 200)

    def test_scoped_operator_session_sees_platform_failures(self):
        self.mark_job(timedelta(minutes=1))
        OperationalIssue.objects.create(key='platform:disk', title='x', severity='critical')
        company = Client.objects.create(name='Cliente', code='c')
        user = get_user_model().objects.create_user('operador', 'op@example.test', 'x')
        StaffAccess.objects.create(user=user, role='operator').clients.add(company)
        self.client.force_login(user)
        with override_settings(SOC_MFA_REQUIRED=False):
            self.assertEqual(self.client.get(reverse('healthz')).status_code, 503)


class FakeResponse:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class HeartbeatTests(TestCase):
    def test_disabled_without_url_and_only_https_without_credentials(self):
        with override_settings(SOC_HEARTBEAT_URL=''):
            self.assertIsNone(continuity.send_heartbeat(timezone.now(), True))
        for url in ('http://hc.example.test/abc', 'https://user:pw@hc.example.test/abc', 'ftp://x'):
            with override_settings(SOC_HEARTBEAT_URL=url):
                self.assertEqual(continuity.heartbeat_url(), '')

    @override_settings(SOC_HEARTBEAT_URL='https://hc.example.test/ping/abc/')
    def test_pings_every_five_minutes_and_reports_failures_at_once(self):
        opened = []
        opener = mock.Mock()
        opener.open.side_effect = lambda req, timeout: opened.append(req.full_url) or FakeResponse()
        now = timezone.now()
        with mock.patch.object(continuity.http, 'build_opener', return_value=opener):
            self.assertTrue(continuity.send_heartbeat(now, True))
            self.assertIsNone(continuity.send_heartbeat(now + timedelta(minutes=1), True))
            self.assertTrue(continuity.send_heartbeat(now + timedelta(minutes=2), False))
            self.assertTrue(continuity.send_heartbeat(now + timedelta(minutes=8), False))
        self.assertEqual(opened, ['https://hc.example.test/ping/abc', 'https://hc.example.test/ping/abc/fail',
                                  'https://hc.example.test/ping/abc/fail'])

    @override_settings(SOC_HEARTBEAT_URL='https://hc.example.test/ping/abc')
    def test_network_errors_are_recorded_without_raising(self):
        opener = mock.Mock()
        opener.open.side_effect = OSError('sin red')
        with mock.patch.object(continuity.http, 'build_opener', return_value=opener):
            self.assertFalse(continuity.send_heartbeat(timezone.now(), True))
        self.assertTrue(WorkerState.objects.get(name='heartbeat').error)


class RestoreCheckCommandTests(TestCase):
    def test_reports_counts_and_integrity_without_identifiers(self):
        site = Site.objects.create(client=Client.objects.create(name='Conservas Secretas', code='c'), name='Sede', code='s')
        DeviceHealth.objects.create(device=Device.objects.create(site=site, name='FW', vendor='opnsense'),
                                    last_log_at=timezone.now() - timedelta(hours=2))
        out = StringIO()
        with mock.patch('core.management.commands.comprobar_restauracion.Command.unit_active', return_value=False):
            call_command('comprobar_restauracion', stdout=out)
        text = out.getvalue()
        self.assertIn('Clientes: 1', text)
        self.assertIn('Último registro de un equipo', text)
        self.assertIn('todas las migraciones aplicadas', text)
        self.assertIn('Cadena de auditoría: íntegra', text)
        self.assertIn('Resultado: restauración coherente', text)
        self.assertNotIn('Conservas Secretas', text)

    def test_warns_when_outbound_timers_are_running(self):
        out = StringIO()
        with mock.patch('core.management.commands.comprobar_restauracion.Command.unit_active', return_value=True):
            call_command('comprobar_restauracion', stdout=out)
        self.assertIn('deben estar parados', out.getvalue())
        self.assertIn('a revisar', out.getvalue())

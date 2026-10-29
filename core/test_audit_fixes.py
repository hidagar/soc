"""Fallos de prioridad baja de la auditoría del 29/10/2026: cada prueba reproduce lo que antes fallaba."""
import base64
import io
import json
import shutil
import subprocess
import time
from datetime import datetime
from types import SimpleNamespace
from unittest import mock, skipUnless
from zoneinfo import ZoneInfo

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse

from . import opnsense_api, provisioning, ssh_connection, unifi_cloud
from .forms import IncidentForm
from .models import AuthAttempt, BackupRun, Client, Device, MfaProfile, OperationalIssue, Site
from .recovery import queue_daily_backup
from .security import encrypt, totp
from .testing_access import FreshMfaClient

MADRID = ZoneInfo('Europe/Madrid')


class IncidentFormTests(SimpleTestCase):
    def test_the_actions_label_is_applied(self):
        # Había dos __init__: el segundo anulaba al primero.
        self.assertEqual(IncidentForm().fields['actions'].label, 'Notas de acciones (texto libre)')


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class LoginOriginTests(TestCase):
    def test_a_failure_noting_the_origin_never_breaks_login_or_skips_the_count(self):
        get_user_model().objects.create_user('real', 'real@example.test', 'A-strong-password-27!')
        with mock.patch('core.continuity.note_login_origin', side_effect=RuntimeError('base ocupada')), \
                self.assertLogs('core.security', level='ERROR'):
            response = self.client.post(reverse('login'), {'username': 'real@example.test', 'password': 'mal'},
                                        REMOTE_ADDR='127.0.0.1', HTTP_X_REAL_IP='45.155.205.233')
            self.assertEqual(response.status_code, 200)
            self.assertEqual(AuthAttempt.objects.count(), 2)  # identidad e IP: el fallo cuenta
            response = self.client.post(reverse('login'), {'username': 'real@example.test',
                                                           'password': 'A-strong-password-27!'})
            self.assertEqual(response.status_code, 302)


class DailyBackupTests(TestCase):
    def test_after_midnight_yesterdays_copy_does_not_count_as_today(self):
        BackupRun.objects.create(status='verified', created_at=datetime(2026, 10, 28, 3, 15, tzinfo=MADRID))
        # 00:30 en Madrid son las 23:30 UTC del día anterior: antes se comparaba con la fecha UTC.
        run = queue_daily_backup(datetime(2026, 10, 29, 0, 30, tzinfo=MADRID))
        self.assertIsNotNone(run)
        self.assertEqual(run.status, 'queued')

    def test_only_one_copy_per_local_day(self):
        BackupRun.objects.create(status='verified', created_at=datetime(2026, 10, 29, 0, 10, tzinfo=MADRID))
        self.assertIsNone(queue_daily_backup(datetime(2026, 10, 29, 23, 50, tzinfo=MADRID)))


@override_settings(SECURE_SSL_REDIRECT=False)
class NonNumericIdsTests(TestCase):
    client_class = FreshMfaClient

    def test_blocklist_forms_answer_404_instead_of_500(self):
        company = Client.objects.create(name='Cliente', code='c')
        self.client.force_login(get_user_model().objects.create_superuser('admin', 'admin@example.test', 'x'))
        url = reverse('blocklist_detail', args=[company.pk])
        for data in ({'action': 'manual_revoke', 'block': 'abc'}, {'action': 'unifi_policy_enable', 'binding': '1 OR 1'},
                     {'action': 'unifi_lists', 'device': '../1'}):
            self.assertEqual(self.client.post(url, data).status_code, 404, data)


class FakeKey:
    def get_name(self):
        return 'ssh-rsa'

    def get_base64(self):
        return 'QUFBQQ=='

    def asbytes(self):
        return b'AAAA'


class FakeTransport:
    host_key_type = 'ssh-rsa'  # firma RSA con SHA-1: el equipo no admite rsa-sha2

    def __init__(self, sock):
        pass

    def start_client(self, timeout=None):
        pass

    def get_remote_server_key(self):
        return FakeKey()

    def close(self):
        pass


@override_settings(SECURE_SSL_REDIRECT=False)
class Sha1SignatureTests(TestCase):
    client_class = FreshMfaClient

    def test_the_probe_reports_the_signature_algorithm_and_the_page_warns(self):
        with mock.patch.object(ssh_connection.socket, 'create_connection'), \
                mock.patch.object(ssh_connection.paramiko, 'Transport', FakeTransport):
            probe = ssh_connection.probe_host_key('192.0.2.10', 22)
        self.assertEqual(probe['algorithm'], 'ssh-rsa')
        device = Device.objects.create(site=Site.objects.create(client=Client.objects.create(name='C', code='c'),
                                                                name='S', code='s'), name='FW', vendor='opnsense')
        self.client.force_login(get_user_model().objects.create_superuser('admin', 'admin@example.test', 'x'))
        session = self.client.session
        session[f'ssh_probe_{device.pk}'] = {**probe, 'hostname': '192.0.2.10', 'port': 22, 'username': 'root'}
        session.save()
        page = self.client.get(reverse('ssh_connection', args=[device.pk]))
        self.assertContains(page, 'solo admite firmas SSH con SHA-1')


class Response:
    def __init__(self, body, content_type='application/json'):
        self.stream, self.headers = io.BytesIO(body), {'Content-Type': content_type}

    def read(self, size=-1):
        return self.stream.read(size)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class ResponseSizeTests(SimpleTestCase):
    def test_oversized_opnsense_answers_are_refused(self):
        opener = mock.Mock()
        opener.open.return_value = Response(json.dumps({'rows': ['x' * 100]}).encode())
        with mock.patch.object(opnsense_api.request, 'build_opener', return_value=opener), \
                mock.patch.object(opnsense_api, 'MAX_RESPONSE', 50):
            with self.assertRaisesMessage(opnsense_api.OpnsenseApiError, 'tamaño permitido'):
                opnsense_api._request_json('https://192.0.2.1', 'k', 's', '', '/api/core/system/status')
        opener.open.return_value = Response(b'{"status": "ok"}')
        with mock.patch.object(opnsense_api.request, 'build_opener', return_value=opener):
            self.assertEqual(opnsense_api._request_json('https://192.0.2.1', 'k', 's', '', '/x'), {'status': 'ok'})

    def test_oversized_unifi_answers_are_refused(self):
        with mock.patch.object(unifi_cloud, 'MAX_RESPONSE', 10):
            with self.assertRaises(ValueError):
                unifi_cloud._read_json(Response(b'{"data": [1, 2, 3, 4, 5]}'))
        self.assertEqual(unifi_cloud._read_json(Response(b'{"data": []}')), {'data': []})


class SshScriptParametersTests(SimpleTestCase):
    MARKER = "Centro SOC {${system('id')}} $x é"

    def script(self):
        calls = []

        def fake(connection, command, *, stdin_data=None):
            calls.append(stdin_data)
            if command == 'id -u':
                return 0, '0\n', ''
            return 0, json.dumps({'status': 'ok', 'uuid': 'u1', 'host': provisioning.DESTINATION, 'notice': ''}), ''
        with mock.patch.object(provisioning, 'run_command', side_effect=fake), \
                mock.patch.object(provisioning, '_marker', return_value=self.MARKER):
            provisioning._opnsense_ssh(SimpleNamespace(pk=7), SimpleNamespace(), provisioning.DESTINATION, 514)
        return calls[-1].decode()

    def test_values_travel_encoded_and_never_as_php_code(self):
        script = self.script()
        self.assertNotIn('system(', script)
        line = next(row for row in script.splitlines() if 'base64_decode' in row)
        encoded = line.split("base64_decode('")[1].split("')")[0]
        params = json.loads(base64.b64decode(encoded))
        self.assertEqual((params['marker'], params['port']), (self.MARKER, '514'))

    @skipUnless(shutil.which('php'), 'PHP no está instalado.')
    def test_php_reads_them_literally(self):
        line = next(row for row in self.script().splitlines() if 'base64_decode' in row).strip()
        code = line + " echo json_encode([(string)$params['marker'], (string)$params['port']]);"
        output = subprocess.run(['php', '-r', code], capture_output=True, text=True, check=True, timeout=20).stdout
        self.assertEqual(json.loads(output), [self.MARKER, '514'])


@override_settings(SECURE_SSL_REDIRECT=False)
class MfaLockoutTests(TestCase):
    SECRET = 'JBSWY3DPEHPK3PXP'

    def test_exhausting_mfa_attempts_alerts_the_soc_until_a_good_code(self):
        user = get_user_model().objects.create_user('ana', 'ana@example.test', 'x')
        MfaProfile.objects.create(user=user, enabled=True, encrypted_secret=encrypt(self.SECRET))
        self.client.force_login(user)
        url = reverse('mfa_challenge')
        for _ in range(7):
            self.client.post(url, {'code': '000000'})
        self.assertFalse(OperationalIssue.objects.filter(key__startswith='security:mfa-failures:').exists())
        self.client.post(url, {'code': '000000'})  # el octavo agota los intentos
        issue = OperationalIssue.objects.get(key=f'security:mfa-failures:{user.pk}', active=True)
        self.assertEqual(issue.severity, 'critical')
        self.assertIn('ana', issue.details)
        AuthAttempt.objects.all().delete()  # pasan los 15 minutos
        for _ in range(8):  # un segundo bloqueo reutiliza el aviso (antes: error por clave duplicada)
            self.client.post(url, {'code': '000000'})
        self.assertEqual(OperationalIssue.objects.filter(key=f'security:mfa-failures:{user.pk}').count(), 1)
        AuthAttempt.objects.all().delete()
        code = totp(self.SECRET, int(time.time() // 30))
        self.assertEqual(self.client.post(url, {'code': code}).status_code, 302)
        self.assertFalse(OperationalIssue.objects.filter(key=f'security:mfa-failures:{user.pk}', active=True).exists())

import os
import subprocess
import sys
import tempfile
from pathlib import Path

from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse

from .models import Client, ExportConfiguration, Site, Device, StaffAccess
from .release import deployed_release

COMMIT = 'a' * 40


class ReleaseTests(SimpleTestCase):
    def test_reads_only_a_full_commit_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(deployed_release(directory)['commit'], '')
            Path(directory, '.deployed-commit').write_text(COMMIT + '\n')
            release = deployed_release(directory)
            self.assertEqual((release['commit'], release['short']), (COMMIT, 'a' * 12))
            self.assertIsNotNone(release['deployed_at'])
            Path(directory, '.deployed-commit').write_text('<script>')
            self.assertEqual(deployed_release(directory)['commit'], '')


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class ReleaseOnHealthPageTests(TestCase):
    def test_only_global_staff_sees_the_installed_version(self):
        admin = get_user_model().objects.create_superuser('admin-version', 'v@example.test', 'x')
        self.client.force_login(admin)
        response = self.client.get(reverse('health_list'))
        self.assertContains(response, 'Versión instalada')
        self.assertContains(response, 'Sin registrar')
        operator = get_user_model().objects.create_user('operador-version')
        company = Client.objects.create(name='A', code='a')
        StaffAccess.objects.create(user=operator, role='operator').clients.add(company)
        self.client.force_login(operator)
        self.assertNotContains(self.client.get(reverse('health_list')), 'Versión instalada')


class ReceiverConfigurationTests(TestCase):
    def test_current_installation_values_are_the_default(self):
        from .provisioning import DESTINATION, PORT
        self.assertEqual((settings.SOC_RECEIVER_IP, settings.SOC_RECEIVER_PORT), ('172.20.10.20', 5514))
        self.assertEqual((DESTINATION, PORT), ('172.20.10.20', 5514))

    @override_settings(SOC_RECEIVER_IP='192.0.2.10', SOC_RECEIVER_PORT=6514)
    def test_new_export_configurations_use_the_configured_receiver(self):
        device = Device.objects.create(site=Site.objects.create(client=Client.objects.create(name='A', code='a'),
                                                                name='S', code='s'), name='FW', vendor='opnsense')
        config = ExportConfiguration.objects.create(device=device)
        self.assertEqual((config.destination, config.port), ('192.0.2.10', 6514))

    def test_invalid_receiver_stops_the_process(self):
        env = {**os.environ, 'SOC_PORTAL_DEBUG': '1', 'SOC_PORTAL_RECEIVER_IP': 'soc.example.test'}
        result = subprocess.run([sys.executable, 'manage.py', 'check'], cwd=settings.BASE_DIR, env=env,
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('SOC_PORTAL_RECEIVER_IP', result.stderr)

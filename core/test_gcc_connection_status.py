from unittest.mock import patch
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from .models import Client, Site, Device, GdmsConnection, ExportConfiguration
from .operations import probe_device
from .testing_access import workflow_access


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class GccStatusTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = get_user_model().objects.create_user('gcc-manager')
        workflow_access(cls.user)
        cls.customer = Client.objects.create(name='GCC customer', code='gcc-customer')
        cls.site = Site.objects.create(client=cls.customer, name='Site', code='site')
        cls.device = Device.objects.create(site=cls.site, name='GCC', vendor='grandstream_gcc', management_method='api', log_method='syslog')
        cls.connection = GdmsConnection.objects.create(device=cls.device, client_scope_id=cls.customer.pk, app_id='APP', encrypted_secret='CIPHER', last_ok=True)
        ExportConfiguration.objects.create(device=cls.device, source_ip='192.0.2.80', status='configured', receiver_ready=True)

    def test_health_checks_gdms_without_marking_receipt_or_protection(self):
        with patch('core.gdms_api.decrypt', return_value='SECRET'), patch('core.gdms_api.check_connection', return_value=True) as check, patch('core.network_coverage.discover_networks'):
            health = probe_device(self.device)
        check.assert_called_once()
        self.assertTrue(health.api_ok)
        self.assertIsNone(health.last_log_at)
        self.assertIsNone(health.engines['Grandstream GCC']['running'])
        self.device.refresh_from_db(); self.assertEqual(self.device.integration, 'pending')

    def test_foreign_credentials_are_not_used_after_move(self):
        GdmsConnection.objects.filter(pk=self.connection.pk).update(client_scope_id=self.customer.pk + 100)
        with patch('core.gdms_api.check_connection') as check:
            health = probe_device(self.device)
        check.assert_not_called(); self.assertFalse(health.api_ok)

    def test_syslog_identity_and_pending_receipt_are_clear_without_agent_id(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse('device_detail', args=[self.device.pk]))
        self.assertContains(response, 'Conexión del GCC con el SOC')
        self.assertContains(response, 'no necesita un agente Wazuh')
        self.assertContains(response, 'todavía no se ha confirmado un evento')
        self.assertContains(response, '192.0.2.80')

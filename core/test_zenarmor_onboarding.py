from .testing_access import workflow_access
import json
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from .models import Client, Device, ExportConfiguration, FirewallOnboarding
from .onboarding_verification import confirm_onboarding_events


@override_settings(SECURE_SSL_REDIRECT=False)
class ZenarmorWizardTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        from .models import Site
        cls.operator = get_user_model().objects.create_user('zen-wizard')
        workflow_access(cls.operator, reader=False)
        cls.operator.user_permissions.add(Permission.objects.get(codename='manage_connections'))
        customer = Client.objects.create(name='Laboratorio', code='zen-lab')
        cls.site = Site.objects.create(client=customer, name='Oficina', code='zen-office')

    def setUp(self):
        self.client.force_login(self.operator)

    def device(self, step=4, method='manual', enabled=True):
        device = Device.objects.create(site=self.site, name='Laboratorio', vendor='opnsense', zenarmor_enabled=enabled)
        FirewallOnboarding.objects.create(device=device, step=step, method=method,
            verification_started_at=timezone.now() - timedelta(seconds=10) if step == 5 else None)
        return device

    def event(self, decoder, when=None, source='198.51.100.50'):
        return json.dumps({'timestamp': (when or timezone.now()).isoformat(), 'location': source,
            'decoder': {'name': decoder}, 'rule': {'id': '110103' if decoder == 'zenarmor' else '5715'}})

    def test_combined_choice_maps_to_opnsense_and_persists_profile(self):
        url = reverse('onboarding_add_device', args=[self.site.pk])
        page = self.client.get(url)
        self.assertContains(page, 'OPNsense + Zenarmor')
        response = self.client.post(url, {'creation_token': page.context['creation_token'],
            'name': 'Firewall con Zenarmor', 'vendor': 'opnsense_zenarmor'})
        self.assertEqual(response.status_code, 302)
        device = Device.objects.get(name='Firewall con Zenarmor')
        self.assertEqual(device.vendor, 'opnsense')
        self.assertTrue(device.zenarmor_enabled)
        self.assertEqual(device.connection_profile_label, 'OPNsense + Zenarmor')

    def test_existing_opnsense_can_choose_profile_and_all_methods(self):
        device = self.device(step=3, enabled=False)
        url = reverse('device_onboarding', args=[device.pk])
        page = self.client.get(url)
        self.assertEqual([value for value, _ in page.context['form'].fields['method'].choices], ['api', 'ssh', 'https', 'manual'])
        self.client.post(url, {'method': 'manual', 'profile': 'opnsense_zenarmor'})
        device.refresh_from_db()
        self.assertTrue(device.zenarmor_enabled)
        self.client.post(url + '?step=3', {'method': 'manual', 'profile': 'opnsense'})
        device.refresh_from_db()
        self.assertFalse(device.zenarmor_enabled)

    def test_both_exports_must_be_confirmed_but_api_setup_can_happen_first(self):
        device = self.device()
        url = reverse('device_onboarding', args=[device.pk])
        page = self.client.get(url)
        self.assertContains(page, 'Stream Reporting Data to Syslog')
        self.assertContains(page, 'Alerts')
        data = {'destination': '172.20.10.20', 'source_ip': '198.51.100.50', 'configured': 'on'}
        self.assertContains(self.client.post(url, data), 'Configura la exportación de Zenarmor antes')
        self.assertFalse(ExportConfiguration.objects.filter(device=device).exists())
        self.assertEqual(self.client.post(url, {**data, 'zenarmor_configured': 'on'}).status_code, 302)
        api_device = self.device(method='api')
        api_url = reverse('device_onboarding', args=[api_device.pk])
        self.assertContains(self.client.get(api_url), 'Ahora configura Zenarmor')
        response = self.client.post(api_url, {'destination': '172.20.10.20', 'action': 'connection'})
        self.assertEqual(response.url, reverse('opnsense_api', args=[api_device.pk]))

    def test_verification_requires_both_in_either_order_and_shows_partial_receipt(self):
        for order in (('sshd', 'zenarmor'), ('zenarmor', 'sshd')):
            with self.subTest(order=order):
                device = self.device(step=5)
                ExportConfiguration.objects.create(device=device, source_ip='198.51.100.50', status='configured', receiver_ready=True)
                self.assertEqual(confirm_onboarding_events([self.event(order[0])]), 0)
                state = self.client.get(reverse('onboarding_status', args=[device.pk])).json()
                self.assertTrue(state['zenarmor_required'])
                self.assertFalse(state['verified'])
                self.assertEqual(state['opnsense_received'], order[0] == 'sshd')
                self.assertEqual(state['zenarmor_received'], order[0] == 'zenarmor')
                self.assertEqual(confirm_onboarding_events([self.event(order[0])]), 0)
                self.assertEqual(confirm_onboarding_events([self.event(order[1])]), 1)
                device.refresh_from_db()
                self.assertEqual(device.integration, 'connected')
                self.assertContains(self.client.get(reverse('device_onboarding', args=[device.pk])), 'OPNsense y Zenarmor en Wazuh')
                device.delete()

    def test_old_or_other_origin_zenarmor_event_does_not_complete(self):
        device = self.device(step=5)
        ExportConfiguration.objects.create(device=device, source_ip='198.51.100.50', status='configured', receiver_ready=True)
        self.assertEqual(confirm_onboarding_events([self.event('sshd'),
            self.event('zenarmor', when=device.onboarding.verification_started_at - timedelta(seconds=1)),
            self.event('zenarmor', source='198.51.100.51')]), 0)
        device.refresh_from_db()
        self.assertEqual(device.integration, 'pending')
        self.assertIsNone(device.onboarding.zenarmor_event_at)

    def test_plain_opnsense_does_not_require_zenarmor_and_cannot_use_it_as_generic_proof(self):
        device = self.device(step=5, enabled=False)
        ExportConfiguration.objects.create(device=device, source_ip='198.51.100.50', status='configured', receiver_ready=True)
        self.assertEqual(confirm_onboarding_events([self.event('zenarmor')]), 0)
        self.assertEqual(confirm_onboarding_events([self.event('sshd')]), 1)

    def test_iso_decoder_counts_as_zenarmor_not_as_opnsense(self):
        device = self.device(step=5)
        ExportConfiguration.objects.create(device=device, source_ip='198.51.100.50', status='configured', receiver_ready=True)
        self.assertEqual(confirm_onboarding_events([self.event('zenarmor-iso')]), 0)
        device.onboarding.refresh_from_db()
        self.assertTrue(device.onboarding.zenarmor_event_at)
        self.assertIsNone(device.onboarding.event_at)
        self.assertEqual(confirm_onboarding_events([self.event('sshd')]), 1)

    def test_zenarmor_profile_rejected_for_other_vendor(self):
        from django.core.exceptions import ValidationError
        device = self.device()
        device.vendor = 'unifi'
        with self.assertRaises(ValidationError):
            device.full_clean()

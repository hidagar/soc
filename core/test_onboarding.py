from .testing_access import workflow_access
import json
from datetime import timedelta
from unittest import mock

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from .models import Client, Device, ExportConfiguration, FirewallOnboarding, OpnsenseConnection, Site
from .onboarding_verification import confirm_onboarding_events


@override_settings(SECURE_SSL_REDIRECT=False)
class OnboardingTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.operator = get_user_model().objects.create_user('wizard-operator')
        workflow_access(cls.operator, reader=False)
        cls.operator.user_permissions.add(Permission.objects.get(codename='manage_connections'))
        cls.reader = get_user_model().objects.create_user('wizard-reader')
        workflow_access(cls.reader, reader=True)
        cls.customer = Client.objects.create(name='Cliente seleccionado', code='wizard-client')
        cls.other = Client.objects.create(name='Cliente ajeno', code='wizard-other')
        cls.site = Site.objects.create(client=cls.customer, name='Oficina', code='office')

    def setUp(self):
        self.client.force_login(self.operator)

    def make_device(self, vendor='unifi', step=3, method='manual'):
        device = Device.objects.create(site=self.site, name='Firewall piloto', vendor=vendor)
        FirewallOnboarding.objects.create(device=device, step=step, method=method)
        return device

    def make_verification(self, source='198.51.100.12'):
        device = self.make_device(step=5)
        row = device.onboarding
        row.verification_started_at = timezone.now() - timedelta(seconds=10)
        row.save()
        config = ExportConfiguration.objects.create(device=device, destination='172.20.10.20',
            source_ip=source, status='configured', receiver_ready=True)
        return device, row, config

    def event(self, source='198.51.100.12', when=None, decoder='soc-unifi-cef'):
        return json.dumps({'timestamp': (when or timezone.now()).isoformat(), 'location': source,
            'decoder': {'name': decoder}, 'rule': {'id': '111105', 'level': 3},
            'data': {'unifi': {'version': '10.6.106'}}, 'full_log': 'PRIVATE RAW LOG NOT FOR THE BROWSER'})

    def test_new_site_scoped_to_selected_customer_and_duplicate_submit_does_not_duplicate_site(self):
        url = reverse('site_new') + f'?client={self.customer.pk}'
        response = self.client.get(url)
        self.assertContains(response, 'Paso 1 de 5')
        self.assertContains(response, 'id="selected-client-name"')
        self.assertNotContains(response, self.other.name)
        token = response.context['creation_token']
        data = {'wizard_step': '1', 'creation_token': token, 'client': self.other.pk,
                'name': 'Nueva sede guiada', 'code': ''}
        first = self.client.post(url, data)
        second = self.client.post(url, data)
        self.assertEqual(first.url, second.url)
        created = Site.objects.get(name=data['name'])
        self.assertEqual(created.client_id, self.customer.pk)
        self.assertEqual(first.url, reverse('onboarding_add_device', args=[created.pk]))

    def test_equipment_only_requests_name_vendor_and_can_add_another(self):
        url = reverse('onboarding_add_device', args=[self.site.pk])
        response = self.client.get(url)
        self.assertContains(response, 'name="vendor"')
        self.assertNotContains(response, 'name="model"')
        data = {'creation_token': response.context['creation_token'], 'name': 'Gateway', 'vendor': 'opnsense'}
        first = self.client.post(url, data)
        second = self.client.post(url, data)
        self.assertEqual(first.url, second.url)
        self.assertEqual(Device.objects.count(), 1)
        response = self.client.get(url)  # fresh wizard for another device
        self.client.post(url, {**data, 'creation_token': response.context['creation_token'], 'name': 'Second'})
        self.assertEqual(Device.objects.count(), 2)

    def test_manual_flow_registers_receiver_without_api_ssh_and_is_not_active_yet(self):
        for vendor in ('unifi', 'opnsense', 'hillstone', 'other'):
            with self.subTest(vendor=vendor):
                device = self.make_device(vendor=vendor)
                url = reverse('device_onboarding', args=[device.pk])
                self.client.post(url, {'method': 'manual'})
                response = self.client.get(url)
                self.assertContains(response, 'Configura el envío')
                with mock.patch('core.views.provision_export') as automatic:
                    response = self.client.post(url, {'destination': '172.20.10.20',
                        'source_ip': f'198.51.100.{device.pk}', 'configured': 'on'})
                    automatic.assert_not_called()
                self.assertEqual(response.status_code, 302)
                device.refresh_from_db()
                self.assertEqual(device.management_method, 'none')
                self.assertEqual(device.integration, 'pending')
                self.assertEqual(device.onboarding.step, 5)
                self.assertFalse(device.export_configuration.receiver_ready)
                self.assertFalse(hasattr(device, 'unifi_cloud'))
                self.assertFalse(hasattr(device, 'ssh_connection'))
                self.assertFalse(hasattr(device, 'opnsense_api'))

    def test_source_for_another_client_or_equipment_is_rejected(self):
        other_site = Site.objects.create(client=self.other, name='Ajena', code='other')
        other_device = Device.objects.create(site=other_site, name='Ajeno', vendor='opnsense')
        ExportConfiguration.objects.create(device=other_device, source_ip='198.51.100.15')
        device = self.make_device(step=4)
        response = self.client.post(reverse('device_onboarding', args=[device.pk]), {
            'source_ip': '198.51.100.15', 'destination': '172.20.10.20', 'configured': 'on'})
        self.assertContains(response, 'Esta IP ya pertenece a otro equipo')
        self.assertFalse(ExportConfiguration.objects.filter(device=device).exists())

    def test_manual_requires_saved_confirmation_destination_allowlist_and_host_ip(self):
        device = self.make_device(step=4)
        url = reverse('device_onboarding', args=[device.pk])
        for data in (
            {'destination': '172.20.10.20', 'source_ip': '198.51.100.15'},
            {'destination': '8.8.8.8', 'source_ip': '198.51.100.15', 'configured': 'on'},
            {'destination': '172.20.10.20', 'source_ip': '127.0.0.1', 'configured': 'on'},
        ):
            self.assertEqual(self.client.post(url, data).status_code, 200)
            self.assertFalse(ExportConfiguration.objects.filter(device=device).exists())

    def test_no_permission_no_receiver_changes_and_unsupported_methods_rejected(self):
        self.client.force_login(self.reader)
        device = self.make_device(step=4)
        response = self.client.post(reverse('device_onboarding', args=[device.pk]), {
            'destination': '172.20.10.20', 'source_ip': '198.51.100.15', 'configured': 'on'})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(ExportConfiguration.objects.filter(device=device).exists())
        device = self.make_device(vendor='hillstone')
        url = reverse('device_onboarding', args=[device.pk])
        self.assertEqual(self.client.post(url, {'method': 'api'}).status_code, 403)
        device.onboarding.refresh_from_db()
        self.assertEqual(device.onboarding.step, 3)

    def test_automatic_connection_is_optional_and_returns_to_wizard(self):
        device = self.make_device(vendor='opnsense')
        url = reverse('device_onboarding', args=[device.pk])
        self.client.post(url, {'method': 'api'})
        data = {'destination': '172.20.10.20', 'source_ip': '198.51.100.16', 'action': 'connection'}
        response = self.client.post(url, data)
        self.assertEqual(response.url, reverse('opnsense_api', args=[device.pk]))
        self.assertContains(self.client.get(response.url), 'Volver al asistente')
        response = self.client.post(url, {**data, 'action': 'verify'})
        self.assertContains(response, 'Completa y verifica primero')
        device.onboarding.refresh_from_db()
        self.assertEqual(device.onboarding.step, 4)
        config = device.export_configuration
        config.status = 'configured'
        config.save()
        self.assertEqual(self.client.post(url, {**data, 'action': 'verify'}).status_code, 200)
        OpnsenseConnection.objects.create(device=device, api_url='https://fw.example.test',
            encrypted_api_key='encrypted', encrypted_api_secret='encrypted', last_ok=True)
        self.assertEqual(self.client.post(url, {**data, 'action': 'verify'}).status_code, 302)

    def test_get_and_poll_do_not_create_records_or_activate_device(self):
        device = Device.objects.create(site=self.site, name='Legacy', vendor='unifi')
        self.assertEqual(self.client.get(reverse('device_onboarding', args=[device.pk])).status_code, 200)
        self.assertFalse(FirewallOnboarding.objects.filter(device=device).exists())
        self.assertEqual(self.client.get(reverse('onboarding_status', args=[device.pk])).status_code, 404)
        device, row, config = self.make_verification()
        for _ in range(2):
            response = self.client.get(reverse('onboarding_status', args=[device.pk]))
            self.assertFalse(response.json()['verified'])
        self.assertEqual(self.client.post(reverse('device_onboarding', args=[device.pk]), {'verified': '1'}).status_code, 403)
        device.refresh_from_db()
        self.assertEqual(device.integration, 'pending')

    def test_automatic_export_keeps_wizard_log_origin_when_management_uses_another_ip(self):
        from .provisioning import provision_export
        device = self.make_device(vendor='opnsense', step=4, method='api')
        device.management_method = 'api'
        device.management_address = 'https://192.168.10.1'
        device.save()
        OpnsenseConnection.objects.create(device=device, api_url=device.management_address,
            encrypted_api_key='encrypted-value', encrypted_api_secret='encrypted-value', last_ok=True)
        ExportConfiguration.objects.create(device=device, source_ip='198.51.100.16', status='pending')
        with mock.patch('core.provisioning._opnsense_api', return_value='managed-target'):
            config = provision_export(device)
        self.assertEqual(config.status, 'configured')
        self.assertEqual(config.source_ip, '198.51.100.16')

    def test_api_setup_can_discover_source_before_operator_confirms_it(self):
        device = self.make_device(vendor='unifi', step=4, method='api')
        url = reverse('device_onboarding', args=[device.pk])
        response = self.client.post(url, {'destination': '172.20.10.20', 'action': 'connection'})
        self.assertEqual(response.url, reverse('unifi_cloud', args=[device.pk]))
        self.assertIsNone(device.export_configuration.source_ip)
        response = self.client.post(url, {'destination': '172.20.10.20', 'action': 'verify'})
        self.assertContains(response, 'Confirma la IP de origen')

    def test_verification_requires_new_real_matching_decoded_event_and_ready_receiver(self):
        device, row, config = self.make_verification()
        invalid = ['invalid json', 'null', self.event(source='198.51.100.88'),
                   self.event(when=row.verification_started_at - timedelta(seconds=1)),
                   self.event(decoder='sshd'), self.event(when=timezone.now() + timedelta(days=1))]
        self.assertEqual(confirm_onboarding_events(invalid), 0)
        config.receiver_ready = False
        config.save()
        self.assertEqual(confirm_onboarding_events([self.event()]), 0)
        config.receiver_ready = True
        config.save()
        self.assertEqual(confirm_onboarding_events([self.event()]), 1)
        device.refresh_from_db()
        row.refresh_from_db()
        self.assertEqual(device.integration, 'connected')
        self.assertEqual(device.software_version, '10.6.106')
        self.assertTrue(row.verified_at)
        response = self.client.get(reverse('onboarding_status', args=[device.pk]))
        self.assertTrue(response.json()['verified'])
        self.assertNotContains(response, 'PRIVATE RAW LOG')
        self.assertContains(self.client.get(reverse('device_onboarding', args=[device.pk])), 'Equipo activo')

    def test_ambiguous_source_is_not_activated_even_with_a_real_event(self):
        device, row, config = self.make_verification()
        other = self.make_device(vendor='opnsense')
        ExportConfiguration.objects.create(device=other, source_ip=config.source_ip)
        self.assertEqual(confirm_onboarding_events([self.event()]), 0)
        row.refresh_from_db()
        self.assertFalse(row.verified_at)
        self.assertIn('compartido', row.verification_error)

    def test_changing_method_resets_verification_and_progress_can_resume(self):
        device, row, config = self.make_verification()
        url = reverse('device_onboarding', args=[device.pk])
        self.assertContains(self.client.get(url), 'Paso 5 de 5')
        self.client.post(url + '?step=3', {'method': 'manual'})
        row.refresh_from_db()
        self.assertEqual(row.step, 4)
        self.assertIsNone(row.verification_started_at)
        self.assertContains(self.client.get(url), 'Paso 4 de 5')

    def test_paused_device_is_not_activated_by_background_verification(self):
        device, row, config = self.make_verification()
        device.integration = 'paused'
        device.save()
        self.assertEqual(confirm_onboarding_events([self.event()]), 0)
        row.refresh_from_db()
        self.assertFalse(row.verified_at)

    def test_operator_without_connection_permission_cannot_reset_registered_receiver(self):
        device, row, config = self.make_verification()
        self.client.force_login(self.reader)
        response = self.client.post(reverse('device_onboarding', args=[device.pk]) + '?step=3', {'method': 'manual'})
        self.assertEqual(response.status_code, 403)
        config.refresh_from_db()
        self.assertTrue(config.receiver_ready)

    def test_unauthenticated_wizard_and_status_require_login(self):
        device = self.make_device()
        self.client.logout()
        for url in (reverse('site_new'), reverse('onboarding_add_device', args=[self.site.pk]),
                    reverse('device_onboarding', args=[device.pk]), reverse('onboarding_status', args=[device.pk])):
            self.assertEqual(self.client.get(url).status_code, 302)

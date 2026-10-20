from .testing_access import workflow_access
from datetime import date
from unittest import mock

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.db.models.deletion import ProtectedError
from django.test import Client as BrowserClient, TestCase, override_settings
from django.urls import reverse

from .models import Client, Device, ExportConfiguration, FirewallOnboarding, Incident, OpnsenseConnection, Site, SshConnection, UnifiCloudConnection, WeeklyReport


@override_settings(SECURE_SSL_REDIRECT=False)
class SiteDeleteTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.operator = get_user_model().objects.create_user('site-delete-operator')
        workflow_access(cls.operator, reader=False)
        cls.operator.user_permissions.add(Permission.objects.get(codename='manage_connections'))
        cls.reader = get_user_model().objects.create_user('site-delete-reader')
        workflow_access(cls.reader, reader=True)
        cls.customer = Client.objects.create(name='Cliente de prueba', code='delete-test')
        cls.site = Site.objects.create(client=cls.customer, name='Sede de prueba', code='office')
        cls.other_site = Site.objects.create(client=cls.customer, name='Sede conservada', code='keep')
        cls.other_device = Device.objects.create(site=cls.other_site, name='Equipo conservado', vendor='unifi')

    def setUp(self):
        self.client.force_login(self.operator)
        self.url = reverse('site_delete', args=[self.site.pk])

    def equipment(self):
        first = Device.objects.create(site=self.site, name='Firewall UniFi', vendor='unifi')
        second = Device.objects.create(site=self.site, name='Firewall OPNsense', vendor='opnsense')
        UnifiCloudConnection.objects.create(device=first, encrypted_api_key='private-api-ciphertext')
        OpnsenseConnection.objects.create(device=second, api_url='https://fw.example.test',
            encrypted_api_key='private-key-ciphertext', encrypted_api_secret='private-secret-ciphertext')
        SshConnection.objects.create(device=second, hostname='fw.example.test', username='soc',
            encrypted_password='private-password-ciphertext', host_key_type='ssh-ed25519',
            host_key_base64='hostkey', fingerprint='SHA256:example')
        ExportConfiguration.objects.create(device=first, source_ip='198.51.100.12', status='configured')
        FirewallOnboarding.objects.create(device=first)
        return first, second

    def test_button_and_preview_show_scope_without_deleting_or_exposing_credentials(self):
        first, second = self.equipment()
        self.assertContains(self.client.get(reverse('site_detail', args=[self.site.pk])), 'Eliminar sede')
        response = self.client.get(self.url)
        self.assertContains(response, self.site.name)
        self.assertContains(response, first.name)
        self.assertContains(response, second.name)
        self.assertNotContains(response, self.other_device.name)
        self.assertNotContains(response, 'private-api-ciphertext')
        self.assertNotContains(response, 'private-password-ciphertext')
        self.assertTrue(Site.objects.filter(pk=self.site.pk).exists())
        self.assertEqual(Device.objects.filter(site=self.site).count(), 2)

    def test_confirmed_empty_site_deletion_keeps_client_and_other_site(self):
        response = self.client.post(self.url, {'confirm': 'yes'})
        self.assertRedirects(response, reverse('client_detail', args=[self.customer.pk]))
        self.assertFalse(Site.objects.filter(pk=self.site.pk).exists())
        self.assertTrue(Client.objects.filter(pk=self.customer.pk).exists())
        self.assertTrue(Site.objects.filter(pk=self.other_site.pk).exists())

    def test_confirmed_deletion_cleans_owned_equipment_connections_and_wizard_only(self):
        first, second = self.equipment()
        report = WeeklyReport.objects.create(client=self.customer, week_start=date(2026, 9, 28), sources=['198.51.100.12'])
        self.client.post(self.url, {'confirm': 'yes'})
        self.assertFalse(Site.objects.filter(pk=self.site.pk).exists())
        self.assertFalse(Device.objects.filter(pk__in=[first.pk, second.pk]).exists())
        for model in (UnifiCloudConnection, OpnsenseConnection, SshConnection, ExportConfiguration, FirewallOnboarding):
            self.assertFalse(model.objects.filter(device_id__in=[first.pk, second.pk]).exists())
        self.assertTrue(Device.objects.filter(pk=self.other_device.pk).exists())
        self.assertTrue(WeeklyReport.objects.filter(pk=report.pk).exists())

    def test_login_permission_and_explicit_confirmation_are_required(self):
        self.client.logout()
        self.assertEqual(self.client.get(self.url).status_code, 302)
        self.client.force_login(self.reader)
        self.assertEqual(self.client.get(self.url).status_code, 403)
        self.assertEqual(self.client.post(self.url, {'confirm': 'yes'}).status_code, 403)
        self.assertNotContains(self.client.get(reverse('site_detail', args=[self.site.pk])), 'Eliminar sede')
        self.client.force_login(self.operator)
        for value in ('', 'false', 'no'):
            response = self.client.post(self.url, {'confirm': value})
            self.assertContains(response, 'Confirma que quieres eliminar')
            self.assertTrue(Site.objects.filter(pk=self.site.pk).exists())
        self.assertEqual(self.client.delete(self.url).status_code, 405)

    def test_site_and_device_incidents_both_prevent_deletion(self):
        first, second = self.equipment()
        for related in ({'site': self.site}, {'device': first}):
            with self.subTest(related=related):
                incident = Incident.objects.create(client=self.customer, title='Incidencia que se conserva', description='Historial', **related)
                response = self.client.post(self.url, {'confirm': 'yes'})
                self.assertContains(response, 'historial')
                self.assertTrue(Site.objects.filter(pk=self.site.pk).exists())
                self.assertEqual(Device.objects.filter(site=self.site).count(), 2)
                self.assertTrue(UnifiCloudConnection.objects.filter(device=first).exists())
                self.assertTrue(Incident.objects.filter(pk=incident.pk).exists())
                incident.delete()

    def test_protected_reference_rolls_back_already_deleted_devices_and_credentials(self):
        first, second = self.equipment()
        with mock.patch.object(Site, 'delete', side_effect=ProtectedError('Protected', {self.site})):
            response = self.client.post(self.url, {'confirm': 'yes'})
        self.assertContains(response, 'No se ha borrado ningún dato')
        self.assertTrue(Site.objects.filter(pk=self.site.pk).exists())
        self.assertTrue(Device.objects.filter(pk=first.pk).exists())
        self.assertTrue(UnifiCloudConnection.objects.filter(device=first).exists())
        self.assertTrue(SshConnection.objects.filter(device=second).exists())

    def test_security_evidence_and_vpn_are_explained_before_confirming_deletion(self):
        from .models import SecurityEvidence
        from .vpn import create_peer
        from django.utils import timezone
        first,second=self.equipment()
        SecurityEvidence.objects.create(uid='a'*64,device=first,observed_at=timezone.now(),engine='unifi',signature='Evidence',level=3)
        create_peer(self.site)
        response=self.client.get(self.url)
        self.assertContains(response,'evidencias de seguridad')
        self.assertContains(response,'configuraciones VPN')
        self.assertNotContains(response,'name="confirm"')
        self.client.post(self.url,{'confirm':'yes'})
        self.assertTrue(Site.objects.filter(pk=self.site.pk).exists())
        self.assertTrue(UnifiCloudConnection.objects.filter(device=first).exists())

    def test_cross_site_request_forgery_cannot_delete(self):
        browser = BrowserClient(enforce_csrf_checks=True)
        browser.force_login(self.operator)
        self.assertEqual(browser.post(self.url, {'confirm': 'yes'}).status_code, 403)
        self.assertTrue(Site.objects.filter(pk=self.site.pk).exists())

"""Ajustes de seguridad de la revisión: MFA reciente en credenciales, sesiones y operaciones globales."""
import time
from unittest import mock

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase, override_settings
from django.urls import reverse

from .models import AuditEvent, Client, Device, MfaProfile, RecoverySettings, Site, StaffAccess
from .security import encrypt


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class FreshMfaTests(TestCase):
    def setUp(self):
        self.company = Client.objects.create(name='Empresa', code='empresa')
        self.site = Site.objects.create(client=self.company, name='Sede', code='s')
        self.device = Device.objects.create(site=self.site, name='FW', vendor='opnsense')
        self.admin = get_user_model().objects.create_superuser('admin', 'admin@example.test', 'x')
        MfaProfile.objects.create(user=self.admin, encrypted_secret=encrypt('JBSWY3DPEHPK3PXP'), enabled=True)
        self.client.force_login(self.admin)

    def mfa(self, seconds_ago):
        session = self.client.session
        session.update({'soc_mfa_user': self.admin.pk, 'soc_mfa_at': time.time() - seconds_ago, 'soc_mfa_version': 1})
        session.save()

    def test_credential_changes_need_a_recent_code_even_for_superusers(self):
        self.mfa(3600)
        posts = [('mail_settings', [], {'action': 'save'}), ('verify_public_reports', [], {}),
                 ('opnsense_api', [self.device.pk], {'action': 'save'}), ('ssh_connection', [self.device.pk], {'action': 'probe'}),
                 ('export_destination', [self.device.pk], {'destination': '192.0.2.1'}),
                 ('site_delete', [self.site.pk], {'confirm': 'yes'})]
        for name, args, data in posts:
            response = self.client.post(reverse(name, args=args), data)
            self.assertRedirects(response, reverse('mfa_challenge'), fetch_redirect_response=False, msg_prefix=name)
        self.assertTrue(Site.objects.filter(pk=self.site.pk).exists())
        # Desactivar el envío de correo es una parada segura: no espera al MFA.
        self.assertRedirects(self.client.post(reverse('mail_settings'), {'action': 'disable'}), reverse('mail_settings'),
                             fetch_redirect_response=False)
        # Consultar no exige repetir el código.
        self.assertEqual(self.client.get(reverse('opnsense_api', args=[self.device.pk])).status_code, 200)
        self.mfa(10)
        response = self.client.post(reverse('site_delete', args=[self.site.pk]), {'confirm': 'yes'})
        self.assertRedirects(response, reverse('client_detail', args=[self.company.pk]), fetch_redirect_response=False)

    @override_settings(SOC_MFA_REQUIRED=True)
    def test_verified_session_has_an_absolute_lifetime(self):
        self.mfa(60)
        self.assertEqual(self.client.get(reverse('dashboard')).status_code, 200)
        self.mfa(13 * 3600)
        self.assertRedirects(self.client.get(reverse('dashboard')), reverse('mfa_challenge'), fetch_redirect_response=False)
        self.assertNotIn('soc_mfa_user', self.client.session)


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class GlobalOperationsTests(TestCase):
    def setUp(self):
        self.company = Client.objects.create(name='Empresa', code='empresa')
        self.manager = get_user_model().objects.create_user('gestor')
        StaffAccess.objects.create(user=self.manager, role='manager').clients.add(self.company)
        self.manager.groups.add(Group.objects.get(name='SOC Administrador'))
        self.client.force_login(self.manager)
        session = self.client.session
        session.update({'soc_mfa_user': self.manager.pk, 'soc_mfa_at': time.time()})
        session.save()

    def test_scoped_manager_cannot_create_clients(self):
        response = self.client.post(reverse('client_new'), {'name': 'Nueva', 'code': 'nueva', 'active': 'on'})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(Client._base_manager.filter(code='nueva').exists())

    def test_invalid_vpn_site_is_not_found_not_a_server_error(self):
        self.assertEqual(self.client.post(reverse('vpn_sites'), {'site': 'x', 'action': 'enable'}).status_code, 404)


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class RecoveryDestinationTests(TestCase):
    def setUp(self):
        self.admin = get_user_model().objects.create_superuser('admin', 'admin@example.test', 'x')
        self.client.force_login(self.admin)
        session = self.client.session
        session.update({'soc_mfa_user': self.admin.pk, 'soc_mfa_at': time.time()})
        session.save()
        RecoverySettings.objects.update_or_create(pk=1, defaults={
            'transport': 'sftp', 'hostname': 'copias.example.test', 'port': 22, 'username': 'soc', 'remote_path': '/copias',
            'encrypted_password': encrypt('secreto-anterior'), 'fingerprint': 'SHA256:abc', 'enabled': False})

    def test_stored_password_is_not_sent_to_a_new_destination(self):
        data = {'transport': 'sftp', 'hostname': 'otro.example.test', 'port': 22, 'username': 'soc', 'password': '',
                'remote_path': '/copias', 'fingerprint': 'SHA256:nuevo', 'retention_days': 30, 'evidence_days': 365,
                'operational_email': 'noc@example.test', 'action': 'save'}
        observed = {'fingerprint': 'SHA256:nuevo', 'type': 'ssh-ed25519', 'base64': 'AAAA'}
        with mock.patch('core.ssh_connection.probe_host_key', return_value=observed):
            page = self.client.post(reverse('recovery'), data)
        self.assertContains(page, 'vuelve a escribir la contraseña')
        self.assertEqual(RecoverySettings.objects.get(pk=1).hostname, 'copias.example.test')


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class StaffAuditTests(TestCase):
    def test_account_changes_are_recorded_without_the_address(self):
        from .security import audit
        member = get_user_model().objects.create_user('persona')
        audit('staff.access', member, {'role': 'operator', 'clients': [], 'all_clients': False, 'active': False,
                                       'fields': ['email', 'active'], 'email': 'persona@example.test'})
        details = AuditEvent.objects.get(action='staff.access').details
        self.assertEqual((details['active'], details['all_clients'], details['fields']), (False, False, ['email', 'active']))
        self.assertNotIn('email', details)

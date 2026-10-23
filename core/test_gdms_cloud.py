import hashlib
import json
import os
from email.message import Message
from unittest.mock import patch
from urllib import parse, error
from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import TestCase, SimpleTestCase, override_settings
from django.urls import reverse
from . import gdms_api as api
from .models import Client, Site, Device, GdmsConnection, AuditEvent, StaffAccess
from .testing_access import FreshMfaClient, workflow_access


TOKEN = {'access_token': 'TOKEN-NEVER-PERSIST', 'token_type': 'bearer', 'expires_in': 3600}


class TransportTests(SimpleTestCase):
    def response(self, builder, payload=TOKEN):
        response = builder.return_value.open.return_value.__enter__.return_value
        response.headers = Message()
        response.headers['Content-Type'] = 'application/json'
        response.read.return_value = json.dumps(payload).encode()
        return response

    def test_documented_region_auth_and_no_token_returned(self):
        with patch.object(api.request, 'build_opener') as builder:
            response = self.response(builder)
            self.assertIs(api.check_connection('eu', '123', 'SECRET'), True)
            req = builder.return_value.open.call_args.args[0]
            self.assertEqual(parse.urlsplit(req.full_url).netloc, 'eu.gwn.cloud')
            self.assertEqual(parse.urlsplit(req.full_url).path, '/oauth/token')
            self.assertEqual(req.method, 'GET')
            self.assertEqual(parse.parse_qs(parse.urlsplit(req.full_url).query),
                {'client_id': ['123'], 'client_secret': ['SECRET'], 'grant_type': ['client_credentials']})
            response.read.assert_called_once_with(api.MAX_RESPONSE + 1)

    def test_restricted_password_uses_documented_hash(self):
        with patch.object(api.request, 'build_opener') as builder:
            self.response(builder)
            api.check_connection('us', '123', 'SECRET', True, 'operator', 'Password')
            query = parse.parse_qs(parse.urlsplit(builder.return_value.open.call_args.args[0].full_url).query)
            self.assertEqual(query['grant_type'], ['password'])
            self.assertEqual(query['password'], [hashlib.sha256(hashlib.md5(b'Password').hexdigest().encode()).hexdigest()])
            self.assertNotEqual(query['password'], ['Password'])

    def test_no_custom_host_no_redirect_no_control_character(self):
        self.assertIsNone(api.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://elsewhere.invalid'))
        for args in [('https://private.invalid', 'app', 'secret'), ('eu', 'app', 'secret\n')]:
            with patch.object(api.request, 'build_opener') as builder:
                with self.assertRaises(api.GdmsError): api.check_connection(*args)
                builder.assert_not_called()

    def test_malformed_oversized_and_false_success_are_rejected(self):
        for payload in ({'error': 'SECRET-REMOTE'}, [], {}, {**TOKEN, 'expires_in': True}, {**TOKEN, 'token_type': 'bad'}):
            with patch.object(api.request, 'build_opener') as builder:
                self.response(builder, payload)
                with self.assertRaises(api.GdmsError) as caught: api.check_connection('eu', 'app', 'secret')
                self.assertNotIn('SECRET-REMOTE', str(caught.exception))
        with patch.object(api.request, 'build_opener') as builder:
            self.response(builder).read.return_value = b'x' * (api.MAX_RESPONSE + 1)
            with self.assertRaises(api.GdmsError): api.check_connection('eu', 'app', 'secret')

    def test_remote_errors_never_echo_url_or_body(self):
        with patch.object(api.request, 'build_opener') as builder:
            builder.return_value.open.side_effect = error.HTTPError('https://vendor/?client_secret=PRIVATE', 401, 'PRIVATE', {}, None)
            with self.assertRaises(api.GdmsError) as caught: api.check_connection('eu', 'app', 'PRIVATE')
            self.assertNotIn('PRIVATE', str(caught.exception))


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class ConnectionTests(TestCase):
    client_class = FreshMfaClient  # credential views require a fresh MFA
    @classmethod
    def setUpTestData(cls):
        cls.user = get_user_model().objects.create_user('gdms-operator')
        workflow_access(cls.user)
        cls.user.user_permissions.add(Permission.objects.get(codename='manage_connections'))
        cls.customer = Client.objects.create(name='Cloud customer', code='cloud-customer')
        cls.site = Site.objects.create(client=cls.customer, name='Site', code='site')
        cls.device = Device.objects.create(site=cls.site, name='GCC', vendor='grandstream_gcc', model='GCC6010W')

    def setUp(self):
        self.client.force_login(self.user)
        self.url = reverse('gdms_cloud', args=[self.device.pk])
        env = patch.dict(os.environ, {'SOC_PORTAL_SSH_KEY': Fernet.generate_key().decode()})
        env.start(); self.addCleanup(env.stop)

    def save(self, **kwargs):
        return self.client.post(self.url, {'action': 'save', 'region': 'eu', 'app_id': '123', 'secret': 'PRIVATE-SECRET', **kwargs})

    def test_encrypted_save_blank_preserves_secret_and_ui_links(self):
        with patch.object(api, 'check_connection') as check:
            self.assertEqual(self.save().status_code, 302)
            check.assert_not_called()
        conn = GdmsConnection.objects.get(device=self.device)
        self.assertNotIn('PRIVATE-SECRET', conn.encrypted_secret)
        self.assertEqual(api.decrypt(conn.encrypted_secret), 'PRIVATE-SECRET')
        self.assertNotContains(self.client.get(self.url), 'PRIVATE-SECRET')
        self.assertNotIn('PRIVATE-SECRET', repr(list(AuditEvent.objects.values())))
        self.assertEqual(self.save(secret='').status_code, 302)
        conn.refresh_from_db(); self.assertEqual(api.decrypt(conn.encrypted_secret), 'PRIVATE-SECRET')
        self.assertContains(self.client.get(reverse('device_detail', args=[self.device.pk])), self.url)
        self.assertContains(self.client.get(reverse('api_connections')), self.url)
        self.assertContains(self.client.get(reverse('device_onboarding', args=[self.device.pk]) + '?step=3'), self.url)

    def test_test_auth_only_does_not_activate_device_or_logs_and_throttles(self):
        self.save()
        with patch.object(api, 'check_connection', return_value=True) as check:
            self.assertContains(self.client.post(self.url, {'action': 'test'}), 'Autenticación GDMS correcta')
            self.client.post(self.url, {'action': 'test'})
            self.assertEqual(check.call_count, 1)
        self.assertTrue(GdmsConnection.objects.get(device=self.device).last_ok)
        self.device.refresh_from_db()
        self.assertEqual(self.device.integration, 'pending')
        self.assertEqual(self.device.log_method, 'none')
        self.assertEqual(self.device.management_method, 'none')

    def test_changed_identity_requires_new_secret_and_restricted_password(self):
        self.save()
        self.assertContains(self.save(secret='', region='us'), 'Introduce Secret Key')
        self.assertContains(self.save(restricted='on', username='operator'), 'Introduce la contraseña')
        self.assertEqual(self.save(restricted='on', username='operator', password='PRIVATE-PASSWORD').status_code, 302)
        conn = GdmsConnection.objects.get(device=self.device)
        self.assertEqual(api.decrypt(conn.encrypted_password), 'PRIVATE-PASSWORD')
        self.assertNotContains(self.client.get(self.url), 'PRIVATE-PASSWORD')
        self.assertEqual(self.save().status_code, 302)
        conn.refresh_from_db(); self.assertEqual(conn.encrypted_password, '')

    def test_access_permission_vendor_and_customer_scope(self):
        self.user.user_permissions.remove(Permission.objects.get(codename='manage_connections'))
        self.assertEqual(self.client.get(self.url).status_code, 403)
        self.user.user_permissions.add(Permission.objects.get(codename='manage_connections'))
        Device.objects.filter(pk=self.device.pk).update(vendor='unifi')
        self.assertEqual(self.client.get(self.url).status_code, 404)
        Device.objects.filter(pk=self.device.pk).update(vendor='grandstream_gcc')
        other = Client.objects.create(name='Other', code='other')
        access = StaffAccess.objects.get(user=self.user)
        access.all_clients = False; access.save(); access.clients.add(other)
        self.assertEqual(self.client.get(self.url).status_code, 404)
        self.assertEqual(self.save().status_code, 404)

    def test_reassignment_cannot_reuse_prior_clients_credentials(self):
        self.save()
        other = Client.objects.create(name='Other', code='other')
        self.site.client = other; self.site.save()
        self.assertNotContains(self.client.get(self.url), 'value="123"')
        with patch.object(api, 'check_connection') as check:
            self.client.post(self.url, {'action': 'test'}); check.assert_not_called()
        self.assertContains(self.save(secret=''), 'Introduce Secret Key')
        self.assertEqual(self.save().status_code, 302)
        self.assertEqual(GdmsConnection.objects.get(device=self.device).client_scope_id, other.pk)

    def test_failure_and_concurrent_credentials_change_do_not_mark_verified(self):
        self.save()
        with patch.object(api, 'check_connection', side_effect=api.GdmsError('Acceso rechazado.')):
            self.assertContains(self.client.post(self.url, {'action': 'test'}), 'Acceso rechazado.')
        self.assertFalse(GdmsConnection.objects.get(device=self.device).last_ok)
        GdmsConnection.objects.filter(device=self.device).update(last_checked_at=None)
        def concurrent_save(*args):
            GdmsConnection.objects.filter(device=self.device).update(encrypted_secret=api.encrypt('NEW'), last_checked_at=None)
        with patch.object(api, 'check_connection', side_effect=concurrent_save):
            self.assertContains(self.client.post(self.url, {'action': 'test'}), 'ha cambiado')
        self.assertFalse(GdmsConnection.objects.get(device=self.device).last_ok)

    def test_csrf_required_and_credentials_can_be_removed(self):
        from django.test import Client as HttpClient
        strict = HttpClient(enforce_csrf_checks=True); strict.force_login(self.user)
        self.assertEqual(strict.post(self.url, {'action': 'save'}).status_code, 403)
        self.save()
        self.assertEqual(self.client.post(self.url, {'action': 'remove'}).status_code, 302)
        self.assertFalse(GdmsConnection.objects.exists())

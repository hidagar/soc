"""Bloque 8: rotar claves sin perder secretos ni MFA."""
import time
from io import StringIO
from unittest import mock

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.core.management import CommandError, call_command
from django.test import TestCase, override_settings

from .models import Client, Device, MfaProfile, Site, UnifiCloudConnection, UserInvitation
from .security import decrypt, encrypt, totp, verify_token
from .unifi_cloud import decrypt_api_key, encrypt_api_key

OLD_UNIFI, NEW_UNIFI, NEW_VAULT = (Fernet.generate_key().decode() for _ in range(3))
SECRET = 'JBSWY3DPEHPK3PXP'


@override_settings(SOC_VAULT_KEYS='')
class KeyRotationTests(TestCase):
    def setUp(self):
        user = get_user_model().objects.create_user('analista')
        self.mfa = MfaProfile.objects.create(user=user, enabled=True, encrypted_secret=encrypt(SECRET))
        device = Device.objects.create(site=Site.objects.create(client=Client.objects.create(name='A', code='a'),
                                                                name='S', code='s'), name='FW', vendor='unifi')
        with mock.patch.dict('os.environ', {'SOC_PORTAL_UNIFI_KEY': OLD_UNIFI}):
            self.unifi = UnifiCloudConnection.objects.create(device=device, encrypted_api_key=encrypt_api_key('api-key-1'))
        self.broken = UserInvitation.objects.create(user=user, recipient='a@example.test', token_hash='x',
                                                    encrypted_token='no-es-un-token', expires_at=self.mfa.updated_at)

    def run_command(self, *args):
        out = StringIO()
        try:
            call_command('rotate_encryption_keys', *args, stdout=out)
        except CommandError as exc:
            return out.getvalue(), str(exc)
        return out.getvalue(), ''

    def stored(self):
        self.mfa.refresh_from_db()
        self.unifi.refresh_from_db()
        return self.mfa.encrypted_secret, self.unifi.encrypted_api_key

    def test_dry_run_reports_families_without_changing_anything(self):
        before = self.stored()
        with override_settings(SOC_VAULT_KEYS=NEW_VAULT), \
                mock.patch.dict('os.environ', {'SOC_PORTAL_UNIFI_KEY': f'{NEW_UNIFI},{OLD_UNIFI}'}):
            output, error = self.run_command()
        self.assertEqual(self.stored(), before)
        self.assertIn('core_mfaprofile.encrypted_secret: 1 filas · vault', output)
        self.assertIn('core_unificloudconnection.encrypted_api_key: 1 filas · unifi', output)
        self.assertIn('core_userinvitation.encrypted_token: 1 filas · sin descifrar', output)
        self.assertNotIn(SECRET, output)
        self.assertIn('1 valores no se han recifrado', error)

    def test_apply_moves_every_secret_to_the_new_keys_and_mfa_keeps_working(self):
        with override_settings(SOC_VAULT_KEYS=NEW_VAULT), \
                mock.patch.dict('os.environ', {'SOC_PORTAL_UNIFI_KEY': f'{NEW_UNIFI},{OLD_UNIFI}'}):
            self.run_command('--apply')
        mfa_token, unifi_token = self.stored()
        # Solo con las claves nuevas: la bóveda ya no depende de SECRET_KEY.
        self.assertEqual(Fernet(NEW_VAULT.encode()).decrypt(mfa_token.encode()).decode(), SECRET)
        with override_settings(SOC_VAULT_KEYS=NEW_VAULT, SECRET_KEY='otra-clave-de-django'):
            self.assertEqual(decrypt(mfa_token), SECRET)
            code = totp(SECRET, int(time.time() // 30))
            self.assertTrue(verify_token(self.mfa, code, recovery=False))
        with mock.patch.dict('os.environ', {'SOC_PORTAL_UNIFI_KEY': NEW_UNIFI}):
            self.assertEqual(decrypt_api_key(unifi_token), 'api-key-1')
        self.broken.refresh_from_db()
        self.assertEqual(self.broken.encrypted_token, 'no-es-un-token')

    def test_without_new_keys_nothing_is_lost(self):
        with mock.patch.dict('os.environ', {'SOC_PORTAL_UNIFI_KEY': OLD_UNIFI}):
            self.run_command('--apply')
            self.assertEqual(decrypt_api_key(self.stored()[1]), 'api-key-1')
        self.assertEqual(decrypt(self.stored()[0]), SECRET)

    def test_new_values_are_encrypted_with_the_first_key(self):
        with override_settings(SOC_VAULT_KEYS=f'{NEW_VAULT},{Fernet.generate_key().decode()}'):
            token = encrypt('valor')
        self.assertEqual(Fernet(NEW_VAULT.encode()).decrypt(token.encode()), b'valor')

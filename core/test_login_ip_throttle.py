from django.contrib.auth import get_user_model
from django.test import RequestFactory, SimpleTestCase, TestCase, override_settings

from .models import AuthAttempt
from .security import client_ip

LOGIN = '/login/'


class ClientIpTests(SimpleTestCase):
    def ip(self, remote, real=None):
        extra = {'REMOTE_ADDR': remote}
        if real is not None:
            extra['HTTP_X_REAL_IP'] = real
        return client_ip(RequestFactory().post(LOGIN, **extra))

    def test_header_is_trusted_only_from_the_local_proxy(self):
        self.assertEqual(self.ip('127.0.0.1', '203.0.113.5'), '203.0.113.5')
        self.assertEqual(self.ip('198.51.100.9', '203.0.113.5'), '198.51.100.9')

    def test_unattributable_requests_have_no_ip_instead_of_the_proxy(self):
        self.assertIsNone(self.ip('127.0.0.1'))
        self.assertIsNone(self.ip('127.0.0.1', 'no-es-ip'))
        self.assertIsNone(self.ip('127.0.0.1', '127.0.0.1'))


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False, SOC_LOGIN_IP_LIMIT=5)
class LoginIpThrottleTests(TestCase):
    def setUp(self):
        get_user_model().objects.create_user('real', 'real@example.test', 'A-strong-password-27!')

    def post(self, username, ip, password='wrong', remote='127.0.0.1'):
        return self.client.post(LOGIN, {'username': username, 'password': password},
                                REMOTE_ADDR=remote, HTTP_X_REAL_IP=ip)

    def test_spraying_many_usernames_from_one_ip_is_limited(self):
        for index in range(5):
            self.assertEqual(self.post(f'usuario{index}@example.test', '203.0.113.5').status_code, 200)
        self.assertEqual(self.post('real@example.test', '203.0.113.5', 'A-strong-password-27!').status_code, 429)
        # Otra IP no queda afectada y el usuario real puede entrar desde ella.
        self.assertEqual(self.post('real@example.test', '198.51.100.20', 'A-strong-password-27!').status_code, 302)

    def test_success_does_not_reset_the_ip_counter(self):
        for index in range(4):
            self.post(f'usuario{index}@example.test', '203.0.113.5')
        self.assertEqual(self.post('real@example.test', '203.0.113.5', 'A-strong-password-27!').status_code, 302)
        self.client.logout()
        self.post('otro@example.test', '203.0.113.5')
        self.assertEqual(self.post('real@example.test', '203.0.113.5', 'A-strong-password-27!').status_code, 429)

    def test_missing_proxy_header_never_blocks_everyone(self):
        for index in range(12):
            self.client.post(LOGIN, {'username': f'usuario{index}@example.test', 'password': 'wrong'})
        self.assertEqual(AuthAttempt.objects.count(), 12)
        self.assertEqual(self.client.post(LOGIN, {'username': 'real@example.test',
                                                  'password': 'A-strong-password-27!'}).status_code, 302)

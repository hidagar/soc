"""Política de sesión documentada en docs/security.md: 2 horas desde su último cambio, no por inactividad."""
import time

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.sessions.models import Session
from django.test import TestCase, override_settings
from django.urls import reverse

from .security import MFA_SESSION_MAX
from .testing_access import FreshMfaClient


@override_settings(SECURE_SSL_REDIRECT=False)
class SessionPolicyTests(TestCase):
    client_class = FreshMfaClient

    def test_browsing_does_not_extend_the_session(self):
        self.assertEqual(settings.SESSION_COOKIE_AGE, 7200)
        self.assertTrue(settings.SESSION_EXPIRE_AT_BROWSER_CLOSE)
        self.assertFalse(getattr(settings, 'SESSION_SAVE_EVERY_REQUEST', False))
        self.assertGreater(MFA_SESSION_MAX, settings.SESSION_COOKIE_AGE)  # segunda barrera
        user = get_user_model().objects.create_superuser('admin', 'admin@example.test', 'x')
        self.client.force_login(user)
        key = self.client.session.session_key
        expires = Session.objects.get(session_key=key).expire_date
        time.sleep(1.1)
        for name in ('dashboard', 'incident_list', 'client_list'):
            self.assertEqual(self.client.get(reverse(name)).status_code, 200)
        self.assertEqual(Session.objects.get(session_key=key).expire_date, expires)

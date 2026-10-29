"""Cadena de auditoría: pasada completa diaria por partes y comprobación rápida de lo posterior en la página."""
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from .models import AuditEvent, OperationalIssue, WorkerState
from .security import audit, audit_status, check_audit_chain
from .testing_access import FreshMfaClient


class AuditChainTests(TestCase):
    def setUp(self):
        for n in range(5):
            audit('test.event', details={'count': n})

    def test_daily_pass_then_only_new_events_are_checked(self):
        details = check_audit_chain()
        self.assertTrue(details['ok'])
        self.assertEqual(details['verified_pk'], AuditEvent.objects.order_by('-pk').first().pk)
        self.assertEqual(audit_status()['recent'], 0)
        audit('test.event', details={'count': 9})
        status = audit_status()
        self.assertEqual((status['ok'], status['recent']), (True, 1))
        # Una hora después no se repite la pasada: sigue la del día.
        self.assertEqual(check_audit_chain(timezone.now() + timedelta(hours=1))['pass_at'], details['pass_at'])

    def test_a_tampered_new_event_is_caught_by_the_page(self):
        check_audit_chain()
        event = audit('test.event', details={'count': 9})
        AuditEvent.objects.filter(pk=event.pk).update(details={'count': 10})
        self.assertFalse(audit_status()['ok'])

    def test_a_tampered_old_event_is_caught_by_the_next_daily_pass(self):
        check_audit_chain()
        AuditEvent.objects.filter(pk=AuditEvent.objects.order_by('pk').first().pk).update(action='test.otro')
        details = check_audit_chain(timezone.now() + timedelta(hours=25))
        self.assertFalse(details['ok'])
        self.assertFalse(audit_status()['ok'])
        issue = OperationalIssue.objects.get(key='platform:audit-integrity', active=True)
        self.assertEqual(issue.severity, 'critical')

    def test_deleting_already_checked_events_is_detected(self):
        check_audit_chain()
        AuditEvent.objects.order_by('-pk').first().delete()
        status = audit_status()
        self.assertFalse(status['ok'])
        self.assertTrue(status['truncated'])

    def test_the_pass_is_split_across_runs_when_time_runs_out(self):
        details = check_audit_chain(budget=0)  # tiempo agotado tras el primer evento
        self.assertTrue(details['in_progress'])
        for _ in range(10):
            details = check_audit_chain(budget=0)
            if not details['in_progress']:
                break
        self.assertTrue(details['ok'])
        self.assertEqual(details['verified_pk'], AuditEvent.objects.order_by('-pk').first().pk)

    def test_before_the_first_pass_the_page_checks_everything_as_before(self):
        self.assertFalse(WorkerState.objects.filter(name='audit-integrity').exists())
        self.assertEqual(audit_status(), {'ok': True, 'full_at': None})


@override_settings(SECURE_SSL_REDIRECT=False)
class AuditPageTests(TestCase):
    client_class = FreshMfaClient

    def test_page_shows_when_the_full_check_ran(self):
        admin = get_user_model().objects.create_superuser('admin', 'admin@example.test', 'x')
        audit('test.event', details={'count': 1})
        check_audit_chain()
        self.client.force_login(admin)
        page = self.client.get(reverse('audit_log'))
        self.assertContains(page, 'La cadena de registros conserva su integridad.')
        self.assertContains(page, 'Comprobación completa el')

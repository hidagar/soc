"""Bloque 8: ancla externa de la auditoría; detecta que se borre o altere el final de la cadena."""
from datetime import timedelta
from unittest import mock

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from . import audit_anchor
from .mail_delivery import MailDeliveryError
from .models import AuditAnchor, AuditEvent, MailSettings, OperationalIssue, StaffAccess
from .security import audit

SEND = 'core.mail_delivery.send_customer_email'


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class AuditAnchorTests(TestCase):
    def setUp(self):
        MailSettings.objects.create(pk=1, from_email='soc@example.test', enabled=True, last_test_ok=True, encrypted_api_key='opaque',
                                    report_copy_email='noc@example.test')
        for index in range(3):
            audit('test.event', details={'count': index})
        self.now = timezone.now()

    def anchor(self, now=None, **kwargs):
        with mock.patch(SEND, return_value='sg-1', **kwargs) as send:
            result = audit_anchor.check(now or self.now)
        return result, send

    def test_daily_anchor_sends_only_the_head_of_the_chain(self):
        anchor, send = self.anchor()
        last = AuditEvent.objects.order_by('-pk').first()
        self.assertEqual((anchor.event_id, anchor.digest, anchor.event_count, anchor.status), (last.pk, last.digest, 3, 'accepted'))
        recipient, subject, plain, html = send.call_args.args
        self.assertEqual(recipient, 'noc@example.test')
        self.assertIn('Ancla de auditoría', subject)
        self.assertIn(last.digest, plain)
        self.assertNotIn('test.event', plain + html)
        self.assertEqual(send.call_args.kwargs['delivery_context'], {'kind': 'audit'})
        again, send_again = self.anchor(self.now + timedelta(hours=2))
        self.assertIsNone(again)
        send_again.assert_not_called()
        self.assertEqual(self.anchor(self.now + timedelta(hours=25))[0].event_count, 3)

    def test_configured_recipient_takes_precedence(self):
        with mock.patch.dict('os.environ', {'SOC_PORTAL_AUDIT_ANCHOR_EMAIL': 'auditoria@example.test'}):
            anchor, _ = self.anchor()
        self.assertEqual(anchor.recipient, 'auditoria@example.test')

    def test_truncating_the_audit_after_an_anchor_raises_a_critical_issue(self):
        self.anchor()
        AuditEvent.objects.order_by('-pk').first().delete()
        self.anchor(self.now + timedelta(hours=1))
        issue = OperationalIssue.objects.get(key=audit_anchor.ISSUE_BROKEN, active=True)
        self.assertEqual(issue.severity, 'critical')

    def test_altering_the_anchored_event_is_detected(self):
        anchor, _ = self.anchor()
        AuditEvent.objects.filter(pk=anchor.event_id).update(digest='0' * 64)
        self.assertEqual(audit_anchor.broken_anchors(), [anchor])

    def test_new_events_after_the_anchor_are_fine(self):
        self.anchor()
        audit('test.event', details={'count': 9})
        self.anchor(self.now + timedelta(hours=1))
        self.assertFalse(OperationalIssue.objects.filter(key=audit_anchor.ISSUE_BROKEN, active=True).exists())

    def test_uncertain_send_is_not_retried_and_missing_anchors_are_reported(self):
        anchor, _ = self.anchor(side_effect=MailDeliveryError('red'))
        self.assertEqual(anchor.status, 'uncertain')
        self.assertEqual(AuditAnchor.objects.count(), 1)
        self.anchor(self.now + timedelta(days=4), side_effect=MailDeliveryError('red'))
        self.assertTrue(OperationalIssue.objects.filter(key=audit_anchor.ISSUE_MISSING, active=True).exists())

    def test_without_recipient_nothing_is_sent_and_it_is_reported(self):
        MailSettings.objects.update(report_copy_email='')
        anchor, send = self.anchor()
        self.assertIsNone(anchor)
        send.assert_not_called()
        self.assertIn('destinatario', OperationalIssue.objects.get(key=audit_anchor.ISSUE_MISSING).details)

    def test_audit_page_checks_an_anchor_received_by_email(self):
        anchor, _ = self.anchor()
        user = get_user_model().objects.create_user('seguridad')
        StaffAccess.objects.create(user=user, role='manager', all_clients=True)
        user.user_permissions.add(Permission.objects.get(codename='manage_security'))
        self.client.force_login(user)
        url = reverse('audit_log')
        self.assertContains(self.client.get(url), 'Ancla externa')
        self.assertContains(self.client.get(url, {'evento': anchor.event_id, 'huella': anchor.digest}), 'Coincide')
        self.assertContains(self.client.get(url, {'evento': anchor.event_id, 'huella': 'a' * 64}), 'No coincide')
        self.assertContains(self.client.get(url, {'evento': 'x', 'huella': 'corta'}), 'Escribe el número del evento')
        with mock.patch(SEND, return_value='sg-2'):
            self.client.post(reverse('audit_anchor_send'))
        self.assertEqual(AuditAnchor.objects.count(), 2)

    def test_housekeeping_runs_the_anchor(self):
        from .background_jobs import execute
        with mock.patch('core.audit_anchor.check') as check, mock.patch('core.security.check_audit_chain'):
            execute('housekeeping')
        check.assert_called_once()

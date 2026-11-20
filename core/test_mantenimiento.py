"""Mantenimiento: conservación de registros operativos, vuelta tras el MFA y recordatorio de propuestas sin decidir."""
import time
from datetime import timedelta
from unittest import mock

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from . import policy_views
from .models import (ChatChannel, ChatNotice, Client, ConnectivityEvent, CustomerRequest, CustomerRequestEntry, MfaProfile,
                     PolicyProposal, StaffAccess, ThreatIntelLookup, UrgentAlert)
from .retention import prune
from .security import MFA_NEXT, encrypt, totp


class RetentionTests(TestCase):
    def setUp(self):
        self.now = timezone.now()
        self.company = Client.objects.create(name='Empresa A', code='a')

    def old(self, model, pk, field, days):
        model._base_manager.filter(pk=pk).update(**{field: self.now - timedelta(days=days)})

    def test_operational_records_are_pruned_after_their_period(self):
        channel = ChatChannel.objects.create(client=self.company, kind='telegram', chat_id='-100', enabled=True)
        alert = UrgentAlert.objects.create(client=self.company, event_uid='u1', fingerprint='f1', kind='security_allowed',
                                           observed_at=self.now, source_ip='192.0.2.10')
        other = ChatChannel.objects.create(client=self.company, kind='teams', enabled=True)
        sent = ChatNotice.objects.create(alert=alert, channel=channel, status='delivered')
        pending = ChatNotice.objects.create(alert=alert, channel=other, status='pending')
        for notice in (sent, pending):
            self.old(ChatNotice, notice.pk, 'created_at', 400)
        old_cut = ConnectivityEvent.objects.create(client=self.company, kind='down', observed_at=self.now - timedelta(days=401),
                                                   event_key='a')
        recent_cut = ConnectivityEvent.objects.create(client=self.company, kind='down', observed_at=self.now - timedelta(days=300),
                                                      event_key='b')
        old_request = CustomerRequest.objects.create(client=self.company, kind='question', subject='Antigua', status='resolved',
                                                     resolved_at=self.now - timedelta(days=731))
        CustomerRequestEntry.objects.create(request=old_request, kind='customer', text='hola')
        open_request = CustomerRequest.objects.create(client=self.company, kind='question', subject='Abierta',
                                                      created_at=self.now - timedelta(days=900))
        obsolete = PolicyProposal.objects.create(client=self.company, kind='ips_block', key='k1', title='t', change='c', risk='r',
                                                 status='obsolete')
        self.old(PolicyProposal, obsolete.pk, 'updated_at', 181)
        recent_obsolete = PolicyProposal.objects.create(client=self.company, kind='ips_block', key='k2', title='t', change='c',
                                                        risk='r', status='obsolete')
        done = ThreatIntelLookup.objects.create(value='192.0.2.1', status='done', requested_at=self.now - timedelta(days=91))
        queued = ThreatIntelLookup.objects.create(value='192.0.2.2', status='queued', requested_at=self.now - timedelta(days=91))
        result = prune(self.now)
        self.assertFalse(result['pending'])
        self.assertEqual(list(ChatNotice.objects.values_list('pk', flat=True)), [pending.pk])  # sin terminar: se conserva
        self.assertEqual(list(ConnectivityEvent.objects.values_list('pk', flat=True)), [recent_cut.pk])
        self.assertFalse(ConnectivityEvent.objects.filter(pk=old_cut.pk).exists())
        self.assertEqual(list(CustomerRequest.objects.values_list('pk', flat=True)), [open_request.pk])
        self.assertFalse(CustomerRequestEntry.objects.exists())
        self.assertEqual(list(PolicyProposal.objects.values_list('pk', flat=True)), [recent_obsolete.pk])
        self.assertEqual(list(ThreatIntelLookup.objects.values_list('pk', flat=True)), [queued.pk])
        self.assertFalse(ThreatIntelLookup.objects.filter(pk=done.pk).exists())


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=True)
class MfaReturnTests(TestCase):
    """Tras confirmar el código, el usuario vuelve a donde estaba (solo a páginas del portal y de su ámbito)."""

    def setUp(self):
        self.company = Client.objects.create(name='Empresa A', code='a')
        self.secret = 'JBSWY3DPEHPK3PXP'

    def login(self, role='operator', fresh=False):
        user = get_user_model().objects.create_user('persona', password='x')
        access = StaffAccess.objects.create(user=user, role=role, all_clients=role != 'customer')
        if role == 'customer':
            access.clients.add(self.company)
        user.user_permissions.add(Permission.objects.get(codename='manage_operations'))
        profile = MfaProfile.objects.create(user=user, encrypted_secret=encrypt(self.secret), enabled=True)
        self.client.force_login(user)
        if fresh:
            session = self.client.session
            session.update({'soc_mfa_user': user.pk, 'soc_mfa_version': profile.version, 'soc_mfa_at': time.time() - 3600})
            session.save()
        return user

    def verify(self):
        return self.client.post(reverse('mfa_challenge'), {'code': totp(self.secret, int(time.time()) // 30)})

    def test_a_page_asked_before_the_code_is_opened_after_it(self):
        self.login()
        response = self.client.get(reverse('client_list') + '?q=a')
        self.assertRedirects(response, reverse('mfa_challenge'), fetch_redirect_response=False)
        self.assertRedirects(self.verify(), reverse('client_list') + '?q=a', fetch_redirect_response=False)

    def test_an_action_returns_to_the_page_it_was_sent_from_without_repeating_it(self):
        self.login(fresh=True)  # sesión verificada, pero no reciente para una operación sensible
        page = reverse('blocklist_detail', args=[self.company.pk])
        response = self.client.post(page, {'action': 'rotate'}, HTTP_REFERER='http://testserver' + page + '?solo=qfeeds')
        self.assertRedirects(response, reverse('mfa_challenge'), fetch_redirect_response=False)
        self.assertEqual(self.client.session[MFA_NEXT], page + '?solo=qfeeds')
        self.assertRedirects(self.verify(), page + '?solo=qfeeds', fetch_redirect_response=False)

    def test_external_or_unsafe_destinations_are_ignored(self):
        self.login(fresh=True)
        page = reverse('blocklist_detail', args=[self.company.pk])
        self.client.post(page, {'action': 'rotate'}, HTTP_REFERER='https://evil.example/robar')
        self.assertNotIn(MFA_NEXT, self.client.session)
        session = self.client.session
        session[MFA_NEXT] = '//evil.example/'
        session.save()
        self.assertRedirects(self.verify(), reverse('dashboard'), fetch_redirect_response=False)

    def test_a_customer_only_returns_to_the_customer_portal(self):
        self.login(role='customer')
        session = self.client.session
        session[MFA_NEXT] = reverse('client_list')
        session.save()
        self.assertRedirects(self.verify(), reverse('customer_home'), fetch_redirect_response=False)


class PolicyReminderTests(TestCase):
    def setUp(self):
        self.now = timezone.now()
        self.company = Client.objects.create(name='Empresa A', code='a', task_notices_enabled=True)

    def proposal(self, key, days, notice='accepted', **extra):
        return PolicyProposal.objects.create(client=self.company, kind='ips_block', key=key, title='t', change='c', risk='r',
                                             status='offered', offered_at=self.now - timedelta(days=days), notice_status=notice,
                                             notice_recipient='it@a.test', notice_sent_at=self.now - timedelta(days=days),
                                             customer_title='Cambio', customer_text='x', **extra)

    def test_one_reminder_after_fourteen_days_without_decision(self):
        due = self.proposal('due', 15)
        recent = self.proposal('recent', 10)
        unsent = self.proposal('unsent', 20, notice='failed')
        self.assertEqual(policy_views.queue_reminders(self.now), 1)
        self.assertEqual(policy_views.queue_reminders(self.now), 0)  # repetir no duplica
        due.refresh_from_db()
        self.assertEqual((due.notice_status, due.reminded_at), ('queued', self.now))
        for other in (recent, unsent):
            other.refresh_from_db()
            self.assertIsNone(other.reminded_at)
        with mock.patch('core.mail_delivery.send_customer_email', return_value='m2') as send:
            self.assertEqual(policy_views.send_pending(now=self.now), 1)
        self.assertTrue(send.call_args.args[1].startswith('Recordatorio: cambios de seguridad pendientes'))
        self.assertIn('desde hace más de dos semanas', send.call_args.args[2])
        due.refresh_from_db()
        self.assertEqual(due.notice_status, 'accepted')
        # Semanas después solo entra la que entonces cumple 14 días; la ya recordada no se repite.
        self.assertEqual(policy_views.queue_reminders(self.now + timedelta(days=30)), 1)
        due.refresh_from_db()
        recent.refresh_from_db()
        self.assertEqual((due.reminded_at, due.notice_status), (self.now, 'accepted'))
        self.assertIsNotNone(recent.reminded_at)

    def test_decided_or_disabled_clients_get_no_reminder(self):
        approved = self.proposal('a', 20)
        PolicyProposal.objects.filter(pk=approved.pk).update(status='approved')
        Client.objects.filter(pk=self.company.pk).update(task_notices_enabled=False)
        self.proposal('b', 20)
        self.assertEqual(policy_views.queue_reminders(self.now), 0)

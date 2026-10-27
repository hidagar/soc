"""Bloqueo proactivo visto por el cliente (portal e informe) y acceso directo desde la investigación de IP."""
import time
from datetime import date, timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from .blocklist_efficacy import client_protection, state_name
from .models import (BlocklistFeed, ChangePlan, Client, Device, ManualBlock, SecurityEvidence, Site, StaffAccess,
                     WeeklyReport, WorkerState)

ATTACKER = '45.155.205.233'


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class CustomerProtectionTests(TestCase):
    def setUp(self):
        self.now = timezone.now()
        self.company = Client.objects.create(name='Conservas Roselló', code='rosello', customer_portal_detail_enabled=True)
        self.device = Device.objects.create(site=Site.objects.create(client=self.company, name='Fábrica', code='f'),
                                            name='FW-Rosello', vendor='opnsense', management_method='api')
        self.feed = BlocklistFeed.objects.create(client=self.company, enabled=True, generated_at=self.now,
                                                 entries=[{'ip': ATTACKER, 'reasons': ['MOTIVO INTERNO']},
                                                          {'ip': '185.220.101.4', 'reasons': ['x']}])
        ManualBlock.objects.create(client=self.company, network='185.191.171.45', reason='CASO INTERNO 128',
                                   expires_at=self.now + timedelta(days=1))
        self.plan = ChangePlan.objects.create(device=self.device, template='crowdsec', title='Bloqueo', status='active')
        today = timezone.localdate()
        WorkerState.objects.create(name=state_name(self.plan), details={
            'checked_at': self.now.isoformat(), 'history': {today.isoformat(): 30, (today - timedelta(days=3)).isoformat(): 12,
                                                            (today - timedelta(days=20)).isoformat(): 500}})
        self.customer = get_user_model().objects.create_user('cliente')
        StaffAccess.objects.create(user=self.customer, role='customer').clients.add(self.company)

    def test_projection_has_only_aggregates_and_needs_an_active_rule_and_list(self):
        data = client_protection(self.company, now=self.now)
        self.assertEqual(data, {'inbound': {'entries': 2, 'packets': 42, 'firewalls': ['FW-Rosello'], 'measured': True}})
        BlocklistFeed.objects.filter(pk=self.feed.pk).update(stopped=True)
        self.assertIsNone(client_protection(self.company, now=self.now), 'con el freno echado no se presume protección')
        BlocklistFeed.objects.filter(pk=self.feed.pk).update(stopped=False)
        ChangePlan.objects.filter(pk=self.plan.pk).update(status='rolled_back')
        self.assertIsNone(client_protection(self.company, now=self.now))

    def test_portal_shows_the_protection_without_ips_or_internal_reasons(self):
        self.client.force_login(self.customer)
        page = self.client.get(reverse('customer_firewalls'))
        self.assertContains(page, 'Bloqueo proactivo del SOC')
        self.assertContains(page, '<strong>42</strong>')
        for secret in (ATTACKER, 'MOTIVO INTERNO', 'CASO INTERNO', '185.191.171.45'):
            self.assertNotContains(page, secret)

    def test_weekly_report_counts_only_its_week(self):
        from .reporting import report_context
        today = timezone.localdate()
        monday = today - timedelta(days=today.weekday())
        report = WeeklyReport.objects.create(client=self.company, week_start=monday, sources=['192.0.2.1'])
        expected = 30 + (12 if (today - timedelta(days=3)) >= monday else 0)
        self.assertEqual(report_context(report)['proactive']['inbound']['packets'], expected)
        old = WeeklyReport.objects.create(client=self.company, week_start=date(2020, 1, 6), sources=['192.0.2.1'])
        self.assertEqual(report_context(old)['proactive']['inbound']['packets'], 0)

    def test_ip_investigation_offers_blocking_in_the_affected_client_list(self):
        SecurityEvidence.objects.create(uid='a' * 64, device=self.device, observed_at=self.now - timedelta(hours=1),
                                        engine='suricata', signature='ET SCAN', source_ip=ATTACKER, destination_ip='10.0.0.5',
                                        action='blocked', level=8, client_scope_id=self.company.pk)
        admin = get_user_model().objects.create_superuser('admin', 'a@example.test', 'x')
        self.client.force_login(admin)
        session = self.client.session
        session.update({'soc_mfa_user': admin.pk, 'soc_mfa_at': time.time()})
        session.save()
        page = self.client.get(reverse('ip_investigation'), {'ip': ATTACKER})
        link = reverse('blocklist_detail', args=[self.company.pk]) + '?network=' + ATTACKER
        self.assertContains(page, 'Bloquear en la lista de Conservas Roselló')
        self.assertContains(page, link)
        self.assertContains(self.client.get(link), f'value="{ATTACKER}"')

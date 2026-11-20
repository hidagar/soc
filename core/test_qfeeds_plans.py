"""Q-Feeds en la lista de bloqueo (como CrowdSec), revisión en la página del cliente y consulta de contexto."""
import io
import json
import os
import time
from datetime import timedelta
from unittest import mock
from urllib import error as urlerror

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import TestCase, override_settings
from django.urls import reverse

from . import threat_intel
from . import test_threat_intel as base
from .blocklist import refresh_feeds, servable
from .models import BlocklistFeed, IpReputation, OperationalIssue, StaffAccess, ThreatIntelLookup, ThreatIntelReview
from .test_threat_intel import ATTACKER, C2, KEY, OTHER_C2, FakeApi


def login(test, *perms, all_clients=True):
    user = get_user_model().objects.create_user('analista')
    access = StaffAccess.objects.create(user=user, role='operator', all_clients=all_clients)
    if not all_clients:
        access.clients.add(test.company)
    for codename in perms:
        user.user_permissions.add(Permission.objects.get(codename=codename))
    test.client.force_login(user)
    session = test.client.session
    session.update({'soc_mfa_user': user.pk, 'soc_mfa_at': time.time()})
    session.save()
    return user


class Base(TestCase):
    setUp = base.ThreatIntelTests.setUp
    sync = base.ThreatIntelTests.sync

    def ready(self):
        self.sync()
        threat_intel.refresh_matches(self.now)


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class BlocklistQFeedsTests(Base):
    """Q-Feeds es una fuente más de la lista, con el criterio de CrowdSec: solo IPs vistas en las detecciones."""

    def feed(self, **extra):
        values = {'client': self.company, 'enabled': True, 'include_lists': False, 'include_cti': False, 'include_qfeeds': True,
                  'outbound_enabled': True, 'include_c2_detections': False, 'include_qfeeds_c2': True, **extra}
        return BlocklistFeed.objects.create(**values)

    def test_new_lists_include_qfeeds_like_crowdsec_and_outbound_is_opt_in(self):
        feed = BlocklistFeed.objects.create(client=self.company)
        self.assertEqual((feed.include_lists, feed.include_qfeeds, feed.include_qfeeds_c2), (True, True, False))

    def test_without_current_qfeeds_lists_nothing_enters(self):
        feed = self.feed()
        refresh_feeds(self.now)
        feed.refresh_from_db()
        self.assertEqual((feed.entries, feed.outbound_entries), ([], []))

    def test_only_observed_ips_enter_and_dismissed_destinations_do_not(self):
        self.ready()
        ThreatIntelReview.objects.create(client=self.other, ip=OTHER_C2, decision='dismissed')
        feed = self.feed()
        refresh_feeds(self.now)
        feed.refresh_from_db()
        inbound = {e['ip']: e for e in feed.entries}
        self.assertIn(ATTACKER, inbound)
        self.assertTrue(inbound[ATTACKER]['qfeeds_only'])
        self.assertIn('Q-Feeds: Botnet', inbound[ATTACKER]['reasons'])
        self.assertEqual([e['ip'] for e in feed.outbound_entries], [C2])  # OTHER_C2 descartado en la revisión
        self.assertIn(ATTACKER, servable(feed, self.now))
        self.assertEqual(servable(feed, self.now, outbound=True), [C2])

    def test_disabling_the_option_stops_serving_qfeeds_entries_at_once(self):
        self.ready()
        feed = self.feed()
        refresh_feeds(self.now)
        BlocklistFeed.objects.filter(pk=feed.pk).update(include_qfeeds=False, include_qfeeds_c2=False)
        feed.refresh_from_db()
        self.assertNotIn(ATTACKER, servable(feed, self.now))
        self.assertEqual(servable(feed, self.now, outbound=True), [])

    def test_clients_without_the_option_get_nothing_from_qfeeds(self):
        self.ready()
        feed = self.feed(include_qfeeds=False, include_qfeeds_c2=False)
        refresh_feeds(self.now)
        feed.refresh_from_db()
        self.assertEqual((feed.entries, feed.outbound_entries), ([], []))

    def test_crowdsec_reason_keeps_an_entry_when_qfeeds_is_disabled(self):
        self.ready()
        IpReputation.objects.create(ip=ATTACKER, listed=True, lists_checked_at=self.now)
        feed = self.feed(include_lists=True)
        refresh_feeds(self.now)
        feed.refresh_from_db()
        entry = next(e for e in feed.entries if e['ip'] == ATTACKER)
        self.assertNotIn('qfeeds_only', entry)
        BlocklistFeed.objects.filter(pk=feed.pk).update(include_qfeeds=False)
        feed.refresh_from_db()
        self.assertIn(ATTACKER, servable(feed, self.now))

    def test_settings_save_the_qfeeds_options_next_to_crowdsec(self):
        self.ready()
        feed = BlocklistFeed.objects.create(client=self.company, include_qfeeds=False)
        login(self, 'manage_operations')
        page = self.client.get(reverse('blocklist_detail', args=[self.company.pk]))
        self.assertContains(page, 'IPs en listas de Q-Feeds')
        self.assertNotContains(page, 'Q-Feeds sin configurar')
        self.client.post(reverse('blocklist_detail', args=[self.company.pk]),
                         {'action': 'settings', 'enabled': 'on', 'include_qfeeds': 'on', 'include_qfeeds_c2': 'on',
                          'max_entries': '100'})
        feed.refresh_from_db()
        self.assertTrue(feed.include_qfeeds and feed.include_qfeeds_c2)


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class PilotReviewTests(Base):
    """Revisión de lo que aporta Q-Feeds en la página de la lista del cliente."""

    def setUp(self):
        Base.setUp(self)
        self.ready()
        self.feed = BlocklistFeed.objects.create(client=self.company, enabled=True, include_lists=False, include_cti=False,
                                                 include_qfeeds=True, outbound_enabled=True, include_c2_detections=False,
                                                 include_qfeeds_c2=True)
        refresh_feeds(self.now)
        self.feed.refresh_from_db()
        login(self, 'manage_operations')

    def test_outbound_entries_say_whether_this_client_contacted_them(self):
        entry = next(e for e in self.feed.outbound_entries if e['ip'] == C2)
        self.assertEqual((entry['here'], entry['here_allowed']), (1, 1))

    def test_page_summarises_qfeeds_and_filters_its_entries(self):
        url = reverse('blocklist_detail', args=[self.company.pk])
        page = self.client.get(url)
        self.assertContains(page, 'Q-Feeds en esta lista')
        self.assertContains(page, 'Contactados por este cliente')
        self.assertContains(page, 'Solo Q-Feeds')
        filtered = self.client.get(url, {'solo': 'qfeeds'})
        self.assertContains(filtered, 'mostrando solo Q-Feeds')
        self.assertContains(filtered, C2)

    def test_exclude_adds_the_ip_to_the_exceptions_and_removes_it(self):
        url = reverse('blocklist_detail', args=[self.company.pk])
        self.client.post(url, {'action': 'exclude', 'ip': C2})
        self.client.post(url, {'action': 'exclude', 'ip': C2})  # repetir no la duplica
        self.feed.refresh_from_db()
        self.assertEqual(self.feed.allowlist.count(C2), 1)
        self.assertIn('excluida en la revisión (Q-Feeds)', self.feed.allowlist)
        self.assertNotIn(C2, [e['ip'] for e in self.feed.outbound_entries])
        response = self.client.post(url, {'action': 'exclude', 'ip': '8.8.8.8'})
        self.assertContains(response, 'ya no está en la lista')


LOOKUP = {'value': C2, 'matched': True, 'ioc': {
    'verdict': 'malicious', 'score': 85, 'source_count': 3, 'first_seen': '2026-10-01T08:00:00Z', 'last_seen': '2026-11-19T08:00:00Z',
    'verdict_reasons': ['Seen on 3 independent sources (+30)'], 'tags': [{'name': 'c2'}],
    'notes': [{'text': 'nota interna del analista'}],
    'mitre_attack': [{'id': 'T1071.001', 'name': 'Web Protocols', 'tactics': [{'name': 'Command and Control'}]}],
    'enrichments': [{'source': 'geoip', 'data': {'country_name': 'Netherlands', 'asn_org': 'Example Hosting'}}],
    'linked_iocs': {'outbound_total': 1, 'inbound_total': 0}},
    'meta': {'lookups_limit_month': 5000, 'lookups_used_month': 11, 'lookups_remaining_month': 4989}}


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class LookupTests(Base):
    def request(self, value=C2):
        return self.client.post(reverse('threat_intel_lookup'), {'value': value})

    def test_sync_records_the_soc_license_and_lookup_quota(self):
        index = {**json.loads(json.dumps(FakeApi().index)),
                 'company_info': {'token_expiration': (self.now + timedelta(days=10)).isoformat(), 'premium_access': True}}
        self.sync(FakeApi(index=index))
        values = threat_intel.details()
        self.assertEqual((values['lookup']['available'], values['lookup']['remaining']), (True, 4990))
        self.assertTrue(values['license']['premium'])
        self.assertTrue(OperationalIssue.objects.filter(key=threat_intel.LICENSE_ISSUE, active=True).exists())

    def test_lookup_not_in_the_license_does_not_pause_the_lists(self):
        self.sync(FakeApi(lookup=403))
        values = threat_intel.details()
        self.assertFalse(values['lookup']['available'])
        self.assertNotIn('paused_until', values)
        self.assertTrue(threat_intel.usable_feeds())

    def test_only_indicators_already_in_the_lists_are_queued_once(self):
        self.ready()
        login(self, 'manage_operations')
        self.request('8.8.8.8')
        self.assertFalse(ThreatIntelLookup.objects.exists())
        self.request()
        self.request()
        self.assertEqual(ThreatIntelLookup.objects.filter(value=C2, status='queued').count(), 1)

    def test_without_lookup_in_the_license_nothing_is_queued(self):
        self.sync(FakeApi(lookup=403))
        login(self, 'manage_operations')
        self.request()
        self.assertFalse(ThreatIntelLookup.objects.exists())

    def test_job_stores_a_bounded_summary_and_keeps_the_queue_on_429(self):
        ThreatIntelLookup.objects.create(value=C2)

        def opener(req):
            self.assertNotIn(KEY, req.full_url)
            return io.BytesIO(json.dumps(LOOKUP).encode())
        with mock.patch.dict(os.environ, {'SOC_PORTAL_QFEEDS_KEY': KEY}), mock.patch.object(threat_intel, '_open', opener):
            self.assertEqual(threat_intel.process_lookups(self.now), 1)
        item = ThreatIntelLookup.objects.get()
        self.assertEqual((item.status, item.matched, item.result['score'], item.result['mitre'][0]['id']),
                         ('done', True, 85, 'T1071.001'))
        self.assertNotIn('nota interna', json.dumps(item.result))
        self.assertEqual(threat_intel.details()['lookup']['remaining'], 4989)
        ThreatIntelLookup.objects.create(value=ATTACKER)

        def limited(req):
            raise urlerror.HTTPError(req.full_url, 429, 'error', {}, None)
        with mock.patch.dict(os.environ, {'SOC_PORTAL_QFEEDS_KEY': KEY}), mock.patch.object(threat_intel, '_open', limited):
            threat_intel.process_lookups(self.now)
        self.assertEqual(ThreatIntelLookup.objects.get(value=ATTACKER).status, 'queued')

    def test_page_shows_the_context(self):
        self.ready()
        ThreatIntelLookup.objects.create(value=C2, status='done', matched=True, done_at=self.now,
                                         result=threat_intel._clean_ioc(LOOKUP['ioc']))
        login(self, 'manage_operations')
        page = self.client.get(reverse('threat_intel'), {'q': C2})
        self.assertContains(page, 'Contexto de Q-Feeds')
        self.assertContains(page, 'puntuación 85/100')
        self.assertContains(page, 'T1071.001 Web Protocols (Command and Control)')
        self.assertContains(page, 'Maliciosa')
        self.assertContains(page, '01/10/2026')
        self.assertNotContains(page, 'gasta 1 consulta')  # consultado hace menos de 7 días


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class KeyRejectionTests(Base):
    """La clave rechazada se explica, y una clave nueva se prueba sin esperar a la pausa de una hora."""

    def test_rejections_explain_the_likely_cause(self):
        self.sync(FakeApi(error=401))
        self.assertIn('sin espacios ni comillas', threat_intel.details()['error'])
        later = self.now + timedelta(hours=2)
        self.sync(FakeApi(error=403), now=later)
        self.assertIn('no permite la IP de este servidor', threat_intel.details()['error'])
        login(self, 'manage_operations')
        with mock.patch('django.utils.timezone.now', return_value=later):
            page = self.client.get(reverse('threat_intel'))
        self.assertContains(page, 'no permite la IP de este servidor')
        self.assertContains(page, 'Se reintenta a partir de las')

    def test_a_new_key_is_tried_at_once_and_the_same_key_waits(self):
        self.sync(FakeApi(error=401))
        api = self.sync(now=self.now + timedelta(minutes=15))
        self.assertEqual(api.requests, [])  # misma clave: espera la hora de pausa
        api = self.sync(now=self.now + timedelta(minutes=15), key='otra-clave-nueva-123')
        self.assertTrue(api.requests)
        values = threat_intel.details()
        self.assertEqual(values['error'], '')
        self.assertNotIn('paused_key', values)

"""Inteligencia Q-Feeds (fase 1): descarga local, consulta, coincidencias con los clientes y página."""
import base64
import io
import json
import os
from datetime import timedelta
from unittest import mock
from urllib import error as urlerror

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from . import threat_intel
from .background_jobs import JOBS
from .models import (Client, Device, ExportConfiguration, IpReputation, OperationalIssue, SecurityEvidence, Site, StaffAccess,
                     ThreatIndicator, ThreatIntelMatch, WorkerState)

KEY = 'qf-test-key'
ATTACKER = '45.155.205.10'
C2 = '91.92.240.5'
IN_NETWORK = '185.220.101.33'
PARTNER = '81.0.0.5'
OTHER_C2 = '94.102.49.7'
INDEX = {'feeds': [
    {'feed_type': 'malware_ip', 'type': 'ip', 'licensed': True, 'updated_at': '2026-11-05T08:00:00Z', 'next_update': '2026-11-06T08:00:00Z'},
    {'feed_type': 'malware_domains', 'type': 'domain', 'licensed': True, 'updated_at': '2026-11-05T08:00:00Z'},
    {'feed_type': 'malicious_urls', 'type': 'url', 'licensed': False}]}
META = {'category': {'botnet': {'id': 1, 'name': 'Botnet'}, 'c2': {'id': 2, 'name': 'Control remoto (C2)'}}}
IPS = {'feed': 'malware_ip', 'kind': 'ip', 'generated_at': '2026-11-05T08:00:00Z', 'meta': META,
       'iocs': {ATTACKER: {'m': [1]}, C2: {'m': [2]}, '185.220.101.0/24': {'m': [1]}, PARTNER: {'m': [1]}, OTHER_C2: {'m': [2]},
                '10.0.0.9': {}, '1.0.0.0/8': {}, 'no-es-una-ip': {}}}
DOMAINS = {'feed': 'malware_domains', 'kind': 'domain', 'generated_at': '2026-11-05T08:00:00Z',
           'iocs': {'Malo.Example.com.': {}, 'mal..dominio': {}}}


class FakeApi:
    def __init__(self, index=INDEX, ips=IPS, domains=DOMAINS, error=None):
        self.index, self.ips, self.domains, self.error, self.requests = index, ips, domains, error, []

    def __call__(self, req):
        self.requests.append(req)
        if self.error:
            raise urlerror.HTTPError(req.full_url, self.error, 'error', {}, None)
        if '/licenses.php' in req.full_url:
            body = self.index
        else:
            body = self.ips if 'feed_type=malware_ip' in req.full_url else self.domains
        return io.BytesIO(json.dumps(body).encode())


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class ThreatIntelTests(TestCase):
    def setUp(self):
        self.now = timezone.now()
        self.company = Client.objects.create(name='Empresa A', code='a')
        self.other = Client.objects.create(name='Empresa B', code='b')
        self.device = Device.objects.create(site=Site.objects.create(client=self.company, name='Sede', code='s'), name='FW-A', vendor='opnsense')
        self.other_device = Device.objects.create(site=Site.objects.create(client=self.other, name='Sede B', code='sb'), name='FW-B', vendor='opnsense')
        ExportConfiguration.objects.create(device=self.other_device, source_ip=PARTNER)
        flows = [(self.device, ATTACKER, '10.0.0.5', 'allowed'), (self.device, ATTACKER, '10.0.0.5', 'blocked'),
                 (self.device, '10.0.0.7', C2, 'allowed'), (self.device, IN_NETWORK, '10.0.0.5', 'blocked'),
                 (self.device, '10.0.0.8', PARTNER, 'allowed'), (self.other_device, '10.1.0.4', OTHER_C2, 'blocked')]
        for index, (device, source, destination, action) in enumerate(flows):
            SecurityEvidence.objects.create(uid=f'{index:064x}', device=device, observed_at=self.now - timedelta(hours=3),
                                            engine='suricata', signature='Firma', source_ip=source, destination_ip=destination,
                                            action=action, level=8, client_scope_id=device.site.client_id)

    def sync(self, api=None, now=None, key=KEY):
        api = api or FakeApi()
        with mock.patch.dict(os.environ, {'SOC_PORTAL_QFEEDS_KEY': key}), mock.patch.object(threat_intel, '_open', api):
            threat_intel.sync(now or self.now)
        return api

    def test_download_keeps_only_valid_public_indicators_and_sends_the_key_in_the_header(self):
        api = self.sync()
        rows = dict(ThreatIndicator.objects.values_list('value', 'kind'))
        self.assertEqual(rows, {ATTACKER: 'ip', C2: 'ip', '185.220.101.0/24': 'net', PARTNER: 'ip', OTHER_C2: 'ip',
                                'malo.example.com': 'domain'})
        self.assertEqual(ThreatIndicator.objects.get(value=C2).categories, ['c2'])
        feeds = threat_intel.details()['feeds']
        self.assertEqual((feeds['malware_ip']['count'], feeds['malware_ip']['rejected']), (5, 3))
        self.assertEqual(feeds['malware_domains']['rejected'], 1)
        self.assertNotIn('malicious_urls', feeds)
        for req in api.requests:
            self.assertNotIn(KEY, req.full_url)
            self.assertEqual(req.get_header('Authorization'), 'Basic ' + base64.b64encode(f'api_token:{KEY}'.encode()).decode())
        self.assertEqual(len(api.requests), 3)

    def test_unchanged_lists_are_not_downloaded_again(self):
        self.sync()
        later = self.now + timedelta(hours=2)
        api = self.sync(now=later)
        self.assertEqual(len(api.requests), 1)
        self.assertEqual(threat_intel.details()['feeds']['malware_ip']['checked_at'], later.isoformat())

    def test_new_version_replaces_the_local_copy(self):
        self.sync()
        index = json.loads(json.dumps(INDEX))
        index['feeds'][0]['updated_at'] = '2026-11-05T12:00:00Z'
        ips = {**IPS, 'iocs': {ATTACKER: {'m': [2]}, '8.8.4.4': {}}}
        self.sync(FakeApi(index=index, ips=ips), now=self.now + timedelta(hours=4))
        self.assertEqual(set(ThreatIndicator.objects.filter(feed='malware_ip').values_list('value', flat=True)), {ATTACKER, '8.8.4.4'})
        self.assertEqual(ThreatIndicator.objects.get(value=ATTACKER).categories, ['c2'])
        self.assertEqual(threat_intel.details()['feeds']['malware_ip']['removed'], 4)

    def test_rejected_key_pauses_and_old_data_stops_being_used_then_is_deleted(self):
        self.sync()
        api = self.sync(FakeApi(error=401), now=self.now + timedelta(hours=1))
        values = threat_intel.details()
        self.assertEqual(values['error'], 'clave rechazada')
        self.assertIn('paused_until', values)
        self.assertTrue(OperationalIssue.objects.filter(key=threat_intel.ISSUE, active=True).exists())
        self.assertEqual(threat_intel.usable_feeds(values, self.now + timedelta(hours=1)), {'malware_ip', 'malware_domains'})
        paused = self.sync(FakeApi(), now=self.now + timedelta(minutes=90))
        self.assertEqual(paused.requests, [])
        self.assertEqual(len(api.requests), 1)
        self.sync(FakeApi(error=500), now=self.now + timedelta(hours=37))
        self.assertEqual(threat_intel.usable_feeds(now=self.now + timedelta(hours=37)), set())
        self.assertTrue(OperationalIssue.objects.filter(key=threat_intel.ISSUE, active=True).exists())
        self.sync(FakeApi(error=500), now=self.now + timedelta(days=8))
        self.assertFalse(ThreatIndicator.objects.exists())

    def test_oversized_list_is_rejected_without_touching_the_copy(self):
        self.sync()
        index = json.loads(json.dumps(INDEX))
        index['feeds'][0]['updated_at'] = '2026-11-05T12:00:00Z'
        with mock.patch.object(threat_intel, 'MAX_FEED', 100):
            self.sync(FakeApi(index=index), now=self.now + timedelta(hours=1))
        self.assertEqual(threat_intel.details()['error'], 'respuesta demasiado grande')
        self.assertEqual(ThreatIndicator.objects.filter(feed='malware_ip').count(), 5)

    def test_without_key_nothing_is_requested(self):
        api = self.sync(key='')
        self.assertEqual(api.requests, [])
        self.assertEqual(threat_intel.lookup(ATTACKER)['status'], 'not_configured')

    def test_local_lookup_of_ip_network_and_domain(self):
        self.sync()
        hit = threat_intel.lookup(C2)
        self.assertEqual(hit['status'], 'ok')
        self.assertEqual(hit['hits'][0]['categories'], ['Control remoto (C2)'])
        self.assertEqual(threat_intel.lookup(IN_NETWORK)['hits'][0]['match'], '185.220.101.0/24')
        self.assertEqual(threat_intel.lookup('MALO.example.com.')['hits'][0]['label'], 'Dominios maliciosos')
        self.assertEqual(threat_intel.lookup('8.8.8.8')['hits'], [])

    def test_matches_cover_inbound_sources_and_outbound_destinations_but_never_protected_addresses(self):
        self.sync()
        IpReputation.objects.create(ip=ATTACKER, listed=True, lists_checked_at=self.now)
        self.assertEqual(threat_intel.refresh_matches(self.now), 4)
        rows = {(m.client_id, m.ip, m.role): m for m in ThreatIntelMatch.objects.all()}
        out = rows[(self.company.pk, C2, 'destination')]
        self.assertEqual((out.events, out.allowed, out.peers, out.categories), (1, 1, ['10.0.0.7'], ['Control remoto (C2)']))
        attacker = rows[(self.company.pk, ATTACKER, 'source')]
        self.assertEqual((attacker.events, attacker.allowed, attacker.crowdsec_listed), (2, 1, True))
        self.assertFalse(rows[(self.company.pk, IN_NETWORK, 'source')].crowdsec_listed)
        self.assertIn((self.other.pk, OTHER_C2, 'destination'), rows)
        self.assertFalse(any(ip == PARTNER for _, ip, _ in rows))

    def test_matches_disappear_when_the_lists_are_no_longer_current(self):
        self.sync()
        threat_intel.refresh_matches(self.now)
        threat_intel.refresh_matches(self.now + timedelta(hours=37))
        self.assertFalse(ThreatIntelMatch.objects.exists())

    def test_page_requires_permission_and_shows_only_the_operator_clients(self):
        self.sync()
        threat_intel.refresh_matches(self.now)
        user = get_user_model().objects.create_user('analista')
        access = StaffAccess.objects.create(user=user, role='operator')
        access.clients.add(self.company)
        self.client.force_login(user)
        self.assertEqual(self.client.get(reverse('threat_intel')).status_code, 403)
        user.user_permissions.add(Permission.objects.get(codename='manage_operations'))
        page = self.client.get(reverse('threat_intel'))
        self.assertContains(page, C2)
        self.assertContains(page, '1 con tráfico permitido')
        self.assertNotContains(page, OTHER_C2)
        self.assertNotContains(page, 'Empresa B')
        found = self.client.get(reverse('threat_intel'), {'q': 'malo.example.com'})
        self.assertContains(found, 'Dominios maliciosos')
        self.assertContains(self.client.get(reverse('threat_intel'), {'q': '<script>'}), 'Escribe una IP o un dominio válidos.')

    def test_plan_without_categories_is_explained(self):
        self.sync()
        self.assertEqual(threat_intel.details()['feeds']['malware_ip']['categorized'], 5)
        index = json.loads(json.dumps(INDEX))
        index['feeds'][0]['updated_at'] = index['feeds'][1]['updated_at'] = '2026-11-05T12:00:00Z'
        plain = {**IPS, 'meta': {'verdicts': {}}, 'iocs': {ip: {'t': 1762329600} for ip in (ATTACKER, C2)}}
        self.sync(FakeApi(index=index, ips=plain), now=self.now + timedelta(hours=1))
        threat_intel.refresh_matches(self.now + timedelta(hours=1))
        user = get_user_model().objects.create_user('global')
        StaffAccess.objects.create(user=user, role='operator', all_clients=True)
        user.user_permissions.add(Permission.objects.get(codename='manage_operations'))
        self.client.force_login(user)
        with mock.patch('django.utils.timezone.now', return_value=self.now + timedelta(hours=1)):
            page = self.client.get(reverse('threat_intel'))
        self.assertContains(page, 'el plan actual de Q-Feeds publica solo los indicadores')
        self.assertContains(page, 'Sin categoría en este plan')

    def test_copies_from_before_the_count_get_it_without_downloading_again(self):
        self.sync()
        state = WorkerState.objects.get(name=threat_intel.STATE)
        del state.details['feeds']['malware_ip']['categorized']
        state.save()
        api = self.sync(now=self.now + timedelta(hours=1))
        self.assertEqual(len(api.requests), 1)
        self.assertEqual(threat_intel.details()['feeds']['malware_ip']['categorized'], 5)

    def test_categories_are_shown_when_the_plan_has_them(self):
        self.sync()
        threat_intel.refresh_matches(self.now)
        user = get_user_model().objects.create_user('global')
        StaffAccess.objects.create(user=user, role='operator', all_clients=True)
        user.user_permissions.add(Permission.objects.get(codename='manage_operations'))
        self.client.force_login(user)
        page = self.client.get(reverse('threat_intel'))
        self.assertContains(page, 'Control remoto (C2)')
        self.assertNotContains(page, 'Sin categoría en este plan')

    def test_ip_investigation_shows_the_local_lookup(self):
        self.sync()
        user = get_user_model().objects.create_user('global')
        StaffAccess.objects.create(user=user, role='operator', all_clients=True)
        self.client.force_login(user)
        page = self.client.get(reverse('ip_investigation'), {'ip': C2, 'days': 7})
        self.assertContains(page, 'Inteligencia Q-Feeds')
        self.assertContains(page, 'Control remoto (C2)')

    def test_job_is_registered_and_runs_both_steps(self):
        self.assertIn('threat_intel', JOBS)
        from .background_jobs import execute
        with mock.patch.object(threat_intel, 'sync') as sync, mock.patch.object(threat_intel, 'refresh_matches', return_value=3):
            self.assertEqual(execute('threat_intel'), 3)
        sync.assert_called_once()
        self.assertFalse(WorkerState.objects.filter(name=threat_intel.STATE).exists())

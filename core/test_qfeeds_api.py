"""Mejoras de la API de Q-Feeds: programación de descargas, seguridad y uso de la clave, consultas en bloque y contexto."""
import copy
import io
import json
import os
import time
from datetime import timedelta
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from . import threat_intel
from . import test_threat_intel as base
from .models import OperationalIssue, StaffAccess, ThreatIndicator, ThreatIntelLookup
from .test_threat_intel import ATTACKER, C2, INDEX, KEY, FakeApi


def index(**changes):
    data = copy.deepcopy(INDEX)
    for item in data['feeds']:
        item.update(changes.get(item['feed_type'], {}))
    data.update(changes.get('root', {}))
    return data


class Base(TestCase):
    setUp = base.ThreatIntelTests.setUp

    def sync(self, api, now=None):
        with mock.patch.dict(os.environ, {'SOC_PORTAL_QFEEDS_KEY': KEY}), mock.patch.object(threat_intel, '_open', api):
            threat_intel.sync(now or self.now)
        return api

    def feed_calls(self, api):
        return [r.full_url for r in api.requests if '/api.php' in r.full_url]


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class SchedulingTests(Base):
    def test_waits_for_next_update_before_downloading_again(self):
        later = (self.now + timedelta(hours=2)).isoformat()
        first = index(malware_ip={'next_update': later}, malware_domains={'next_update': later})
        self.sync(FakeApi(index=first))
        # Q-Feeds cambia `updated_at` (también refleja la descarga de la cuenta), pero aún no toca volver a pedirla.
        moved = index(malware_ip={'next_update': later, 'updated_at': self.now.isoformat()},
                      malware_domains={'next_update': later, 'updated_at': self.now.isoformat()})
        api = self.sync(FakeApi(index=moved), self.now + timedelta(minutes=30))
        self.assertEqual(api.requests, [], 'con todo programado para más tarde ni siquiera se lee el índice')
        api = self.sync(FakeApi(index=moved), self.now + timedelta(hours=3))
        self.assertEqual(len(self.feed_calls(api)), 2, 'pasada la hora recomendada, se descargan las que cambiaron')

    def test_index_is_read_at_least_every_six_hours_and_feeds_stay_usable(self):
        far = (self.now + timedelta(days=2)).isoformat()
        self.sync(FakeApi(index=index(malware_ip={'next_update': far}, malware_domains={'next_update': far})))
        api = self.sync(FakeApi(index=index(malware_ip={'next_update': far}, malware_domains={'next_update': far})),
                        self.now + timedelta(hours=7))
        self.assertTrue(any('/licenses.php' in r.full_url for r in api.requests))
        self.assertEqual(self.feed_calls(api), [])
        self.assertEqual(threat_intel.usable_feeds(now=self.now + timedelta(hours=7)), {'malware_ip', 'malware_domains'})

    def test_frequency_is_kept_for_the_page(self):
        self.sync(FakeApi(index=index(malware_ip={'frequency': 1200})))
        self.assertEqual(threat_intel.details()['feeds']['malware_ip']['frequency'], 1200)


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class KeyTests(Base):
    def test_key_restrictions_are_read_and_shown(self):
        settings = {'security_settings': {'allowed_ips': '203.0.113.10, no-es-ip', 'allowed_user_agents': 'curl',
                                          'rate_limit_window': 60}}
        self.sync(FakeApi(index=index(root=settings)))
        security = threat_intel.details()['key_security']
        self.assertEqual(security, {'ips_restricted': True, 'allowed_ips': ['203.0.113.10/32'], 'agents_restricted': True,
                                    'agent_allowed': False, 'rate_window': 60})
        self.sync(FakeApi(index=index(root={'security_settings': {'allowed_ips': '*', 'allowed_user_agents': '*'}})),
                  self.now + timedelta(hours=7))
        self.assertFalse(threat_intel.details()['key_security']['ips_restricted'])

    def test_much_more_use_in_qfeeds_than_in_the_soc_raises_an_issue(self):
        info = {'api_usage': {'total_requests': 400, 'period_days': 1},
                'log_history': [{'status_code': 403, 'message': 'x'}, {'status_code': 200, 'message': 'y'}]}
        self.sync(FakeApi(info=info))
        usage = threat_intel.details()['key_usage']
        self.assertTrue(usage['suspect'])
        self.assertEqual(usage['rejected'], 1)
        self.assertNotIn('message', json.dumps(usage), 'no se guardan los textos del proveedor')
        issue = OperationalIssue.objects.get(key=threat_intel.KEY_USE_ISSUE, active=True)
        self.assertIn('400 peticiones', issue.details)
        # Al día siguiente, con un uso normal, se cierra.
        self.sync(FakeApi(info={'api_usage': {'total_requests': 2}}), self.now + timedelta(hours=25))
        self.assertFalse(OperationalIssue.objects.filter(key=threat_intel.KEY_USE_ISSUE, active=True).exists())

    def test_normal_use_is_not_suspicious_and_only_checked_daily(self):
        self.sync(FakeApi())
        self.assertFalse(threat_intel.details()['key_usage']['suspect'])
        api = self.sync(FakeApi(), self.now + timedelta(hours=7))
        self.assertFalse(any('/info.php' in r.full_url for r in api.requests))
        self.assertGreaterEqual(threat_intel.own_calls(self.now - timedelta(hours=1), self.now + timedelta(hours=8)), 5)


class BulkApi(FakeApi):
    def __init__(self, results=None, status=None, **kwargs):
        super().__init__(**kwargs)
        self.results, self.status = results, status

    def __call__(self, req):
        if 'action=bulk' in req.full_url:
            self.requests.append(req)
            if self.status:
                from urllib import error as urlerror
                raise urlerror.HTTPError(req.full_url, self.status, 'error', {}, None)
            self.bodies = getattr(self, 'bodies', []) + [json.loads(req.data)]
            return io.BytesIO(json.dumps({'results': self.results, 'meta': {'lookups_remaining_month': 90,
                                                                            'lookups_limit_month': 100}}).encode())
        return super().__call__(req)


DETAIL = {'verdict': 'malicious', 'score': 90, 'expired': True, 'warninglist_hits': [{'name': 'CDN conocidas'}],
          'linked_iocs': {'outbound': [{'value': 'c2.example.com', 'type': 'domain', 'verdict': 'malicious', 'kind': 'dns_a'}],
                          'outbound_total': 1}, 'notes': [{'text': 'nota interna del proveedor'}]}


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class LookupTests(Base):
    def run_lookups(self, api):
        with mock.patch.dict(os.environ, {'SOC_PORTAL_QFEEDS_KEY': KEY}), mock.patch.object(threat_intel, '_open', api):
            return threat_intel.process_lookups(self.now)

    def test_several_queued_lookups_go_in_one_bulk_request(self):
        ThreatIntelLookup.objects.create(value=ATTACKER)
        ThreatIntelLookup.objects.create(value=C2)
        api = BulkApi(results=[{'value': ATTACKER, 'matched': True, 'ioc': DETAIL}, {'value': C2, 'matched': False, 'ioc': None}])
        self.assertEqual(self.run_lookups(api), 2)
        self.assertEqual(len(api.requests), 1)
        self.assertEqual(api.bodies, [{'values': [ATTACKER, C2]}])
        result = ThreatIntelLookup.objects.get(value=ATTACKER).result
        self.assertTrue(result['expired'])
        self.assertEqual(result['warninglists'], ['CDN conocidas'])
        self.assertEqual(result['related'], [{'value': 'c2.example.com', 'type': 'domain', 'verdict': 'malicious', 'kind': 'dns_a'}])
        self.assertNotIn('nota interna', json.dumps(result))
        self.assertFalse(ThreatIntelLookup.objects.get(value=C2).matched)
        self.assertEqual(threat_intel.details()['lookup']['remaining'], 90)

    def test_bulk_not_supported_falls_back_to_single_lookups(self):
        ThreatIntelLookup.objects.create(value=ATTACKER)
        ThreatIntelLookup.objects.create(value=C2)
        api = BulkApi(status=404, lookup={'matched': True, 'ioc': DETAIL, 'meta': {}})
        self.assertEqual(self.run_lookups(api), 2)
        self.assertEqual(sum('action=ioc' in r.full_url for r in api.requests), 2)

    def test_rate_limit_keeps_the_bulk_queued(self):
        ThreatIntelLookup.objects.create(value=ATTACKER)
        ThreatIntelLookup.objects.create(value=C2)
        self.assertEqual(self.run_lookups(BulkApi(status=429)), 0)
        self.assertEqual(ThreatIntelLookup.objects.filter(status='queued').count(), 2)

    def test_page_shows_the_new_context_and_key_status(self):
        self.sync(FakeApi(index=index(root={'security_settings': {'allowed_ips': '*', 'allowed_user_agents': '*'}})))
        ThreatIndicator.objects.get_or_create(feed='malware_ip', kind='ip', value=ATTACKER)
        ThreatIntelLookup.objects.create(value=ATTACKER, status='done', matched=True, done_at=self.now,
                                         result=threat_intel._clean_ioc(DETAIL))
        user = get_user_model().objects.create_user('analista')
        StaffAccess.objects.create(user=user, role='operator', all_clients=True)
        from django.contrib.auth.models import Permission
        user.user_permissions.add(Permission.objects.get(codename='manage_operations'))
        self.client.force_login(user)
        session = self.client.session
        session.update({'soc_mfa_user': user.pk, 'soc_mfa_at': time.time()})
        session.save()
        page = self.client.get(reverse('threat_intel'), {'q': ATTACKER})
        self.assertContains(page, 'Ya no lo reporta ninguna fuente')
        self.assertContains(page, 'CDN conocidas')
        self.assertContains(page, 'c2.example.com')
        self.assertContains(page, 'admite peticiones desde cualquier IP')

"""Catálogo de listas de CrowdSec (Service API simulada): evaluación con atacantes reales y suscripciones."""
import time
from datetime import timedelta
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from . import crowdsec_catalog as catalog
from .models import AuditEvent, Client, CrowdsecBlocklist, Device, IpReputation, SecurityEvidence, Site, WorkerState

A_ALLOWED, A_OTHER, A_RANGE, A_COVERED = '45.155.205.233', '185.220.101.4', '91.92.5.6', '218.92.0.35'
EXTRA = ('193.32.162.31', '80.82.77.139')


def blocklist(identifier, tier='free', size=1000, fp=0, name=None):
    return {'id': identifier, 'name': name or identifier, 'label': (name or identifier).title(), 'description': 'Lista de prueba',
            'pricing_tier': tier, 'source': 'crowdsec', 'categories': ['scanner'], 'is_private': False,
            'created_at': '2026-01-01', 'updated_at': '2026-10-01',
            'stats': {'count': size, 'content_stats': {'total_false_positive': fp,
                                                       'most_present_scenarios': [{'name': 'ssh-bf', 'label': 'SSH Bruteforce'}]}}}


class FakeService:
    def __init__(self, engines=None, engines_allowed=True):
        self.calls = []
        self.engines_allowed = engines_allowed
        self.engines = engines or [{'id': 'engine-1', 'blocklists': [{'id': 'subscribed', 'remediation': 'ban'}]}]
        self.subscribers = {'subscribed': [{'id': 'engine-1', 'entity_type': 'engine', 'remediation': 'ban'}]}
        self.lists = [blocklist('good'), blocklist('subscribed'), blocklist('noisy', 'premium', size=100, fp=50),
                      blocklist('platinum', 'platinum'), blocklist('empty')]

    def __call__(self, key, path, method='GET', body=None, raw=False):
        self.calls.append((method, path, body))
        if path.startswith('/engines'):
            if not self.engines_allowed:
                raise catalog.ServiceError('clave rechazada o sin acceso con este plan')
            return {'items': self.engines, 'pages': 1}
        if path.startswith('/blocklists?'):
            if 'subscribed_only=true' in path:
                return {'items': [b for b in self.lists if self.subscribers.get(b['id'])], 'pages': 1}
            return {'items': self.lists, 'pages': 1}
        if path.endswith('/download'):
            raise AssertionError('la evaluación no descarga listas')
        identifier = path.split('/')[2].split('?')[0]
        if path.endswith('/subscribers') and method == 'POST':
            entity = {'id': body['ids'][0] if body.get('ids') else 'org-1', 'entity_type': body['entity_type']}
            self.subscribers.setdefault(identifier, []).append(entity)
            return {'updated': [entity['id']], 'errors': []}
        if '/subscribers?' in path:
            return {'items': self.subscribers.get(identifier, []), 'pages': 1}
        if '/subscribers/' in path and method == 'DELETE':
            target = path.rsplit('/', 1)[1]
            self.subscribers[identifier] = [e for e in self.subscribers.get(identifier, []) if e['id'] != target]
            return {}
        raise AssertionError(path)


class CatalogTestCase(TestCase):
    def setUp(self):
        self.now = timezone.now()
        devices = []
        for code in ('a', 'b'):
            company = Client.objects.create(name=f'Cliente {code}', code=code)
            devices.append(Device.objects.create(site=Site.objects.create(client=company, name='S', code=code),
                                                 name=f'FW-{code}', vendor='opnsense'))
        attacks = [(A_ALLOWED, devices[0], 'allowed'), (A_OTHER, devices[1], 'blocked'), (A_RANGE, devices[1], 'blocked'),
                   (A_COVERED, devices[0], 'blocked'), ('10.0.0.9', devices[0], 'blocked')] + [(ip, devices[0], 'blocked') for ip in EXTRA]
        for index, (ip, device, action) in enumerate(attacks):
            SecurityEvidence.objects.create(uid=f'{index:064x}', device=device, observed_at=self.now - timedelta(days=2),
                                            engine='suricata', signature='Firma', source_ip=ip, destination_ip='10.0.0.5',
                                            action=action, level=8, client_scope_id=device.site.client_id)
        # Motor: A_COVERED solo en una lista suscrita; A_OTHER en la comunitaria.
        IpReputation.objects.create(ip=A_COVERED, listed=True, list_origins=['Lista de la consola'],
                                    list_scenarios=['subscribed'], lists_checked_at=self.now)
        # CTI: en qué listas está cada atacante consultado, suscritas o no.
        IpReputation.objects.create(ip=A_ALLOWED, cti_found=True, reputation='malicious', cti_lists=['good', 'noisy'])
        IpReputation.objects.create(ip=A_OTHER, cti_found=True, reputation='malicious', cti_lists=['good'],
                                    listed=True, list_origins=['Lista comunitaria'], list_scenarios=['ssh:bruteforce'])
        IpReputation.objects.create(ip=A_RANGE, cti_found=True, reputation='suspicious', cti_lists=[])
        for ip in EXTRA:
            IpReputation.objects.create(ip=ip, cti_found=True, reputation='malicious', cti_lists=['good'])
        self.service = FakeService()

    def run_job(self, env=None, now=None, runs=1):
        variables = {'SOC_PORTAL_CROWDSEC_SERVICE_KEY': 'clave-servicio', 'SOC_PORTAL_CROWDSEC_ENGINE_ID': '',
                     'SOC_PORTAL_CROWDSEC_AUTO_SUBSCRIBE': '0', **(env or {})}
        with mock.patch.dict('os.environ', variables), mock.patch.object(catalog, 'call', side_effect=self.service):
            for _ in range(runs):
                catalog.refresh(now or self.now)
        return WorkerState.objects.get(name=catalog.STATE)


class RefreshTests(CatalogTestCase):
    def test_without_key_nothing_is_called(self):
        with mock.patch.dict('os.environ', {'SOC_PORTAL_CROWDSEC_SERVICE_KEY': ''}), \
                mock.patch.object(catalog, 'call') as call:
            catalog.refresh(self.now)
        call.assert_not_called()
        self.assertFalse(WorkerState.objects.get(name=catalog.STATE).details['enabled'])

    def test_lists_are_measured_exactly_by_the_engine_or_estimated_by_the_cti(self):
        state = self.run_job()
        self.assertEqual((state.error, state.details['catalog_count'], state.details['attackers'], state.details['sampled']),
                         ('', 5, 6, 5))
        good = CrowdsecBlocklist.objects.get(blocklist_id='good')
        # Estimado: 4 atacantes en la lista según la CTI; A_OTHER ya lo cubre la comunitaria.
        self.assertEqual((good.method, good.sample, good.hits, good.new_hits, good.allowed_hits, good.clients),
                         ('cti', 5, 4, 3, 1, 2))
        subscribed = CrowdsecBlocklist.objects.get(blocklist_id='subscribed')
        self.assertEqual((subscribed.method, subscribed.hits, subscribed.new_hits, subscribed.subscribed_by),
                         ('motor', 1, 1, 'console'))
        self.assertEqual(CrowdsecBlocklist.objects.get(blocklist_id='noisy').score, 0, 'falsos positivos > 1 %')
        self.assertEqual(CrowdsecBlocklist.objects.get(blocklist_id='empty').hits, 0)
        self.assertEqual([r.blocklist_id for r in catalog.recommended()], ['good'])
        self.assertFalse(any(method == 'POST' for method, _, _ in self.service.calls), 'sin modo automático no suscribe')
        catalog_calls = [p for _, p, _ in self.service.calls if p.startswith('/blocklists?')]
        self.assertEqual(len(catalog_calls), 2)
        self.run_job(now=self.now + timedelta(minutes=30))
        self.assertEqual(len([p for _, p, _ in self.service.calls if p.startswith('/blocklists?')]), 2, 'catálogo diario')

    def test_cti_lists_are_kept_from_references(self):
        from .reputation import parse
        values = parse({'reputation': 'malicious', 'references': [
            {'name': 'list:crowdsec_wordpress'}, {'name': 'list:firehol_greensnow'}, {'name': 'otra:cosa'}, 'x']})
        self.assertEqual(values['cti_lists'], ['crowdsec_wordpress', 'firehol_greensnow'])

    def test_automatic_mode_subscribes_the_best_lists_up_to_the_limit(self):
        self.run_job()
        self.run_job(env={'SOC_PORTAL_CROWDSEC_AUTO_SUBSCRIBE': '1'}, now=self.now + timedelta(minutes=5))
        posts = [(p, b) for m, p, b in self.service.calls if m == 'POST']
        self.assertEqual(posts, [('/blocklists/good/subscribers', {'entity_type': 'engine', 'ids': ['engine-1'], 'remediation': 'ban'})])
        good = CrowdsecBlocklist.objects.get(blocklist_id='good')
        self.assertEqual((good.subscribed, good.subscribed_by), (True, 'soc-auto'))
        self.assertTrue(AuditEvent.objects.filter(action='crowdsec.subscribe').exists())
        self.run_job(env={'SOC_PORTAL_CROWDSEC_AUTO_SUBSCRIBE': '1'}, now=self.now + timedelta(minutes=10))
        self.assertEqual(len([1 for m, _, _ in self.service.calls if m == 'POST']), 1, 'límite alcanzado')

    def test_key_without_engine_permission_subscribes_the_organisation(self):
        self.service = FakeService(engines_allowed=False)
        state = self.run_job()
        self.assertEqual((state.error, state.details['engine_id']), ('', ''))
        self.assertTrue(CrowdsecBlocklist.objects.get(blocklist_id='subscribed').subscribed)
        self.run_job(env={'SOC_PORTAL_CROWDSEC_AUTO_SUBSCRIBE': '1'})
        self.assertIn(('POST', '/blocklists/good/subscribers', {'entity_type': 'org', 'remediation': 'ban'}), self.service.calls)
        good = CrowdsecBlocklist.objects.get(blocklist_id='good')
        CrowdsecBlocklist.objects.filter(pk=good.pk).update(pending_action='unsubscribe')
        self.run_job()
        self.assertIn(('DELETE', '/blocklists/good/subscribers/org-1', None), self.service.calls)
        self.assertFalse(CrowdsecBlocklist.objects.get(pk=good.pk).subscribed)

    def test_several_engines_require_explicit_engine_id(self):
        self.service.engines = [{'id': 'engine-1'}, {'id': 'engine-2'}]
        state = self.run_job()
        self.assertIn('SOC_PORTAL_CROWDSEC_ENGINE_ID', state.error)
        self.assertNotIn('clave-servicio', state.error)
        state = self.run_job(env={'SOC_PORTAL_CROWDSEC_ENGINE_ID': 'engine-2'})
        self.assertEqual(state.error, '')


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class PageTests(CatalogTestCase):
    def login(self, user):
        self.client.force_login(user)
        session = self.client.session
        session.update({'soc_mfa_user': user.pk, 'soc_mfa_at': time.time()})
        session.save()

    def test_manual_subscription_is_queued_then_applied_by_the_job(self):
        self.run_job()
        admin = get_user_model().objects.create_superuser('admin', 'a@example.test', 'x')
        self.login(admin)
        page = self.client.get(reverse('crowdsec_lists'))
        self.assertContains(page, 'Recomendadas')
        self.assertContains(page, 'Good')
        self.assertNotContains(page, 'clave-servicio')
        good = CrowdsecBlocklist.objects.get(blocklist_id='good')
        url = reverse('crowdsec_list_action', args=[good.pk])
        self.client.post(url, {'action': 'subscribe'})
        good.refresh_from_db()
        self.assertEqual((good.pending_action, good.subscribed), ('subscribe', False))
        self.run_job()
        good.refresh_from_db()
        self.assertEqual((good.pending_action, good.subscribed, good.subscribed_by), ('', True, 'soc-manual'))
        self.client.post(url, {'action': 'unsubscribe'})
        self.run_job()
        good.refresh_from_db()
        self.assertFalse(good.subscribed)
        self.assertIn(('DELETE', '/blocklists/good/subscribers/engine-1', None), self.service.calls)
        platinum = CrowdsecBlocklist.objects.get(blocklist_id='platinum')
        self.client.post(reverse('crowdsec_list_action', args=[platinum.pk]), {'action': 'subscribe'})
        self.assertEqual(CrowdsecBlocklist.objects.get(pk=platinum.pk).pending_action, '')

    def test_only_connection_managers_with_fresh_mfa_change_subscriptions(self):
        self.run_job()
        good = CrowdsecBlocklist.objects.get(blocklist_id='good')
        url = reverse('crowdsec_list_action', args=[good.pk])
        admin = get_user_model().objects.create_superuser('admin', 'a@example.test', 'x')
        self.client.force_login(admin)
        self.assertRedirects(self.client.post(url, {'action': 'subscribe'}), reverse('mfa_challenge'),
                             fetch_redirect_response=False)
        reader = get_user_model().objects.create_user('lector')
        from .models import StaffAccess
        StaffAccess.objects.create(user=reader, role='reader', all_clients=True)
        self.login(reader)
        self.assertEqual(self.client.get(reverse('crowdsec_lists')).status_code, 403)
        self.assertEqual(CrowdsecBlocklist.objects.get(pk=good.pk).pending_action, '')

"""Catálogo de listas de CrowdSec (Service API simulada): evaluación con atacantes reales y suscripciones."""
import io
import time
from datetime import timedelta
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from . import crowdsec_catalog as catalog
from .models import AuditEvent, Client, CrowdsecBlocklist, Device, IpReputation, SecurityEvidence, Site, WorkerState

A_ALLOWED, A_OTHER, A_RANGE, A_COVERED = '45.155.205.233', '185.220.101.4', '91.92.5.6', '218.92.0.35'


def blocklist(identifier, tier='free', size=1000, fp=0, name=None):
    return {'id': identifier, 'name': name or identifier, 'label': (name or identifier).title(), 'description': 'Lista de prueba',
            'pricing_tier': tier, 'source': 'crowdsec', 'categories': ['scanner'], 'is_private': False,
            'created_at': '2026-01-01', 'updated_at': '2026-10-01',
            'stats': {'count': size, 'content_stats': {'total_false_positive': fp,
                                                       'most_present_scenarios': [{'name': 'ssh-bf', 'label': 'SSH Bruteforce'}]}}}


CONTENT = {'good': f'{A_ALLOWED}\n{A_OTHER}\n91.92.0.0/16\n{A_COVERED}\n# comentario\nbasura\n',
           'subscribed': f'{A_COVERED}\n', 'noisy': f'{A_ALLOWED}\n{A_OTHER}\n', 'empty': '1.2.3.4\n'}


class FakeService:
    def __init__(self, engines=None):
        self.calls = []
        self.engines = engines or [{'id': 'engine-1', 'blocklists': [{'id': 'subscribed', 'remediation': 'ban'}]}]
        self.lists = [blocklist('good'), blocklist('subscribed'), blocklist('noisy', 'premium', size=100, fp=50),
                      blocklist('platinum', 'platinum'), blocklist('empty')]

    def __call__(self, key, path, method='GET', body=None, raw=False):
        self.calls.append((method, path, body))
        if path.startswith('/engines'):
            return {'items': self.engines, 'pages': 1}
        if path.startswith('/blocklists?'):
            return {'items': self.lists, 'pages': 1}
        if path.endswith('/download'):
            identifier = path.split('/')[2]
            if identifier == 'platinum':
                raise catalog.ServiceError('sin acceso con este plan')
            return io.BytesIO(CONTENT[identifier].encode())
        if path.endswith('/subscribers') and method == 'POST':
            return {'updated': body['ids'], 'errors': []}
        if '/subscribers/' in path and method == 'DELETE':
            return {}
        raise AssertionError(path)


class MatchTests(SimpleTestCase):
    def test_exact_ips_and_ranges_are_matched_and_junk_ignored(self):
        targets = {A_ALLOWED: {}, A_RANGE: {}, '8.8.8.8': {}, '2001:db8::1': {}}
        lines = [A_ALLOWED + '\n', '91.92.0.0/16\n', 'no-es-ip\n', '\n', '2001:db8::/32 # red\n', '10.0.0.1/32\n']
        self.assertEqual(catalog.matches(lines, targets), {A_ALLOWED, A_RANGE, '2001:db8::1'})


class CatalogTestCase(TestCase):
    def setUp(self):
        self.now = timezone.now()
        devices = []
        for code in ('a', 'b'):
            company = Client.objects.create(name=f'Cliente {code}', code=code)
            devices.append(Device.objects.create(site=Site.objects.create(client=company, name='S', code=code),
                                                 name=f'FW-{code}', vendor='opnsense'))
        attacks = [(A_ALLOWED, devices[0], 'allowed'), (A_OTHER, devices[1], 'blocked'), (A_RANGE, devices[1], 'blocked'),
                   (A_COVERED, devices[0], 'blocked'), ('10.0.0.9', devices[0], 'blocked')]
        for index, (ip, device, action) in enumerate(attacks):
            SecurityEvidence.objects.create(uid=f'{index:064x}', device=device, observed_at=self.now - timedelta(days=2),
                                            engine='suricata', signature='Firma', source_ip=ip, destination_ip='10.0.0.5',
                                            action=action, level=8, client_scope_id=device.site.client_id)
        IpReputation.objects.create(ip=A_COVERED, listed=True, lists_checked_at=self.now)
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

    def test_lists_are_measured_against_real_attackers(self):
        state = self.run_job(runs=2)
        self.assertEqual((state.error, state.details['engine_id'], state.details['catalog_count']), ('', 'engine-1', 5))
        good = CrowdsecBlocklist.objects.get(blocklist_id='good')
        # 4 atacantes en la lista (uno por rango); uno ya cubierto por una lista suscrita.
        self.assertEqual((good.hits, good.new_hits, good.allowed_hits, good.clients), (4, 3, 1, 2))
        self.assertGreater(good.score, 0)
        self.assertEqual(CrowdsecBlocklist.objects.get(blocklist_id='noisy').score, 0, 'falsos positivos > 1 %')
        self.assertEqual(CrowdsecBlocklist.objects.get(blocklist_id='empty').hits, 0)
        subscribed = CrowdsecBlocklist.objects.get(blocklist_id='subscribed')
        self.assertEqual((subscribed.subscribed, subscribed.subscribed_by), (True, 'console'))
        self.assertIsNone(CrowdsecBlocklist.objects.get(blocklist_id='platinum').evaluated_at, 'fuera del plan')
        self.assertEqual([r.blocklist_id for r in catalog.recommended()], ['good'])
        self.assertFalse(any(method == 'POST' for method, _, _ in self.service.calls), 'sin modo automático no suscribe')
        downloads = [p for _, p, _ in self.service.calls if p.endswith('/download')]
        self.assertEqual(len(downloads), 4)
        self.assertEqual(len([p for _, p, _ in self.service.calls if p.startswith('/blocklists?')]), 1, 'catálogo diario')

    def test_download_budget_and_reevaluation_interval(self):
        self.run_job(env={'SOC_PORTAL_CROWDSEC_LIST_DOWNLOADS': '2'}, runs=3)
        self.assertEqual(len([p for _, p, _ in self.service.calls if p.endswith('/download')]), 2)
        self.run_job(now=self.now + timedelta(days=1), runs=2)
        evaluated = CrowdsecBlocklist.objects.exclude(evaluated_at=None).count()
        self.assertEqual(evaluated, 4)
        before = len(self.service.calls)
        self.run_job(now=self.now + timedelta(days=2))
        self.assertFalse([p for _, p, _ in self.service.calls[before:] if p.endswith('/download')], 'vigentes 7 días')

    def test_automatic_mode_subscribes_the_best_lists_up_to_the_limit(self):
        self.run_job(runs=2)
        self.run_job(env={'SOC_PORTAL_CROWDSEC_AUTO_SUBSCRIBE': '1'})
        posts = [(p, b) for m, p, b in self.service.calls if m == 'POST']
        self.assertEqual(posts, [('/blocklists/good/subscribers', {'entity_type': 'engine', 'ids': ['engine-1'], 'remediation': 'ban'})])
        good = CrowdsecBlocklist.objects.get(blocklist_id='good')
        self.assertEqual((good.subscribed, good.subscribed_by), (True, 'soc-auto'))
        self.assertTrue(AuditEvent.objects.filter(action='crowdsec.subscribe').exists())
        self.run_job(env={'SOC_PORTAL_CROWDSEC_AUTO_SUBSCRIBE': '1'})
        self.assertEqual(len([1 for m, _, _ in self.service.calls if m == 'POST']), 1, 'límite alcanzado')

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
        self.run_job(runs=2)
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
        self.run_job(runs=2)
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

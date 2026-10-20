"""Aislamiento por cliente en Wazuh: rol con DLS exacto, comprobaciones negativas reales y
objetos del tenant limitados a la empresa. Antes sin cobertura (wazuh_isolation 0 %,
wazuh_tenant_objects 0 %, wazuh_scoped 27 %). La red se sustituye por respuestas simuladas.
"""
import json
from datetime import timedelta
from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from . import wazuh_isolation, wazuh_scoped, wazuh_tenant_objects
from .models import Client, Device, SecurityEvidence, Site, WorkerState
from .wazuh_scoped import binding_ready, document, names, role_definition

CID = 7
N = names(CID)


def healthy_proxy(path, cid, *, dashboard=False, tenant=None, method='GET'):
    if path == '/_plugins/_security/authinfo':
        return 200, {'roles': [N['role'], 'soc_portal_scoped']}
    if path in ('/wazuh-alerts-*/_count', '/soc-customer-*/_count'):
        return 403, {}
    if path == '/' + N['index'] + '/_search?size=0':
        return 200, {'timed_out': False, '_shards': {'failed': 0}}
    if path.startswith('/api/saved_objects/_find'):
        return 200, {'saved_objects': [{'id': N['dashboard']}]}
    if path == '/api/saved_objects/dashboard/soc-general':
        return 403, {}
    if method == 'DELETE':
        return 403, {}
    raise AssertionError(path)


class NamesAndRoleTests(SimpleTestCase):
    def test_names_only_accept_positive_integer_ids(self):
        for bad in (True, 0, -1, '7', None):
            with self.assertRaises(ValueError):
                names(bad)

    def test_role_reads_only_its_own_index_with_document_level_security(self):
        role = role_definition(CID)
        [permission] = role['index_permissions']
        self.assertEqual(permission['index_patterns'], [N['index']])
        self.assertEqual(permission['allowed_actions'], ['read'])
        self.assertEqual(json.loads(permission['dls']), {'term': {'soc.client_id': CID}})
        self.assertEqual(role['tenant_permissions'], [{'tenant_patterns': [N['tenant']], 'allowed_actions': ['kibana_all_read']}])


class VerifyIsolationTests(SimpleTestCase):
    def test_healthy_binding_passes_every_negative_check(self):
        with mock.patch.object(wazuh_isolation, 'proxy_get', side_effect=healthy_proxy):
            self.assertTrue(wazuh_isolation.verify_isolation(CID))

    def test_any_leak_or_failure_is_rejected(self):
        leaks = {
            'raw alert indices readable': ('/wazuh-alerts-*/_count', (200, {})),
            'other customers enumerable': ('/soc-customer-*/_count', (200, {})),
            'extra effective role': ('/_plugins/_security/authinfo', (200, {'roles': [N['role'], 'all_access']})),
            'own index unavailable': ('/' + N['index'] + '/_search?size=0', (200, {'timed_out': True})),
            'foreign dashboard in tenant': ('/api/saved_objects/_find?type=dashboard&per_page=100',
                                            (200, {'saved_objects': [{'id': N['dashboard']}, {'id': 'soc-customer-8'}]})),
            'global tenant readable': ('/api/saved_objects/dashboard/soc-general', (200, {})),
            'projection writable': ('/' + N['index'] + '/_doc/soc-readonly-permission-check', (200, {})),
        }
        for label, (leaky_path, answer) in leaks.items():
            def proxy(path, cid, **kwargs):
                return answer if path == leaky_path else healthy_proxy(path, cid, **kwargs)
            with self.subTest(label), mock.patch.object(wazuh_isolation, 'proxy_get', side_effect=proxy):
                with self.assertRaises(ValueError):
                    wazuh_isolation.verify_isolation(CID)


class SyncClientTests(TestCase):
    def setUp(self):
        self.client_row = Client.objects.create(name='Empresa', code='empresa')
        self.state = 'wazuh-customer-' + str(self.client_row.pk)

    def admin(self, actual_role=None):
        role = role_definition(self.client_row.pk) if actual_role is None else actual_role

        def request(path, body=None, method='GET', **kwargs):
            if path.endswith('roles/' + names(self.client_row.pk)['role']) and method == 'GET':
                return {names(self.client_row.pk)['role']: role}
            return {}
        return request

    def sync(self, admin, isolation=None):
        with mock.patch.object(wazuh_scoped, 'admin_request', side_effect=admin), \
                mock.patch.object(wazuh_tenant_objects, 'sync_objects'), \
                mock.patch.object(wazuh_isolation, 'verify_isolation', side_effect=isolation):
            return wazuh_scoped.sync_client(self.client_row)

    def test_ready_only_after_role_and_isolation_are_confirmed(self):
        self.assertTrue(self.sync(self.admin()))
        self.assertTrue(binding_ready(self.client_row.pk))

    def test_wider_role_than_requested_is_never_ready(self):
        wider = role_definition(self.client_row.pk)
        wider['index_permissions'][0]['index_patterns'] = ['soc-customer-*']
        self.assertFalse(self.sync(self.admin(wider)))
        self.assertFalse(binding_ready(self.client_row.pk))

    def test_failed_isolation_check_revokes_readiness(self):
        self.assertTrue(self.sync(self.admin()))
        self.assertFalse(self.sync(self.admin(), isolation=ValueError('leak')))
        self.assertFalse(binding_ready(self.client_row.pk))

    def test_readiness_expires_and_requires_current_version(self):
        self.sync(self.admin())
        WorkerState.objects.filter(pk=self.state).update(last_success_at=timezone.now() - timedelta(minutes=16))
        self.assertFalse(binding_ready(self.client_row.pk))
        WorkerState.objects.filter(pk=self.state).update(last_success_at=timezone.now(), details={'version': 0, 'ready': True})
        self.assertFalse(binding_ready(self.client_row.pk))


class ProjectionDocumentTests(TestCase):
    def test_document_carries_frozen_owner_and_no_raw_or_internal_fields(self):
        company = Client.objects.create(name='Empresa', code='e')
        device = Device.objects.create(site=Site.objects.create(client=company, name='S', code='s'), name='FW', vendor='opnsense')
        evidence = SecurityEvidence(uid='a' * 64, device=device, observed_at=timezone.now(), engine='suricata',
                                    signature='Firma', source_ip='203.0.113.9', client_scope_id=company.pk,
                                    recommendation='Nota interna', wazuh_id='raw-id')
        body = json.dumps(document(evidence))
        self.assertEqual(document(evidence)['soc']['client_id'], company.pk)
        for private in ('Nota interna', 'raw-id', 'FW', 'Empresa'):
            self.assertNotIn(private, body)
        evidence.client_scope_id = None
        with self.assertRaises(ValueError):
            document(evidence)


class TenantObjectsTests(TestCase):
    def test_every_saved_object_is_filtered_to_the_company_and_sent_to_its_tenant(self):
        company = Client.objects.create(name='Empresa', code='e')
        n = names(company.pk)
        sync_module = wazuh_tenant_objects.load('sync_wazuh_dashboards')
        calls = []

        def request(path, auth, method='GET', body=None, *, tenant=None):
            calls.append((path, method, body, tenant))
            if method == 'GET':
                return 200, {'references': [{'id': n['index']}]}
            return 200, {}
        sync_module.credentials = lambda: 'auth'
        sync_module.request = request
        real_load = wazuh_tenant_objects.load
        with mock.patch.object(wazuh_tenant_objects, 'load',
                               side_effect=lambda name: sync_module if name == 'sync_wazuh_dashboards' else real_load(name)):
            wazuh_tenant_objects.sync_objects(company)
        self.assertEqual({tenant for *_, tenant in calls}, {n['tenant']})
        queries = [body for _, _, body, _ in calls
                   if body and body['attributes'].get('kibanaSavedObjectMeta', {}).get('searchSourceJSON')]
        self.assertGreater(len(queries), 3)
        for path, method, body, _ in calls:
            if not body:
                continue
            for reference in body.get('references', []):
                if reference['type'] == 'index-pattern':
                    self.assertEqual(reference['id'], n['index'])
            source = body['attributes'].get('kibanaSavedObjectMeta', {}).get('searchSourceJSON')
            if source:
                query = json.loads(source)['query']['query']
                self.assertIn(f'soc.client_id: {company.pk}', query)
                self.assertNotIn('__soc_sin_origen__', query)

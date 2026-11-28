"""Vulnerabilidades de los equipos: lectura del índice de Wazuh, fotografía con resueltas, SOC y portal del cliente."""
import io
import time
import urllib.error
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from . import endpoint_vulnerabilities as ev
from .models import (Client, EndpointAgent, EndpointVulnerability, OperationalIssue, Site, StaffAccess, WorkerState)


def doc(agent, cve, package, severity='Critical', score=9.8, version='1.0'):
    return {'_source': {'agent': {'id': agent}, 'package': {'name': package, 'version': version},
                        'vulnerability': {'id': cve, 'severity': severity, 'score': {'base': score},
                                          'description': 'TEXTO DEL PROVEEDOR', 'published_at': '2026-10-01T00:00:00Z',
                                          'detected_at': '2026-11-20T10:00:00Z'}},
            'sort': [agent, package, cve, version]}


class FakeIndexer:
    def __init__(self, docs, page=None):
        self.docs, self.bodies, self.page = docs, [], page

    def __call__(self, body, authorization):
        self.bodies.append(body)
        wanted = set(body['query']['bool']['filter'][0]['terms']['agent.id'])
        rows = [d for d in self.docs if d['_source']['agent']['id'] in wanted]
        start = 0
        if body.get('search_after'):
            start = next(i for i, d in enumerate(rows) if d['sort'] == body['search_after']) + 1
        size = self.page or body['size']
        return {'timed_out': False, '_shards': {'failed': 0}, 'hits': {'hits': rows[start:start + size]}}


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class Base(TestCase):
    def setUp(self):
        self.now = timezone.now()
        self.company = Client.objects.create(name='Talleres', code='t', customer_endpoints_enabled=True)
        self.other = Client.objects.create(name='Otra', code='o', customer_endpoints_enabled=True)
        site = Site.objects.create(client=self.company, name='Palma', code='p')
        self.pc = EndpointAgent.objects.create(agent_id='003', name='PC-CONTA', status='assigned', client=self.company,
                                               site=site, assigned_at=self.now)
        self.srv = EndpointAgent.objects.create(agent_id='004', name='SRV-ERP', status='assigned', client=self.company,
                                                site=site, assigned_at=self.now)
        self.foreign = EndpointAgent.objects.create(agent_id='005', name='PC-OTRA', status='assigned', client=self.other,
                                                    assigned_at=self.now)
        EndpointAgent.objects.create(agent_id='009', name='SIN-ASIGNAR', status='pending')
        self.docs = [doc('003', 'CVE-2026-1111', 'Google Chrome'), doc('003', 'CVE-2026-2222', 'Zoom', 'Medium', 5.3),
                     doc('004', 'CVE-2026-1111', 'Google Chrome', version='2.0'), doc('005', 'CVE-2026-3333', '7-Zip', 'High', 7.8),
                     doc('009', 'CVE-2026-9999', 'Nada'), doc('003', 'no-es-un-cve', 'Raro')]

    def sync(self, indexer=None, now=None):
        indexer = indexer or FakeIndexer(self.docs)
        with mock.patch.object(ev, '_search', side_effect=indexer), \
                mock.patch('core.reporting.indexer_authorization', return_value='Basic x'):
            ev.sync(now or self.now)
        return indexer


class SyncTests(Base):
    def test_only_assigned_agents_are_read_and_invalid_rows_skipped(self):
        indexer = self.sync()
        self.assertEqual(set(indexer.bodies[0]['query']['bool']['filter'][0]['terms']['agent.id']), {'003', '004', '005'})
        self.assertEqual(EndpointVulnerability.objects.count(), 4)
        row = EndpointVulnerability.objects.get(agent=self.pc, cve='CVE-2026-1111')
        self.assertEqual((row.severity, row.score, row.client, row.version), ('critical', 9.8, self.company, '1.0'))

    def test_what_disappears_after_a_complete_read_is_resolved_and_can_come_back(self):
        self.sync()
        self.docs = [d for d in self.docs if not (d['_source']['agent']['id'] == '003'
                                                  and d['_source']['package']['name'] == 'Google Chrome')]
        self.sync()
        row = EndpointVulnerability.objects.get(agent=self.pc, cve='CVE-2026-1111')
        self.assertIsNotNone(row.resolved_at)
        self.docs.append(doc('003', 'CVE-2026-1111', 'Google Chrome'))
        later = self.now + timezone.timedelta(hours=2)
        self.sync(now=later)
        row.refresh_from_db()
        self.assertEqual((row.resolved_at, row.first_seen_at), (None, later))

    def test_an_incomplete_read_resolves_nothing(self):
        self.sync()
        self.docs = self.docs[:1]
        with mock.patch.object(ev, 'PAGE', 1), mock.patch.object(ev, 'MAX_PAGES', 1):
            self.sync(FakeIndexer(self.docs + [doc('003', 'CVE-2026-4444', 'Otro')]))
        self.assertFalse(EndpointVulnerability.objects.exclude(resolved_at=None).exists())
        self.assertIn('no se ha marcado ninguna', ev.status()['error'])

    def test_permission_error_keeps_the_data_and_explains_the_fix(self):
        self.sync()

        def denied(body, authorization):
            raise urllib.error.HTTPError('https://x', 403, 'Forbidden', {}, io.BytesIO(b'{"error":"proveedor"}'))
        self.sync(denied)
        self.assertEqual(EndpointVulnerability.objects.filter(resolved_at=None).count(), 4)
        issue = OperationalIssue.objects.get(key=ev.ISSUE, active=True)
        self.assertIn('permitir_vulnerabilidades.sh', issue.details)
        self.assertNotIn('proveedor', issue.details)

    def test_retired_equipment_stops_counting(self):
        self.sync()
        EndpointAgent.objects.filter(pk=self.srv.pk).update(status='retired')
        self.sync()
        self.assertIsNotNone(EndpointVulnerability.objects.get(agent=self.srv).resolved_at)


class PageTests(Base):
    def login_customer(self):
        user = get_user_model().objects.create_user('cliente')
        StaffAccess.objects.create(user=user, role='customer').clients.add(self.company)
        self.client.force_login(user)

    def test_customer_sees_only_own_critical_and_high_without_vendor_text(self):
        self.sync()
        self.login_customer()
        page = self.client.get(reverse('customer_endpoints'))
        self.assertContains(page, 'Actualizaciones pendientes')
        self.assertContains(page, 'https://nvd.nist.gov/vuln/detail/CVE-2026-1111')
        self.assertContains(page, 'Google Chrome')
        self.assertNotContains(page, 'CVE-2026-2222', msg_prefix='media: solo como recuento')
        self.assertContains(page, 'Además hay 1 de gravedad media')
        for secret in ('TEXTO DEL PROVEEDOR', '7-Zip', 'PC-OTRA', '003'):
            self.assertNotContains(page, secret)
        home = self.client.get(reverse('customer_home'))
        self.assertContains(home, 'Actualizar 2 equipos con vulnerabilidades críticas')

    def test_soc_page_groups_by_cve_with_affected_devices(self):
        self.sync()
        admin = get_user_model().objects.create_superuser('admin', 'a@example.test', 'x')
        self.client.force_login(admin)
        session = self.client.session
        session.update({'soc_mfa_user': admin.pk, 'soc_mfa_at': time.time()})
        session.save()
        page = self.client.get(reverse('endpoint_vulnerabilities'))
        rows = page.context['rows']
        chrome = next(r for r in rows if r['cve'] == 'CVE-2026-1111')
        self.assertEqual((sorted(chrome['devices']), chrome['versions']), (['PC-CONTA', 'SRV-ERP'], ['1.0', '2.0']))
        self.assertEqual(page.context['totals']['critical'], 2)
        self.assertContains(page, 'Qué actualizar primero')
        self.assertTrue(WorkerState.objects.filter(name=ev.STATE).exists())

    def test_soc_page_needs_operations_permission(self):
        user = get_user_model().objects.create_user('sinpermiso')
        StaffAccess.objects.create(user=user, role='operator', all_clients=True)
        self.client.force_login(user)
        self.assertEqual(self.client.get(reverse('endpoint_vulnerabilities')).status_code, 403)

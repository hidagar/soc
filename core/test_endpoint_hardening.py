"""Configuración segura de los equipos (SCA de Wazuh): ingesta, orden, puntuación, vistas, portal y recuperación."""
import time
from datetime import timedelta
from unittest import mock

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from . import endpoint_hardening, endpoints
from .models import Client, EndpointAgent, EndpointPolicy, EndpointPolicyCheck, Site, StaffAccess, WorkerState
from .operations import ingest_events
from .service_development import portal_attention
from .test_endpoints import alert as defender_alert

POLICY = 'cis_win11_enterprise_21H2'
NAME = 'CIS Microsoft Windows 11 Enterprise Benchmark v1.0.0'
REMEDIATION = 'To establish the recommended configuration via GP, set the following UI path to 14 or more character(s).'


def check(check_id, result, ident, stamp, title=None, previous=None, agent='003'):
    body = {'id': check_id, 'title': title or f"Ensure setting {check_id} is configured", 'result': result,
            'description': 'This policy setting determines...', 'rationale': 'Longer passwords are harder to guess.',
            'remediation': REMEDIATION,
            'compliance': {'cis': '1.1.4', 'cis_csc_v8': ['5.2'], 'pci_dss_v3.2.1': '8.2.3'}}
    if previous:
        body['previous_result'] = previous
    return {'timestamp': stamp.isoformat(), 'id': ident, 'location': 'sca',
            'agent': {'id': agent, 'name': 'PC-CONTA-01', 'ip': '10.0.0.25'},
            'rule': {'id': '19007' if result == 'failed' else '19008', 'level': 7 if result == 'failed' else 3,
                     'groups': ['sca'], 'description': 'SCA check'},
            'decoder': {'name': 'sca'},
            'data': {'sca': {'type': 'check', 'scan_id': '1234', 'policy': NAME, 'policy_id': POLICY, 'check': body}}}


def summary(ident, stamp, score='60', passed='3', failed='2', agent='003'):
    return {'timestamp': stamp.isoformat(), 'id': ident, 'location': 'sca',
            'agent': {'id': agent, 'name': 'PC-CONTA-01', 'ip': '10.0.0.25'},
            'rule': {'id': '19004', 'level': 7, 'groups': ['sca'], 'description': 'SCA summary'}, 'decoder': {'name': 'sca'},
            'data': {'sca': {'type': 'summary', 'scan_id': '1234', 'policy': NAME, 'policy_id': POLICY, 'score': score,
                             'passed': passed, 'failed': failed, 'invalid': '0', 'total_checks': '5', 'file': 'cis_win11.yml'}}}


class HardeningBase(TestCase):
    def setUp(self):
        self.now = timezone.now()
        self.company = Client.objects.create(name='Talleres Ejemplo', code='te', customer_endpoints_enabled=True)
        self.other = Client.objects.create(name='Empresa B', code='b')
        self.site = Site.objects.create(client=self.company, name='Palma', code='palma')
        ingest_events([defender_alert('1150', stamp=self.now - timedelta(hours=3), ident='seed')], self.now)
        EndpointAgent.objects.update(status='assigned', client=self.company, site=self.site,
                                     assigned_at=self.now - timedelta(hours=2))

    def scan(self, minutes=60):
        stamp = self.now - timedelta(minutes=minutes)
        return [check('26001', 'passed', 'c1', stamp), check('26002', 'passed', 'c2', stamp),
                check('26003', 'failed', 'c3', stamp, title="Ensure 'Minimum password length' is set to '14 or more character(s)'"),
                check('26004', 'failed', 'c4', stamp), check('26005', 'not applicable', 'c5', stamp),
                summary('s1', stamp + timedelta(seconds=5))]


class IngestTests(HardeningBase):
    def test_first_scan_stores_checks_and_the_summary(self):
        ingest_events(self.scan(), self.now)
        policy = EndpointPolicy.objects.get()
        self.assertEqual((policy.policy_id, policy.name, policy.score, policy.passed, policy.failed, policy.total),
                         (POLICY, NAME, 60, 3, 2, 5))
        results = dict(EndpointPolicyCheck.objects.values_list('check_id', 'result'))
        self.assertEqual(results, {'26001': 'passed', '26002': 'passed', '26003': 'failed', '26004': 'failed',
                                   '26005': 'not_applicable'})
        row = EndpointPolicyCheck.objects.get(check_id='26003')
        self.assertEqual(row.compliance, {'cis': '1.1.4', 'cis_csc_v8': '5.2', 'pci_dss_v3.2.1': '8.2.3'})
        self.assertEqual((row.remediation, row.client_scope_id), (REMEDIATION, self.company.pk))

    def test_a_change_records_the_previous_result_and_a_late_old_event_does_not_undo_it(self):
        ingest_events(self.scan(minutes=90), self.now)
        ingest_events([check('26001', 'failed', 'later', self.now - timedelta(minutes=10), previous='passed')], self.now)
        row = EndpointPolicyCheck.objects.get(check_id='26001')
        self.assertEqual((row.result, row.previous_result, row.regressed), ('failed', 'passed', True))
        ingest_events([check('26001', 'passed', 'old', self.now - timedelta(minutes=80))], self.now)  # recuperado tarde
        row.refresh_from_db()
        self.assertEqual(row.result, 'failed')
        ingest_events(self.scan(minutes=90), self.now)  # releer no cambia nada
        self.assertEqual(EndpointPolicyCheck.objects.get(check_id='26001').result, 'failed')
        self.assertEqual(EndpointPolicyCheck.objects.count(), 5)

    def test_an_older_summary_does_not_replace_a_newer_one(self):
        ingest_events([summary('new', self.now - timedelta(minutes=5), score='80')], self.now)
        ingest_events([summary('old', self.now - timedelta(minutes=50), score='20')], self.now)
        self.assertEqual(EndpointPolicy.objects.get().score, 80)

    def test_unassigned_agents_and_events_before_the_assignment_are_ignored(self):
        ingest_events([check('1', 'failed', 'x', self.now - timedelta(hours=2, minutes=30))], self.now)
        ingest_events([check('1', 'failed', 'y', self.now, agent='009')], self.now)
        self.assertFalse(EndpointPolicyCheck.objects.exists())
        self.assertFalse(EndpointPolicy.objects.exists())

    def test_alerts_without_the_sca_group_or_identifiers_are_ignored(self):
        broken = check('', 'failed', 'a', self.now)
        other = check('7', 'failed', 'b', self.now)
        other['rule']['groups'] = ['syslog']
        ingest_events([broken, other], self.now)
        self.assertFalse(EndpointPolicyCheck.objects.exists())

    def test_score_is_computed_from_the_checks_until_a_summary_arrives(self):
        ingest_events(self.scan()[:-1], self.now)
        [row] = endpoint_hardening.policy_rows(EndpointPolicy.objects.all())
        self.assertEqual((row['score'], row['from_summary'], row['passed'], row['failed']), (50, False, 2, 2))


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class ViewTests(HardeningBase):
    def login(self, role='operator', all_clients=True, client=None, perms=('manage_operations',)):
        user = get_user_model().objects.create_user(role + str(time.time_ns()))
        access = StaffAccess.objects.create(user=user, role=role, all_clients=all_clients)
        if not all_clients:
            access.clients.add(client or self.company)
        for codename in perms:
            user.user_permissions.add(Permission.objects.get(codename=codename))
        self.client.force_login(user)
        session = self.client.session
        session.update({'soc_mfa_user': user.pk, 'soc_mfa_at': time.time()})
        session.save()

    def test_soc_page_shows_scores_what_to_fix_and_regressions(self):
        ingest_events(self.scan(minutes=90), self.now)
        ingest_events([check('26001', 'failed', 'later', self.now - timedelta(minutes=10), previous='passed')], self.now)
        self.login()
        page = self.client.get(reverse('endpoint_hardening'))
        self.assertContains(page, 'PC-CONTA-01')
        self.assertContains(page, '60 %')
        self.assertContains(page, 'Minimum password length')
        self.assertContains(page, 'Dejaron de cumplir')
        self.assertContains(page, 'Longer passwords are harder to guess.')
        self.assertContains(page, REMEDIATION)

    def test_limited_operators_and_users_without_permission(self):
        ingest_events(self.scan(), self.now)
        self.login(all_clients=False, client=self.other)
        self.assertNotContains(self.client.get(reverse('endpoint_hardening')), 'PC-CONTA-01')
        self.login(perms=())
        self.assertEqual(self.client.get(reverse('endpoint_hardening')).status_code, 403)

    def test_customer_sees_score_and_titles_without_remediation_or_identifiers(self):
        ingest_events(self.scan(), self.now)
        context = endpoint_hardening.customer_context(self.company)
        self.assertEqual([(d['device'], d['policy'], d['score'], d['failed']) for d in context['devices']],
                         [('PC-CONTA-01', NAME, 60, 2)])
        self.assertEqual(endpoint_hardening.customer_context(self.other)['devices'], [])
        self.assertNotIn(REMEDIATION, str(context))
        self.assertNotIn(POLICY, str(context))
        self.login(role='customer', all_clients=False, perms=())
        page = self.client.get(reverse('customer_endpoints'))
        self.assertContains(page, 'Configuración segura')
        self.assertContains(page, 'Minimum password length')
        self.assertNotContains(page, REMEDIATION)
        self.assertNotContains(page, '26003')

    def test_low_scores_ask_the_customer_to_improve_the_configuration(self):
        ingest_events(self.scan()[:-1] + [summary('s', self.now, score='40')], self.now)
        summary_ = endpoints.portal_summary(self.company)
        self.assertEqual((summary_['hardening']['low_devices'], summary_['hardening']['average']), (1, 40))
        items = portal_attention({'portal': {'home': '/', 'policies': '/p', 'requests': '/r', 'endpoints': '/e',
                                             'vulnerabilities': '/v'},
                                  'tasks_to_do': [], 'pending_policies': 0, 'request_summary': {'waiting': 0},
                                  'endpoint_status': summary_, 'open_vulnerabilities': 0})
        self.assertIn('Mejorar la configuración de seguridad de un equipo', [i['title'] for i in items])


class RecoveryTests(HardeningBase):
    def test_first_pass_reaches_30_days_back_and_keeps_its_own_cursor(self):
        stamp = self.now - timedelta(minutes=30)
        hits = [{'_index': 'wazuh-alerts-4.x', '_id': s['id'], '_source': s, 'sort': [s['timestamp'], s['id'], 'wazuh-alerts-4.x']}
                for s in [check('26003', 'failed', 'r1', stamp), summary('r2', stamp)]]
        replies = [{'timed_out': False, '_shards': {'failed': 0}, 'hits': {'hits': hits}}]
        with mock.patch('core.reporting.indexer_authorization', return_value='Basic x'), \
                mock.patch('core.reporting._search', side_effect=lambda body, auth: replies.pop(0)) as search:
            self.assertEqual(endpoints.reconcile(self.now, stream='sca'), 2)
        body = search.call_args.args[0]
        self.assertIn(endpoint_hardening.recovery_filter(), body['query']['bool']['filter'])
        start = body['query']['bool']['filter'][-1]['range']['timestamp']['gte']
        self.assertLessEqual(start, (self.now - timedelta(days=29)).isoformat())
        self.assertIn('completed_until', WorkerState.objects.get(name='endpoint-sca-reconciliation').details)
        self.assertEqual(EndpointPolicyCheck.objects.get().result, 'failed')

    def test_incomplete_answer_keeps_the_cursor(self):
        from .models import OperationalIssue
        replies = [{'timed_out': True, '_shards': {'failed': 0}, 'hits': {'hits': []}}]
        with mock.patch('core.reporting.indexer_authorization', return_value='Basic x'), \
                mock.patch('core.reporting._search', side_effect=lambda body, auth: replies.pop(0)):
            endpoints.reconcile(self.now, stream='sca')
        self.assertNotIn('completed_until', WorkerState.objects.get(name='endpoint-sca-reconciliation').details)
        self.assertTrue(OperationalIssue.objects.filter(key='platform:endpoint-sca-reconciliation', active=True).exists())

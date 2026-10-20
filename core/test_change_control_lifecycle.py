"""Ciclo completo de cambios en firewalls de clientes contra un OPNsense simulado en memoria.

Fija las garantías del módulo (antes 34 % de cobertura): borradores siempre desactivados,
preparación idempotente, activación solo con aprobador, sin cambios ajenos y con
savepoint, y reversión si no se confirma a tiempo.
"""
import copy
from datetime import timedelta
from itertools import count
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from . import change_control
from .change_control import enable, preview, process_queue, stage
from .models import ChangePlan, Client, Device, OpnsenseConnection, Site


class FakeOpnsense:
    def __init__(self, rules=None):
        self.rules = copy.deepcopy(rules or {})
        self.ids = count(1)
        self.calls = []
        self.applied = []
        self.cancelled = []
        self.savepoint_revision = '1700000000.1'
        self.fail_on = None

    def __call__(self, connection, path, payload=None, method=None):
        self.calls.append(path)
        if self.fail_on and self.fail_on in path:
            raise ValueError('Fallo simulado')
        if path.startswith('/api/ids/'):
            raise ValueError('Sin API IDS')
        if path.startswith('/api/firewall/filter/search_rule'):
            return {'rows': [{'uuid': uid, **rule} for uid, rule in self.rules.items()]}
        if path == '/api/firewall/filter/add_rule':
            uid = f'uuid-{next(self.ids)}'
            self.rules[uid] = dict(payload['rule'])
            return {'result': 'saved', 'uuid': uid}
        if path.startswith('/api/firewall/filter/get_rule/'):
            return {'rule': dict(self.rules.get(path.rsplit('/', 1)[1], {}))}
        if path.startswith('/api/firewall/filter/set_rule/'):
            self.rules[path.rsplit('/', 1)[1]].update(payload['rule'])
            return {'result': 'saved'}
        if path.startswith('/api/firewall/filter/del_rule/'):
            self.rules.pop(path.rsplit('/', 1)[1])
            return {'result': 'deleted'}
        if path == '/api/firewall/filter/savepoint':
            return {'revision': self.savepoint_revision}
        if path.startswith('/api/firewall/filter/apply'):
            self.applied.append(path)
            return {'status': 'ok'}
        if path.startswith('/api/firewall/filter/cancel_rollback/'):
            self.cancelled.append(path)
            return {'status': 'ok'}
        if path == '/api/core/system/status':
            return {'status': 'ok'}
        raise AssertionError(path)

    def owned(self, plan):
        return {uid: rule for uid, rule in self.rules.items() if rule.get('description', '').startswith(f'SOC PLAN {plan.pk} ')}


class PreviewTests(SimpleTestCase):
    def test_rules_are_always_disabled_drafts_for_valid_internal_networks(self):
        result = preview('pyme', '192.168.1.0/24, 10.0.0.0/24', 'lan,opt1')
        self.assertEqual([r['enabled'] for r in result['rules']], ['0', '0'])
        self.assertEqual({r['action'] for r in result['rules']}, {'block'})

    def test_invalid_requests_are_refused(self):
        for args in (('desconocida', '192.168.1.0/24', 'lan'), ('pyme', '', 'lan'),
                     ('pyme', ','.join(f'10.0.{i}.0/24' for i in range(11)), 'lan'),
                     ('pyme', '2001:db8::/64', 'lan'), ('pyme', '192.168.1.0/24', 'wan'),
                     ('pyme', '192.168.1.1/24', 'lan')):
            with self.subTest(args), self.assertRaises(ValueError):
                preview(*args)


class ChangeLifecycleTests(TestCase):
    def setUp(self):
        site = Site.objects.create(client=Client.objects.create(name='A', code='a'), name='S', code='s')
        self.device = Device.objects.create(site=site, name='FW', vendor='opnsense', management_method='api')
        OpnsenseConnection.objects.create(device=self.device, api_url='https://fw.example.test',
                                          encrypted_api_key='x', encrypted_api_secret='x')
        self.approver = get_user_model().objects.create_user('aprobador')
        self.plan = ChangePlan.objects.create(device=self.device, template='pyme', title='PYME',
                                              preview=preview('pyme', '192.168.1.0/24,192.168.2.0/24', 'lan'))
        self.firewall = FakeOpnsense({'existing': {'description': 'Regla del cliente', 'enabled': '1'}})
        patcher = mock.patch.object(change_control, 'api', side_effect=self.firewall)
        patcher.start()
        self.addCleanup(patcher.stop)

    def staged(self):
        stage(self.plan)
        self.assertEqual(self.plan.status, 'staged')
        return self.firewall.owned(self.plan)

    def test_staging_creates_only_disabled_drafts_and_never_applies(self):
        owned = self.staged()
        self.assertEqual(len(owned), 2)
        self.assertEqual({rule['enabled'] for rule in owned.values()}, {'0'})
        self.assertEqual(self.firewall.applied, [])
        self.assertEqual(self.firewall.rules['existing'], {'description': 'Regla del cliente', 'enabled': '1'})

    def test_staging_again_after_an_interruption_does_not_duplicate_rules(self):
        self.staged()
        self.plan.status = 'staging'
        self.plan.remote_objects = []
        stage(self.plan)
        self.assertEqual(len(self.firewall.owned(self.plan)), 2)

    def test_activation_without_an_identified_approver_never_reaches_the_firewall(self):
        self.staged()
        ChangePlan.objects.filter(pk=self.plan.pk).update(status='apply_queued')
        calls = len(self.firewall.calls)
        process_queue()
        self.plan.refresh_from_db()
        self.assertEqual(self.plan.status, 'needs_review')
        self.assertEqual(len(self.firewall.calls), calls)

    def test_activation_refuses_if_other_rules_changed_since_staging(self):
        self.staged()
        self.firewall.rules['existing']['enabled'] = '0'
        with self.assertRaises(ValueError):
            enable(self.plan)
        self.assertEqual({rule['enabled'] for rule in self.firewall.owned(self.plan).values()}, {'0'})
        self.assertNotIn('/api/firewall/filter/savepoint', self.firewall.calls)

    def test_no_savepoint_means_nothing_is_activated(self):
        self.staged()
        self.firewall.savepoint_revision = ''
        with self.assertRaises(ValueError):
            enable(self.plan)
        self.assertEqual({rule['enabled'] for rule in self.firewall.owned(self.plan).values()}, {'0'})

    def test_activation_waits_for_confirmation_and_confirmed_plan_becomes_active(self):
        self.staged()
        enable(self.plan)
        self.assertEqual(self.plan.status, 'awaiting_confirmation')
        self.assertEqual({rule['enabled'] for rule in self.firewall.owned(self.plan).values()}, {'1'})
        self.assertIn('/api/firewall/filter/apply/' + self.firewall.savepoint_revision, self.firewall.applied)
        ChangePlan.objects.filter(pk=self.plan.pk).update(status='confirm_queued', approved_by=self.approver)
        process_queue()
        self.plan.refresh_from_db()
        self.assertEqual(self.plan.status, 'active')
        self.assertEqual(self.firewall.cancelled, ['/api/firewall/filter/cancel_rollback/' + self.firewall.savepoint_revision])

    def test_unconfirmed_activation_is_rolled_back_after_the_deadline(self):
        self.staged()
        enable(self.plan)
        ChangePlan.objects.filter(pk=self.plan.pk).update(confirmation_deadline=timezone.now() - timedelta(seconds=1))
        process_queue()
        self.plan.refresh_from_db()
        self.assertEqual(self.plan.status, 'rolled_back')
        self.assertEqual({rule['enabled'] for rule in self.firewall.owned(self.plan).values()}, {'0'})
        self.assertEqual(self.firewall.cancelled, [])
        self.assertEqual(self.firewall.rules['existing']['enabled'], '1')

    def test_failure_during_activation_reverts_owned_rules(self):
        self.staged()
        self.firewall.fail_on = '/api/core/system/status'
        enable(self.plan)
        self.assertEqual(self.plan.status, 'rolled_back')
        self.assertEqual({rule['enabled'] for rule in self.firewall.owned(self.plan).values()}, {'0'})

    def test_rollback_never_touches_a_rule_that_changed_owner(self):
        self.staged()
        uid = next(iter(self.firewall.owned(self.plan)))
        self.firewall.rules[uid]['description'] = 'Regla reutilizada por el cliente'
        ChangePlan.objects.filter(pk=self.plan.pk).update(status='rollback_queued')
        process_queue()
        self.plan.refresh_from_db()
        self.assertEqual(self.plan.status, 'needs_review')
        self.assertIn(uid, self.firewall.rules)
        self.assertFalse(any('del_rule/' + uid in call or 'set_rule/' + uid in call for call in self.firewall.calls))

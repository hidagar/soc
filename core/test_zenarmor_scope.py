import copy
import json
from datetime import timedelta
from unittest.mock import Mock, patch
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from .models import (Client, Site, Device, DeviceHealth, StaffAccess,
    ProtectionValidation, SecurityEvidence, Asset)
from .network_coverage import save_discovery, snapshot, fingerprint
from .zenarmor_scope import collect, parse_interfaces, parse_policy, network_snapshot, scope_current


def policy(pid=0, **changes):
    return {**{'id': pid, 'name': 'Default' if pid == 0 else 'Política específica', 'isActive': True,
        'configs': {'security': True, 'app': False, 'web': False, 'tls': False,
            'sort_number': pid, 'interfaces': [], 'interface_tags': [], 'vlans': [],
            'groups': [], 'usernames': [], 'directions': {'inbound': True, 'outbound': True}},
        'networks': [], 'mac_addresses': [], 'devices': [], 'device_categories': [],
        'schedules': [], 'exclusions': [], 'essential_security': [101, 104], 'advanced_security': [],
        'nodes': [{'id': 'local-node'}], 'checksum': 1}, **changes}


def status(**changes):
    return {**{'interfaces_list': [{'interface': 'igc0', 'tags': ['lan']}],
        'deployment_mode': 'routed'}, **changes}


def reader(policies):
    catalogue = {'policies': [{'id': p['id'], 'isActive': p['isActive'], 'checksum': 1,
        'nodes': p['nodes']} for p in policies]}
    def api(connection, path):
        if path == '/api/zenarmor/policy/index':
            return copy.deepcopy(catalogue)
        pid = int(path.split('id=')[1])
        return copy.deepcopy(next(p for p in policies if p['id'] == pid))
    return Mock(side_effect=api)


class ZenarmorScopeParsingTests(SimpleTestCase):
    def test_only_read_endpoints_and_no_raw_auth_identity_exceptions_stored(self):
        p = policy()
        p.update(user='PRIVATE', nodeAuth='PRIVATE', exclusions=[{'value': 'PRIVATE', 'list': 'whitelist'}])
        p['configs']['usernames'] = ['PRIVATE']
        api = reader([p])
        result = collect(None, status(nodeAuth='PRIVATE'), api)
        self.assertEqual(result['policies_status'], 'checked')
        self.assertNotIn('PRIVATE', json.dumps(result))
        self.assertEqual(result['policies'][0]['exclusion_count'], 1)
        self.assertEqual(result['policies'][0]['restrictions'], ['usuarios: 1'])
        self.assertEqual([c.args[1] for c in api.call_args_list], [
            '/api/zenarmor/policy/index', '/api/zenarmor/policy/detail?id=0', '/api/zenarmor/policy/index'])
        self.assertTrue(all(len(c.args) == 2 and not c.kwargs for c in api.call_args_list))

    def test_empty_interface_selection_known_but_missing_or_malformed_unknown(self):
        self.assertEqual(parse_interfaces(status(interfaces_list=[])), [])
        for value in [None, ['igc0'], [{'interface': 'igc0', 'tags': None}],
                [{'interface': 'igc0', 'tags': []}] * 2]:
            result = collect(None, status(interfaces_list=value), reader([policy()]))
            self.assertFalse(result['interfaces_known'])

    def test_partial_failure_preserves_history_and_retires_fingerprint(self):
        old = collect(None, status(), reader([policy()]))
        failed = collect(None, status(), Mock(side_effect=ValueError('PRIVATE')), previous=old)
        self.assertEqual(failed['policies'], old['policies'])
        self.assertEqual(failed['policies_last_success_at'], old['policies_last_success_at'])
        self.assertEqual(failed['policies_status'], 'unavailable')
        self.assertNotIn('policy_fingerprint', failed)
        self.assertNotIn('PRIVATE', json.dumps(failed))

    def test_policy_changes_during_read_are_rejected(self):
        api = reader([policy()])
        original = api.side_effect
        calls = []
        def changed(c, path):
            data = original(c, path); calls.append(path)
            if len(calls) == 3: data['policies'][0]['checksum'] = 2
            return data
        api.side_effect = changed
        self.assertEqual(collect(None, status(), api)['policies_status'], 'unavailable')

    def test_policy_id_unknown_states_duplicates_limits_and_nodes_fail_closed(self):
        cases = [[policy(id='0')], [policy(isActive='false')], [policy(), policy()],
            [policy(i) for i in range(26)], [policy(nodes=[{'id': 'a'}, {'id': 'b'}])],
            [policy(), policy(1, nodes=[{'id': 'other-node'}])]]
        for policies in cases:
            with self.subTest(policies=len(policies)):
                self.assertEqual(collect(None, status(), reader(policies))['policies_status'], 'unavailable')

    def test_wrong_detail_missing_criteria_and_unknown_criteria_fail_closed(self):
        for change in [{'id': 1}, {'networks': [{'value': 'hostname', 'is_disabled': False}]},
                {'configs': {**policy()['configs'], 'new_scope_filter': True}}, {'exclusions': None}]:
            with self.subTest(change=next(iter(change))):
                with self.assertRaises((ValueError, TypeError)):
                    parse_policy(policy(**change), '0')

    def test_bounded_time_budget_and_future_or_stale_not_current(self):
        with patch('core.zenarmor_scope.time.monotonic', side_effect=[0, 31]):
            self.assertEqual(collect(None, status(), reader([policy()]))['policies_status'], 'unavailable')
        now = timezone.now()
        for stamp in [now - timedelta(hours=1), now + timedelta(minutes=1)]:
            self.assertFalse(scope_current({'schema': 1, 'checked_at': stamp.isoformat()}, now))


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class ZenarmorNetworkTests(TestCase):
    def setUp(self):
        self.now = timezone.now()
        company = Client.objects.create(name='Visible', code='zen-visible')
        self.device = Device.objects.create(site=Site.objects.create(client=company, name='Oficina', code='zen-office'),
            name='Firewall', vendor='opnsense', management_method='api', zenarmor_enabled=True)
        self.health = DeviceHealth.objects.create(device=self.device, api_ok=True, protection_checked_at=self.now,
            engines={'Zenarmor': {'configured': True, 'running': True, 'bypass': False,
                'scope': collect(None, status(), reader([policy()]), now=self.now)}})
        save_discovery(self.device, [{'remote_id': 'lan', 'name': 'Administración', 'interface': 'lan',
            'physical_interface': 'igc0', 'cidrs': ['192.168.1.0/24'], 'enabled': True,
            'inspection_selected': None}], self.now)
        self.network = self.device.networks.get()
        self.user = get_user_model().objects.create_user('zen-operator')
        self.user.groups.add(Group.objects.get(name='SOC Operador'))
        access = StaffAccess.objects.create(user=self.user, role='operator'); access.clients.add(company)
        self.client.force_login(self.user)

    def set_policies(self, policies, **changes):
        self.health.engines['Zenarmor']['scope'] = collect(None, status(**changes), reader(policies), now=self.now)
        self.health.save()
        self.device.health = self.health

    def test_exact_selected_interface_does_not_inherit_to_vlan(self):
        self.assertTrue(network_snapshot(self.network, True, self.now)['selection'])
        self.network.physical_interface = 'igc0_vlan20'; self.network.interface = 'opt1'
        result = network_snapshot(self.network, True, self.now)
        self.assertFalse(result['selection']); self.assertEqual(result['candidates'], [])

    def test_candidates_filter_interface_tag_network_and_keep_default(self):
        wrong_if = policy(1); wrong_if['configs']['interfaces'] = ['igc1']
        wrong_tag = policy(2); wrong_tag['configs']['interface_tags'] = ['guest']
        wrong_ip = policy(3, networks=[{'value': '10.0.0.0/24', 'is_disabled': False}])
        specific = policy(4, networks=[{'value': '192.168.1.20', 'is_disabled': False}])
        specific['configs']['usernames'] = ['PRIVATE']; specific['configs']['vlans'] = [20]
        inactive = policy(5, isActive=False)
        self.set_policies([policy(), wrong_if, wrong_tag, wrong_ip, specific, inactive])
        row = network_snapshot(self.network, True, self.now)
        self.assertEqual({p['id'] for p in row['candidates']}, {'0', '4'})
        self.assertEqual(next(p for p in row['candidates'] if p['id'] == '4')['restrictions'], ['usuarios: 1'])
        # A /32 overlapping the subnet stays a candidate, never blanket coverage.
        self.assertNotIn('protected', row)

    def test_required_network_keeps_global_exemption_and_proof_pending(self):
        self.network.scope = 'included'; self.network.require_zenarmor = True
        row = snapshot(self.network, self.now)
        self.assertIn('exenciones globales', ' '.join(row['gaps']))
        self.assertIn('prueba Zenarmor', ' '.join(row['gaps']))
        self.assertNotIn('consulta completa', ' '.join(row['gaps']).lower())

    def proof(self, action='blocked'):
        asset = Asset.objects.create(device=self.device, ip='192.168.1.20')
        evidence = SecurityEvidence.objects.create(uid='zen-proof', device=self.device,
            asset=asset, observed_at=self.now, engine='zenarmor', signature='SOC TEST', action=action)
        return ProtectionValidation.objects.create(device=self.device, network=self.network, engine='zenarmor',
            test_ip=asset.ip, networks='PC', expected_signature='SOC TEST', started_at=self.now,
            expires_at=self.now + timedelta(hours=1), network_snapshot=self.network.cidrs,
            configuration_fingerprint=fingerprint(self.network, 'zenarmor'), evidence=evidence)

    def test_changed_policy_exception_invalidates_proof_without_erasing_history(self):
        proof = self.proof(); self.assertEqual(len(snapshot(self.network, self.now)['proofs']), 1)
        self.set_policies([policy(exclusions=[{'list': 'whitelist', 'value': 'PRIVATE'}])])
        self.assertEqual(snapshot(self.network, self.now)['proofs'], [])
        proof.refresh_from_db(); self.assertIsNotNone(proof.evidence)

    def test_suricata_change_does_not_change_zenarmor_fingerprint(self):
        before = fingerprint(self.network, 'zenarmor')
        self.network.inspection_selected = True
        self.assertEqual(before, fingerprint(self.network, 'zenarmor'))

    def test_failed_scope_stale_health_paused_and_bypass_have_clear_states(self):
        self.health.engines['Zenarmor']['bypass'] = True
        self.assertIn('bypass', network_snapshot(self.network, True, self.now)['label'])
        self.device.integration = 'paused'
        self.assertFalse(snapshot(self.network, self.now)['zenarmor']['current'])
        self.device.integration = 'pending'
        self.health.api_ok = False
        self.assertFalse(snapshot(self.network, self.now)['zenarmor']['current'])

    def test_unknown_action_and_failed_catalogue_never_validate_blocking(self):
        self.network.scope = 'included'; self.network.require_zenarmor = True
        self.proof('unknown')
        self.assertIn('no acredita bloqueo', ' '.join(snapshot(self.network, self.now)['gaps']))
        self.health.engines['Zenarmor']['scope']['policies_status'] = 'unavailable'
        self.assertEqual(snapshot(self.network, self.now)['proofs'], [])

    def test_page_scoped_and_policy_name_escaped(self):
        self.set_policies([policy(name='<script>PRIVATE</script>')])
        hidden = Client.objects.create(name='Hidden', code='zen-hidden')
        other = Device.objects.create(site=Site.objects.create(client=hidden, name='Private', code='private'),
            name='Private firewall', vendor='opnsense', zenarmor_enabled=True)
        DeviceHealth.objects.create(device=other, engines={'Zenarmor': {'scope': {'policies': [{'name': 'HIDDEN POLICY'}]}}})
        response = self.client.get(reverse('network_coverage'))
        self.assertContains(response, 'Catálogo de políticas consultado')
        self.assertContains(response, '&lt;script&gt;PRIVATE&lt;/script&gt;')
        self.assertNotContains(response, '<script>PRIVATE</script>')
        self.assertNotContains(response, 'HIDDEN POLICY')
        self.assertEqual(self.client.get(reverse('device_coverage', args=[other.pk])).status_code, 404)

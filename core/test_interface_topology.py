import copy
import json
from datetime import timedelta
from unittest.mock import Mock, patch
from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone
from .interface_topology import project, collect, current, PATHS, OVERVIEW_PATH
from .network_coverage import fingerprint, snapshot, discover_networks
from . import test_zenarmor_scope as zen_fixtures


def catalogue(rows):
    return {'total': len(rows), 'rows': rows}


def fixtures():
    overview = catalogue([
        {'device': 'igc0', 'identifier': 'opt1', 'is_physical': True},
        {'device': 'igc1', 'identifier': 'opt2', 'is_physical': True},
        {'device': 'vlan01', 'identifier': 'opt3', 'is_physical': False, 'vlan_tag': '20'},
        {'device': 'bridge0', 'identifier': 'lan', 'is_physical': False,
         'members': {'igc0': {'flags': ['learning']}, 'igc1': {'flags': ['learning']}}},
        {'device': 'pppoe0', 'identifier': 'wan', 'is_physical': False, 'link_type': 'pppoe'},
        {'device': 'wg0', 'identifier': 'opt4', 'is_physical': False, 'link_type': 'static'},
        {'device': 'lo0', 'identifier': 'lo0', 'is_physical': False},
    ])
    vlans = catalogue([{'vlanif': 'vlan01 [Invitados]', 'if': 'igc0', 'tag': '20'}])
    bridges = catalogue([{'bridgeif': 'bridge0', 'members': 'opt1,opt2'}])
    return overview, vlans, bridges


class TopologyParsingTests(SimpleTestCase):
    def test_exact_identities_parent_bridge_and_virtual_without_guessing_tunnel(self):
        result = project(*fixtures())
        self.assertEqual(result['opt3']['parents'], ['igc0'])
        self.assertEqual(result['opt3']['vlan'], 20)
        self.assertEqual(result['lan']['members'], ['igc0', 'igc1'])
        self.assertEqual(result['lan']['related_interfaces'], ['opt1', 'opt2'])
        self.assertEqual(result['wan']['link'], 'pppoe')
        self.assertEqual(result['opt4']['kind'], 'virtual')
        self.assertEqual(result['opt4']['link'], '')  # name wg0 does not prove a live tunnel.
        self.assertNotIn('lo0', result)

    def test_projection_discards_descriptions_uuid_secrets_addresses(self):
        overview, vlans, bridges = fixtures()
        for data in (overview, vlans, bridges):
            for row in data['rows']:
                row.update(password='PRIVATE', uuid='PRIVATE', description='PRIVATE', config={'token': 'PRIVATE'})
        vlans['rows'][0]['vlanif'] = 'vlan01 [PRIVATE]'
        self.assertNotIn('PRIVATE', json.dumps(project(overview, vlans, bridges)))

    def test_partial_catalogue_unknown_shape_duplicates_and_ambiguous_ids_fail_closed(self):
        cases = []
        for index in range(3):
            values = fixtures(); values[index]['total'] += 1; cases.append(values)
        values = fixtures(); values[0]['rows'].append(values[0]['rows'][0]); values[0]['total'] += 1; cases.append(values)
        values = fixtures(); values[0]['rows'][1]['identifier'] = 'opt1'; cases.append(values)
        values = fixtures(); values[1]['rows'][0]['vlanif'] = 'prefix vlan01 [Description]'; cases.append(values)
        values = fixtures(); values[1]['rows'][0]['tag'] = True; cases.append(values)
        values = fixtures(); values[0]['rows'][0]['is_physical'] = 'true'; cases.append(values)
        for values in cases:
            with self.assertRaises(ValueError): project(*values)

    def test_missing_runtime_parent_vlan_tag_and_bridge_members_mismatch_fail_closed(self):
        for modify in (
            lambda o,v,b: v['rows'][0].update({'if': 'missing'}),
            lambda o,v,b: o['rows'][2].update(vlan_tag='21'),
            lambda o,v,b: b['rows'][0].update(members='opt1'),
            lambda o,v,b: b['rows'][0].update(members='unassigned'),
            lambda o,v,b: v.update(rows=[], total=0),
            lambda o,v,b: b.update(rows=[], total=0),
        ):
            values = fixtures(); modify(*values)
            with self.assertRaises(ValueError): project(*values)

    def test_cycles_and_nested_parent_changes_rejected_or_change_fingerprint(self):
        overview, vlans, bridges = fixtures()
        overview['rows'].append({'device': 'vlan02', 'identifier': 'opt5', 'is_physical': False, 'vlan_tag': '30'})
        overview['total'] += 1
        vlans['rows'].append({'vlanif': 'vlan02', 'if': 'vlan01', 'tag': '30'}); vlans['total'] += 1
        before = project(overview, vlans, bridges)['opt5']['path_fingerprint']
        overview['rows'][2]['vlan_tag'] = '21'; vlans['rows'][0]['tag'] = '21'
        self.assertNotEqual(before, project(overview, vlans, bridges)['opt5']['path_fingerprint'])
        vlans['rows'][0]['if'] = 'vlan02'
        with self.assertRaises(ValueError): project(overview, vlans, bridges)

    def test_only_get_requests_and_repeated_catalogue_revision(self):
        overview, vlans, bridges = fixtures()
        api = Mock(side_effect=[vlans, bridges, copy.deepcopy(vlans), copy.deepcopy(bridges), overview])
        result = collect(None, overview, api)
        self.assertEqual(result['status'], 'checked')
        self.assertEqual([v.args[1] for v in api.call_args_list], list(PATHS) * 2 + [OVERVIEW_PATH])
        self.assertTrue(all(len(v.args) == 2 and not v.kwargs for v in api.call_args_list))
        changed = copy.deepcopy(vlans); changed['rows'][0]['if'] = 'igc1'
        api = Mock(side_effect=[vlans, bridges, changed, bridges, overview])
        failed = collect(None, overview, api, previous=result)
        self.assertEqual(failed['status'], 'unavailable')
        self.assertEqual(failed['networks'], result['networks'])
        self.assertEqual(failed['last_success_at'], result['last_success_at'])

    def test_timeout_unknown_errors_and_stale_future_are_not_current(self):
        overview, _, _ = fixtures()
        api = Mock(side_effect=RuntimeError('PRIVATE'))
        failed = collect(None, overview, api)
        self.assertNotIn('PRIVATE', json.dumps(failed))
        with patch('core.interface_topology.time.monotonic', side_effect=[0, 31]):
            api.reset_mock()
            self.assertEqual(collect(None, overview, api)['status'], 'unavailable')
            api.assert_not_called()
        now = timezone.now()
        for stamp in (now - timedelta(minutes=31), now + timedelta(seconds=1)):
            self.assertFalse(current({'schema': 1, 'status': 'checked', 'checked_at': stamp.isoformat()}, now))


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class TopologyNetworkTests(TestCase):
    setUp = zen_fixtures.ZenarmorNetworkTests.setUp
    proof = zen_fixtures.ZenarmorNetworkTests.proof
    def topology(self, overview=None, vlans=None, bridges=None):
        default = fixtures()
        overview, vlans, bridges = overview or default[0], vlans or default[1], bridges or default[2]
        self.health.engines.setdefault('Suricata', {})['topology'] = collect(None, overview,
            Mock(side_effect=[vlans, bridges, vlans, bridges, overview]), now=self.now)
        self.health.save(); self.device.health = self.health

    def test_bridge_related_selected_port_does_not_inherit_inspection(self):
        self.network.physical_interface = 'bridge0'
        self.topology()
        row = snapshot(self.network, self.now)
        self.assertTrue(row['topology']['current'])
        self.assertIn('igc0', ' '.join(row['topology']['relations']))
        self.assertFalse(row['zenarmor']['selection'])
        self.assertEqual(row['zenarmor']['candidates'], [])

    def test_topology_change_or_failed_read_retires_proof_without_deleting_evidence(self):
        self.network.remote_id = 'opt1'; self.network.interface = 'opt1'
        self.topology()
        proof = self.proof()
        self.assertEqual(len(snapshot(self.network, self.now)['proofs']), 1)
        self.health.engines['Suricata']['topology']['status'] = 'unavailable'
        self.assertEqual(snapshot(self.network, self.now)['proofs'], [])
        proof.refresh_from_db(); self.assertIsNotNone(proof.evidence)

    def test_changed_bridge_member_changes_configuration_fingerprint(self):
        self.network.physical_interface = 'bridge0'
        self.topology(); before = fingerprint(self.network, 'zenarmor')
        overview, vlans, bridges = fixtures()
        overview['rows'][3]['members'].pop('igc1'); bridges['rows'][0]['members'] = 'opt1'
        self.topology(overview, vlans, bridges)
        self.assertNotEqual(before, fingerprint(self.network, 'zenarmor'))

    def test_page_relationships_visible_and_failed_read_has_guidance(self):
        from django.urls import reverse
        self.network.physical_interface = 'bridge0'; self.network.save()
        self.topology()
        response = self.client.get(reverse('device_coverage', args=[self.device.pk]))
        self.assertContains(response, 'Miembros del puente: igc0, igc1')
        self.assertContains(response, 'Validar el recorrido y probar esta red')
        self.assertContains(response, 'Última lectura válida: ' + timezone.localtime(self.now).strftime('%d/%m/%Y %H:%M'))
        self.health.engines['Suricata']['topology']['status'] = 'unavailable'; self.health.save()
        response = self.client.get(reverse('device_coverage', args=[self.device.pk]))
        self.assertContains(response, 'Topología: consulta actual pendiente')
        self.assertNotContains(response, 'Miembros del puente:')

    def test_discovery_saves_topology_and_partial_failure_preserves_only_history(self):
        from .models import OpnsenseConnection
        # Credentials are never consulted by this mocked read adapter.
        OpnsenseConnection.objects.create(device=self.device, api_url='https://firewall.example')
        overview, vlans, bridges = fixtures()
        def api(connection, path):
            if '/overview/' in path: return overview
            return vlans if '/vlan_settings/' in path else bridges
        with patch('core.provisioning._api_request', side_effect=api):
            self.assertEqual(discover_networks(self.device, self.health.engines, self.now), 6)
        self.health.refresh_from_db()
        before = self.health.engines['Suricata']['topology']
        self.assertEqual(before['status'], 'checked')
        def failed(connection, path):
            if '/overview/' in path: return overview
            raise ValueError('PRIVATE')
        with patch('core.provisioning._api_request', side_effect=failed):
            self.assertEqual(discover_networks(self.device, self.health.engines, self.now), 6)
        self.health.refresh_from_db()
        result = self.health.engines['Suricata']['topology']
        self.assertEqual(result['status'], 'unavailable')
        self.assertEqual(result['networks'], before['networks'])
        self.assertNotIn('PRIVATE', json.dumps(result))

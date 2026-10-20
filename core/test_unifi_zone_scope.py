import copy
import json
from datetime import timedelta
from unittest.mock import Mock, patch
from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.urls import reverse
from .models import Client, Site, Device, StaffAccess, ExposureCheck
from .unifi_zone_scope import project, catalogue, collect, snapshot, integration_json
from .unifi_cloud import UnifiCloudError


def uid(n): return '00000000-0000-0000-0000-' + f'{n:012d}'


def policy(n=1, **changes):
    return {**{'id': uid(100+n), 'name': 'Política ' + str(n), 'enabled': True, 'index': n,
        'loggingEnabled': False, 'action': {'type': 'ALLOW', 'allowReturnTraffic': True},
        'metadata': {'origin': 'SYSTEM_DEFINED'}, 'ipProtocolScope': {'ipVersion': 'IPV4_AND_IPV6'},
        'source': {'zoneId': uid(1)}, 'destination': {'zoneId': uid(2)}}, **changes}


def fixtures(policies=None):
    return [
        [{'id': uid(1), 'name': 'Usuarios', 'networkIds': [uid(4)]},
         {'id': uid(2), 'name': 'Exterior', 'networkIds': [uid(3)]}],
        policies if policies is not None else [policy()],
        [{'id': uid(4), 'name': 'Oficina', 'zoneId': uid(1)}],
        [{'id': uid(5), 'name': 'Objeto permitido', 'type': 'IPV4_ADDRESSES',
            'items': [{'type': 'NETWORK', 'value': 'PRIVATE'}]}],
    ]


def reader(values=None):
    values = values or fixtures()
    resources = dict(zip(('zones','policies','networks','traffic-matching-lists'), values))
    def api(key, host, path, offset=0, limit=100):
        rows = [{'id': uid(9), 'internalReference': 'default', 'name': 'Default'}] if path == '/v1/sites' else resources[path.split('/')[-1]]
        page = copy.deepcopy(rows[offset:offset+limit])
        return {'offset': offset, 'limit': limit, 'count': len(page), 'totalCount': len(rows), 'data': page}
    return Mock(side_effect=api)


class UniFiZoneParsingTests(SimpleTestCase):
    def test_current_official_catalogue_read_only_and_no_raw_filters_or_secrets(self):
        p = policy(source={'zoneId': uid(1), 'trafficFilter': {'type': 'IP_ADDRESS', 'ipAddressFilter': {
            'type': 'TRAFFIC_MATCHING_LIST', 'matchOpposite': False, 'trafficMatchingListId': uid(5)}}},
            token='PRIVATE')
        values = fixtures([p]); api = reader(values)
        connection = Mock(encrypted_api_key='ciphertext', remote_host_id='host')
        with patch('core.unifi_zone_scope.decrypt_api_key', return_value='key'):
            result = collect(connection, api=api)
        self.assertEqual(result['status'], 'checked')
        self.assertNotIn('PRIVATE', json.dumps(result))
        row = result['catalogue']['pairs'][0]['policies'][0]
        self.assertIn('Objeto permitido (1 entradas)', row['criteria'][0])
        self.assertTrue(row['criteria_pending'])
        self.assertEqual(len(api.call_args_list), 9)
        self.assertTrue(all(len(c.args) == 5 and not c.kwargs for c in api.call_args_list))

    def test_order_disabled_generated_unidentified_and_ties_are_explicit(self):
        rows = [policy(4, enabled=False), policy(3, id=None), policy(2), policy(1, index=2)]
        result = project(*fixtures(rows))
        pair = result['pairs'][0]
        self.assertEqual([p['index'] for p in pair['policies']], [2,2,3,4])
        self.assertEqual(pair['active_count'], 3); self.assertEqual(pair['disabled_count'], 1)
        self.assertFalse(pair['order_unambiguous']); self.assertEqual(result['unidentified_count'], 1)
        self.assertTrue(pair['policies'][0]['return_traffic'])
        self.assertNotIn('effective', result)

    def test_exact_network_membership_and_unresolved_external_members(self):
        result = project(*fixtures())
        self.assertEqual(result['zones'][0]['unresolved_networks'], 1)
        users = next(z for z in result['zones'] if z['name'] == 'Usuarios')
        self.assertEqual(users['networks'], ['Oficina'])
        values = fixtures(); values[0][1]['networkIds'].append(uid(4))
        with self.assertRaises(ValueError): project(*values)
        values = fixtures(); values[2][0]['zoneId'] = uid(2)
        with self.assertRaises(ValueError): project(*values)

    def test_duplicate_identity_missing_zone_and_unknown_action_state_fail_closed(self):
        cases = [[policy(), policy()], [policy(id=None), policy(id=None)], [policy(enabled='false')],
            [policy(action={'type': 'UNKNOWN'})], [policy(index=True)],
            [policy(source={'zoneId': uid(8)})], [policy(connectionStateFilter=['UNKNOWN'])]]
        for policies in cases:
            with self.assertRaises(ValueError): project(*fixtures(policies))

    def test_complete_pagination_and_bounds(self):
        rows = [policy(n) for n in range(101)]
        api = reader(fixtures(rows))
        read = lambda p,o,l: api('key', 'host', p,o,l)
        self.assertEqual(len(catalogue(read, '/v1/sites/'+uid(9)+'/firewall/policies', float('inf'))), 101)
        for data in ({'data':[],'offset':0,'limit':100,'count':0,'totalCount':1},
            {'data':[],'offset':100,'limit':100,'count':0,'totalCount':0},
            {'data':[],'offset':0,'limit':100,'count':0,'totalCount':501}):
            with self.assertRaises(ValueError): catalogue(Mock(return_value=data), '/v1/sites', float('inf'))

    def test_failed_or_changing_read_keeps_history_without_claiming_current(self):
        connection = Mock(encrypted_api_key='ciphertext', remote_host_id='host')
        with patch('core.unifi_zone_scope.decrypt_api_key', return_value='key'):
            previous = collect(connection, api=reader())
            result = collect(connection, previous=previous, api=Mock(side_effect=ValueError('PRIVATE')))
        self.assertEqual(result['status'], 'unavailable')
        self.assertEqual(result['catalogue'], previous['catalogue'])
        self.assertEqual(result['last_success_at'], previous['last_success_at'])
        self.assertNotIn('PRIVATE', json.dumps(result))
        api = reader(); base = api.side_effect; calls = []
        def changed(*args):
            data = base(*args); calls.append(args[2])
            if len(calls) == 7: data['data'][0]['enabled'] = False
            return data
        api.side_effect = changed
        with patch('core.unifi_zone_scope.decrypt_api_key', return_value='key'):
            self.assertEqual(collect(connection, api=api)['status'], 'unavailable')

    def test_object_contents_and_policy_changes_change_fingerprint(self):
        values = fixtures(); before = project(*values)['fingerprint']
        values[3][0]['items'][0]['value'] = 'CHANGED'
        self.assertNotEqual(before, project(*values)['fingerprint'])
        before = project(*values)['fingerprint']; values[1][0]['enabled'] = False
        self.assertNotEqual(before, project(*values)['fingerprint'])

    def test_unresolved_network_nested_extensions_and_unparsed_conditions_pending(self):
        for spec in ({'networkIds':[uid(8)], 'matchOpposite':False},
                     {'networkIds':[uid(4)], 'matchOpposite':False, 'additionalCondition':'PRIVATE'}):
            p = policy(source={'zoneId':uid(1), 'trafficFilter':{'type':'NETWORK', 'networkFilter':spec}})
            result = project(*fixtures([p]))
            self.assertTrue(result['pairs'][0]['policies'][0]['criteria_pending'])
            self.assertNotIn('PRIVATE', json.dumps(result))
        for extra in ({'schedule':{'PRIVATE':'value'}}, {'ipsecFilter':{'PRIVATE':'value'}},
                      {'action':{'type':'ALLOW', 'additionalCondition':'PRIVATE'}}):
            result = project(*fixtures([policy(**extra)]))
            self.assertTrue(result['pairs'][0]['policies'][0]['criteria_pending'])
            self.assertNotIn('PRIVATE', json.dumps(result))
        with self.assertRaises(ValueError):
            project(*fixtures([policy(action={'type':'ALLOW', 'allowReturnTraffic':'true'})]))

    def test_get_adapter_rejects_host_paths_queries_traversal_and_oversize_response(self):
        with patch('core.unifi_zone_scope.request.build_opener') as opener:
            for host,path in [('host/other','/v1/sites'),('host','https://evil.example'),
                ('host','/v1/sites?filter=all'),('host','/v1/sites/'+uid(9)+'/firewall/policies/../zones')]:
                with self.assertRaises(UnifiCloudError): integration_json('key',host,path)
            opener.assert_not_called()
            response=opener.return_value.open.return_value.__enter__.return_value
            response.read.return_value=b' ' * 2000001
            with self.assertRaises(UnifiCloudError): integration_json('key','host','/v1/sites')

    def test_timeout_and_ambiguous_local_site_do_not_read_rules(self):
        connection = Mock(encrypted_api_key='ciphertext', remote_host_id='host'); api=reader()
        with patch('core.unifi_zone_scope.decrypt_api_key', return_value='key'), patch(
            'core.unifi_zone_scope.time.monotonic', side_effect=[0,91]):
            self.assertEqual(collect(connection, api=api)['status'], 'unavailable')
            api.assert_not_called()
        data={'offset':0,'limit':100,'count':2,'totalCount':2,'data':[
            {'id':uid(9),'internalReference':'default'}, {'id':uid(10),'internalReference':'default'}]}
        api=Mock(return_value=data)
        with patch('core.unifi_zone_scope.decrypt_api_key',return_value='key'):
            self.assertEqual(collect(connection,api=api)['status'],'unavailable')
            self.assertEqual(api.call_count,1)

    def test_adapter_uses_fixed_official_host_get_and_offset_only(self):
        with patch('core.unifi_zone_scope.request.build_opener') as opener:
            response=opener.return_value.open.return_value.__enter__.return_value
            response.read.return_value=b'{"data":[]}'
            integration_json('key','host:123','/v1/sites/'+uid(9)+'/firewall/policies',100,100)
            req=opener.return_value.open.call_args.args[0]
            self.assertEqual(req.get_method(),'GET'); self.assertIsNone(req.data)
            self.assertEqual(req.full_url,'https://api.ui.com/v1/connector/consoles/host%3A123/proxy/network/integration/v1/sites/'+uid(9)+'/firewall/policies?offset=100&limit=100')


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class UniFiZonePageTests(TestCase):
    def setUp(self):
        self.company=Client.objects.create(name='Visible',code='zones-visible')
        self.device=Device.objects.create(site=Site.objects.create(client=self.company,name='Sede',code='zones-site'),
            name='UDM',vendor='unifi',management_method='api')
        self.now=timezone.now()
        values=fixtures([policy(name='<script>unsafe</script>')])
        scope={'schema':1,'status':'checked','checked_at':self.now.isoformat(),
            'last_success_at':self.now.isoformat(),'catalogue':project(*values)}
        self.check=ExposureCheck.objects.create(device=self.device,checked_at=self.now,coverage={'zones':scope})
        self.user=get_user_model().objects.create_user('zones-operator')
        self.user.groups.add(Group.objects.get(name='SOC Operador'))
        access=StaffAccess.objects.create(user=self.user,role='operator');access.clients.add(self.company)
        self.client.force_login(self.user)
        self.url=reverse('unifi_policies',args=[self.device.pk])

    def test_matrix_catalogue_names_escaped_and_pair_filter_validated(self):
        response=self.client.get(self.url)
        self.assertContains(response,'Tráfico entre zonas')
        self.assertContains(response,'&lt;script&gt;unsafe&lt;/script&gt;')
        self.assertNotContains(response,'<script>unsafe</script>')
        self.assertContains(response,'Oficina')
        self.assertEqual(self.client.get(self.url,{'source':uid(8)}).status_code,404)
        self.assertEqual(self.client.get(self.url,{'source':uid(1),'destination':uid(2)}).status_code,200)
        self.assertEqual(self.client.post(self.url,{}).status_code,405)

    def test_scoped_foreign_device_and_customer_denied(self):
        company=Client.objects.create(name='Hidden',code='zones-hidden')
        other=Device.objects.create(site=Site.objects.create(client=company,name='Private',code='zones-private'),name='Private',vendor='unifi')
        self.assertEqual(self.client.get(reverse('unifi_policies',args=[other.pk])).status_code,404)
        access=self.user.soc_access;access.role='customer';access.save()
        self.assertEqual(self.client.get(self.url).status_code,403)

    def test_history_is_escaped_and_reading_page_preserves_observations(self):
        import copy
        scope=self.check.coverage['zones']
        scope['history']=[{'at':self.now.isoformat(),'since':self.now.isoformat(), 'baseline':False,
            'after_gap':True,'counts':{'added':1,'removed':0,'modified':0,'zones':0,'objects':0,
                'unidentified_added':1,'unidentified_removed':1}, 'omitted':2,
            'details':[{'name':'<script>history</script>', 'detail':'Changed'}]}]
        self.check.save();self.check.refresh_from_db();before=copy.deepcopy(self.check.coverage)
        response=self.client.get(self.url)
        self.assertContains(response,'&lt;script&gt;history&lt;/script&gt;')
        self.assertNotContains(response,'<script>history</script>')
        self.assertContains(response,'Hubo una consulta no disponible')
        self.assertContains(response,'Pueden ser modificaciones de las mismas entradas')
        self.check.refresh_from_db();self.assertEqual(self.check.coverage,before)

    def test_reader_cannot_queue_review_and_missing_data_not_zero_policies(self):
        self.user.groups.clear();self.user.groups.add(Group.objects.get(name='SOC Consulta'))
        access=self.user.soc_access;access.role='reader';access.save()
        self.assertEqual(self.client.post(reverse('exposure_recheck',args=[self.device.pk])).status_code,403)
        self.check.coverage={};self.check.save()
        response=self.client.get(self.url)
        self.assertContains(response,'Preparar la primera lectura')
        self.assertNotContains(response,'0 entradas')

    def test_failure_stale_future_and_paused_keep_catalogue_as_history(self):
        self.device.exposure_check=self.check
        self.assertTrue(snapshot(self.device,self.now)['current'])
        for stamp in (self.now-timedelta(hours=13),self.now+timedelta(seconds=1)):
            self.check.coverage['zones']['checked_at']=stamp.isoformat()
            self.assertFalse(snapshot(self.device,self.now)['current'])
        self.check.coverage['zones']['checked_at']=self.now.isoformat()
        self.check.coverage['zones']['status']='unavailable';self.check.save()
        response=self.client.get(self.url)
        self.assertContains(response,'última referencia conservada')
        self.assertContains(response,'Usuarios')
        self.check.coverage['zones']['status']='checked'
        self.device.integration='paused'
        self.assertFalse(snapshot(self.device,self.now)['current'])

    def test_zone_read_failure_keeps_complete_classic_lists_partial(self):
        from .exposure import save_result
        save_result(self.device,{'filter':[],'nat':[]},{'filter':{'status':'checked'},
            'nat':{'status':'checked'},'zones':{'status':'unavailable'}},'Read failed')
        self.check.refresh_from_db()
        self.assertEqual(self.check.status,'partial')
        self.assertIsNone(self.check.last_success_at)

    def test_missing_connector_preserves_last_catalogue_and_history(self):
        from .exposure import collect
        scope=self.check.coverage['zones']
        scope['history']=[{'at':self.now.isoformat(),'since':None,'baseline':True,
            'counts':{},'details':[],'omitted':0}]
        self.check.save();self.check.refresh_from_db()
        self.device.exposure_check=self.check
        with patch('core.unifi_zone_scope.integration_json') as network:
            _,coverage,_=collect(self.device)
        network.assert_not_called()
        self.assertEqual(coverage['zones']['status'],'unavailable')
        self.assertEqual(coverage['zones']['catalogue'],self.check.coverage['zones']['catalogue'])
        self.assertEqual(coverage['zones']['history'],scope['history'])

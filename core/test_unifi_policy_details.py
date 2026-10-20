import copy
from datetime import timedelta
from unittest.mock import Mock, patch
from django.test import SimpleTestCase
from django.utils import timezone
from .test_unifi_zone_scope import uid, fixtures, policy, reader
from .unifi_zone_scope import project, collect
from .unifi_policy_details import ports, protocol
from .unifi_policy_history import track, changes, presentation


class PolicyDetailTests(SimpleTestCase):
    def test_source_destination_port_filters_keep_roles_and_exclusions(self):
        def spec(inverse=False):return {'type':'PORTS','matchOpposite':inverse,
            'items':[{'type':'PORT_NUMBER','value':443},{'type':'PORT_NUMBER','value':80}]}
        row=policy(source={'zoneId':uid(1),'trafficFilter':{'type':'PORT','portFilter':spec()}},
            destination={'zoneId':uid(2),'trafficFilter':{'type':'NETWORK',
                'networkFilter':{'networkIds':[uid(4)],'matchOpposite':False},'portFilter':spec(True)}})
        parsed=project(*fixtures([row]))['pairs'][0]['policies'][0]
        self.assertIn('Origen · puertos: 80, 443',parsed['criteria'])
        self.assertIn('Destino · puertos: excepto 80, 443',parsed['criteria'])
        self.assertFalse(parsed['criteria_pending'])

    def test_port_object_requires_correct_type_and_never_displays_contents(self):
        values=fixtures();values[3][0]['type']='PORTS';values[3][0]['items']=[{'type':'PORT_NUMBER','value':8888}]
        row=policy(destination={'zoneId':uid(2),'trafficFilter':{'type':'PORT','portFilter':{
            'type':'TRAFFIC_MATCHING_LIST','matchOpposite':False,'trafficMatchingListId':uid(5)}}})
        values[1]=[row];result=project(*values)
        self.assertIn('Objeto permitido (1 entradas)',result['pairs'][0]['policies'][0]['criteria'][0])
        self.assertNotIn('8888',str(result));self.assertNotIn('items',result['objects'][0])
        values[3][0]['type']='IPV4_ADDRESSES'
        self.assertTrue(project(*values)['pairs'][0]['policies'][0]['criteria_pending'])

    def test_invalid_ports_and_unknown_ranges_fail_or_remain_pending(self):
        for value in (True,0,65536,'443'):
            with self.assertRaises(ValueError):ports({'type':'PORTS','matchOpposite':False,
                'items':[{'type':'PORT_NUMBER','value':value}]},{})
        with self.assertRaises(ValueError):ports({'type':'PORTS','matchOpposite':False,'items':[]},{})
        summary,pending=ports({'type':'PORTS','matchOpposite':False,
            'items':[{'type':'PORT_RANGE','PRIVATE':'secret'}]},{})
        self.assertTrue(pending);self.assertNotIn('secret',summary)
        with self.assertRaises(ValueError):ports({'type':'PORTS','matchOpposite':False,
            'items':[{'type':'PORT_NUMBER','value':443}]*2},{})

    def test_protocols_named_preset_opposite_and_unknown_criteria(self):
        self.assertEqual(protocol({'ipVersion':'IPV4'}),('Todos los protocolos en el ámbito IP declarado',False))
        self.assertEqual(protocol({'ipVersion':'IPV4','protocolFilter':{'type':'NAMED_PROTOCOL',
            'protocol':{'name':'TCP'},'matchOpposite':True}}),('Todos excepto TCP',False))
        self.assertEqual(protocol({'ipVersion':'IPV4_AND_IPV6','protocolFilter':{
            'type':'PRESET','preset':{'name':'TCP_UDP'}}}),('TCP y UDP',False))
        for spec in ({'type':'UNKNOWN','secret':'PRIVATE'}, {'type':'NAMED_PROTOCOL',
            'protocol':{'name':'TCP','extra':'PRIVATE'},'matchOpposite':False}):
            summary,pending=protocol({'ipVersion':'IPV4','protocolFilter':spec})
            self.assertTrue(pending);self.assertNotIn('PRIVATE',summary)


class PolicyHistoryTests(SimpleTestCase):
    def scope(self,values=None,days=0):
        at=timezone.now()+timedelta(days=days)
        return {'status':'checked','last_success_at':at.isoformat(), 'catalogue':project(*(values or fixtures()))}

    def test_first_read_baseline_unchanged_does_not_repeat(self):
        first=track(None,self.scope())
        self.assertTrue(first['history'][0]['baseline'])
        second=track(first,self.scope(days=1));self.assertEqual(second['history'],first['history'])

    def test_added_removed_and_changed_known_id_with_human_reasons(self):
        a=fixtures([policy(1),policy(2)]);b=fixtures([policy(1,enabled=False,index=9,loggingEnabled=True),policy(3)])
        counts,details,omitted,changed=changes(project(*a),project(*b))
        self.assertTrue(changed);self.assertEqual((counts['added'],counts['removed'],counts['modified']),(1,1,1))
        self.assertEqual(omitted,0)
        detail=next(r['detail'] for r in details if r['name']=='Política 1')
        for text in ('desactivada','índice: 1 → 9','syslog habilitado'):self.assertIn(text,detail)

    def test_unknown_ids_count_observations_without_false_identity(self):
        a=project(*fixtures([policy(id=None)]));b=project(*fixtures([policy(id=None,enabled=False)]))
        counts,details,_,changed=changes(a,b)
        self.assertTrue(changed);self.assertEqual((counts['unidentified_added'],counts['unidentified_removed']),(1,1))
        self.assertEqual((counts['added'],counts['removed'],counts['modified']),(0,0,0));self.assertEqual(details,[])

    def test_zone_members_and_object_contents_changes_detected(self):
        a=fixtures();b=copy.deepcopy(a);b[0][0]['name']='Nueva zona';b[3][0]['items'][0]['value']='PRIVATE-CHANGED'
        counts,details,_,_=changes(project(*a),project(*b))
        self.assertEqual((counts['zones'],counts['objects']),(1,1));self.assertNotIn('PRIVATE',str(details))

    def test_presentation_only_change_does_not_create_configuration_event(self):
        before=self.scope();after=copy.deepcopy(before);after['last_success_at']=(timezone.now()+timedelta(days=1)).isoformat()
        after['catalogue']['pairs'][0]['policies'][0]['criteria'].append('New formatter only')
        after['catalogue']['objects']=[]
        self.assertFalse(changes(before['catalogue'],after['catalogue'])[3])
        self.assertEqual(track(before,after)['history'],[])

    def test_failed_read_preserves_history_and_recovery_marks_gap(self):
        first=track(None,self.scope())
        failed=track(first,{'status':'unavailable','catalogue':first['catalogue'],'last_success_at':first['last_success_at']})
        self.assertEqual(failed['history'],first['history'])
        values=fixtures([policy(enabled=False)])
        result=track(failed,self.scope(values,days=1))
        self.assertEqual(len(result['history']),2);self.assertTrue(result['history'][-1]['after_gap'])
        self.assertEqual(result['history'][-1]['since'],first['last_success_at'])

    def test_details_and_history_bounded_with_full_counts(self):
        a=project(*fixtures([]));b=project(*fixtures([policy(i) for i in range(80)]))
        counts,details,omitted,_=changes(a,b)
        self.assertEqual((counts['added'],len(details),omitted),(80,40,40))
        current=track(None,self.scope())
        for i in range(1,24):
            current=track(current,self.scope(fixtures([policy(enabled=bool(i%2))]),days=i))
        self.assertEqual(len(current['history']),20)
        self.assertIsNotNone(presentation(current)[0]['at'])

    def test_collect_integrates_history_and_failure_keeps_it_without_secrets(self):
        c=Mock(encrypted_api_key='encrypted',remote_host_id='host')
        with patch('core.unifi_zone_scope.decrypt_api_key',return_value='key'):
            before=collect(c,api=reader())
            after=collect(c,previous=before,now=timezone.now()+timedelta(days=1),api=reader(fixtures([policy(enabled=False)])))
            failed=collect(c,previous=after,api=Mock(side_effect=ValueError('PRIVATE')))
        self.assertEqual(len(after['history']),2)
        self.assertEqual(failed['history'],after['history']);self.assertNotIn('PRIVATE',str(failed))

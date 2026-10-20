"""Cross-channel regression cases; all addresses and identities are lab data."""
import copy
import re
from datetime import timedelta
from unittest.mock import patch
from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone
from .event_contract import ACTION_VALUES, action_filter, security_filter, recommendation
from .operations import normalize, ingest_events
from .models import Client, Site, Device, ExportConfiguration, Asset, SecurityEvidence, UrgentAlert
from .findings import build_findings, inventories_for_sources, _asset
from .test_hillstone_flow import MESSAGE


def field(doc, path):
    value=doc
    for part in path.split('.'):
        value=value.get(part) if isinstance(value,dict) else None
    return value


def matches(doc, query):
    """Small keyword-query evaluator; live OpenSearch also validates this DSL."""
    if 'bool' in query:
        b=query['bool']
        return (all(matches(doc,c) for c in b.get('filter',[])) and
                all(not matches(doc,c) for c in b.get('must_not',[])) and
                sum(matches(doc,c) for c in b.get('should',[]))>=b.get('minimum_should_match',0))
    kind,body=next(iter(query.items()))
    if kind=='script':
        value=field(doc,'data.hillstone.message')
        return isinstance(value,str) and len(value.encode('utf-16-le'))//2<=body['script']['params']['limit']
    if kind=='exists':return field(doc,body['field']) is not None
    path,expected=next(iter(body.items()));actual=field(doc,path)
    values=actual if isinstance(actual,list) else [actual]
    if kind=='term':return any(str(v)==str(expected) for v in values)
    if kind=='terms':return any(str(v) in map(str,expected) for v in values)
    if kind=='prefix':return any(str(v).startswith(expected) for v in values if v is not None)
    if kind=='regexp':
        pattern=expected.get('value') if isinstance(expected,dict) else expected
        flags=re.I if isinstance(expected,dict) and expected.get('case_insensitive') else 0
        return any(re.fullmatch(pattern,str(v),flags) for v in values if v is not None)
    raise AssertionError(kind)


def sample(engine, action='blocked'):
    result={'id':'lab-event','timestamp':timezone.now().isoformat(),'location':'192.0.2.70',
            'rule':{'id':'100','level':8},'decoder':{'name':engine},'data':{}}
    if engine=='unifi':result['data']={'srcip':'203.0.113.9','dstip':'10.0.0.20','dstport':'443','unifi':{'category':'Security','action':action,'ips_signature':'ET SCAN Lab','risk':'high'}}
    elif engine=='suricata':result['data']={'src_ip':'203.0.113.9','dest_ip':'10.0.0.20','dest_port':443,'event_type':'alert','alert':{'action':action,'signature':'ET SCAN Lab','category':'Attempted Information Leak','severity':2}}
    elif engine=='zenarmor':
        result['rule']['groups']=['zenarmor','zenarmor_security']
        result['data']={'ip_src_saddr':'10.0.0.20','ip_dst_saddr':'203.0.113.9','ip_dst_port':443,'security_tags':['Malware'],'is_blocked':action}
    elif engine=='hillstone':
        result['decoder']['name']='soc-hillstone'
        result['data']={'action':action,'srcip':'203.0.113.9','dstip':'10.0.0.20','dstport':'443','hillstone':{'category':'Threat','code':'IPS','message':'Lab scan signature'}}
    elif engine=='clamav':result['rule'].update(id='52502',description='ClamAV test detection')
    return result


class EventContractTests(SimpleTestCase):
    def test_live_index_regex_limit_and_invalid_legacy_endpoints(self):
        import json
        for action in ('allowed','blocked'):
            def walk(query):
                if isinstance(query,dict):
                    if 'regexp' in query:
                        for pattern in query['regexp'].values():self.assertLessEqual(len(pattern.get('value') if isinstance(pattern,dict) else pattern),1000)
                    for value in query.values():walk(value)
                elif isinstance(query,list):
                    for value in query:walk(value)
            walk(action_filter(action))
        for old,new in (('8.8.8.8','999.8.8.8'),('8082','99999')):
            source=sample('hillstone','blocked')
            source['data']['hillstone'].update(code='FLOW',message=MESSAGE.replace(old,new))
            self.assertEqual(normalize(source)['action'],'blocked')
            self.assertTrue(matches(source,action_filter('blocked')))
            self.assertFalse(matches(source,action_filter('allowed')))

    def test_observed_anonymized_layouts_share_the_same_contract(self):
        import json
        from pathlib import Path
        fixture=json.loads((Path(__file__).parent/'event_samples/v1.json').read_text())
        for sample in fixture['samples']:
            event=sample['event'];result=normalize(event)
            self.assertEqual(result['contract_version'],fixture['contract_version'])
            self.assertEqual(result['engine'],sample['engine'])
            self.assertTrue(matches(event,security_filter()))
            for action in ('allowed','blocked'):
                self.assertEqual(matches(event,action_filter(action)),result['action']==action)

    def test_every_alias_has_same_action_in_python_and_index_filters(self):
        for engine,actions in ACTION_VALUES.items():
            for wanted,values in actions.items():
                for value in values:
                    for spelling in (value,value.upper(),' '+value.title()+' '):
                        with self.subTest(engine=engine,value=spelling):
                            event=sample(engine,spelling)
                            self.assertEqual(normalize(event)['action'],wanted)
                            self.assertTrue(matches(event,action_filter(wanted)))
                            self.assertFalse(matches(event,action_filter('allowed' if wanted=='blocked' else 'blocked')))

    def test_unknown_action_is_neither_allowed_nor_blocked(self):
        for engine in ACTION_VALUES:
            source=sample(engine,'new-unknown-value')
            self.assertEqual(normalize(source)['action'],'unknown')
            self.assertFalse(matches(source,action_filter('allowed')))
            self.assertFalse(matches(source,action_filter('blocked')))

    def test_fields_from_other_engines_cannot_change_the_action(self):
        source=sample('suricata','drop');source['data']['is_blocked']='0'
        self.assertTrue(matches(source,action_filter('blocked')))
        self.assertFalse(matches(source,action_filter('allowed')))
        source=sample('clamav');source['data']={'is_blocked':'1','alert':{'action':'blocked'}}
        self.assertEqual(normalize(source)['action'],'unknown')
        self.assertFalse(matches(source,action_filter('blocked')))

    def test_legacy_hillstone_message_overrides_conflicting_decoded_action(self):
        source=sample('hillstone','blocked')
        source['data']['hillstone'].update(code='FLOW',message=MESSAGE)
        self.assertEqual(normalize(source)['action'],'allowed')
        self.assertTrue(matches(source,action_filter('allowed')))
        self.assertFalse(matches(source,action_filter('blocked')))
        source['data']['hillstone']['message']=MESSAGE.replace('Log-Only','Something-New')
        self.assertEqual(normalize(source)['action'],'unknown')
        self.assertFalse(matches(source,action_filter('blocked')))

    def test_security_selector_distinguishes_detection_and_system_activity(self):
        for engine in ('unifi','suricata','zenarmor','hillstone','clamav'):
            source=sample(engine,'1' if engine=='zenarmor' else 'blocked')
            self.assertEqual(matches(source,security_filter()),normalize(source)['security'])
        for source in ({'decoder':{'name':'clamav'},'rule':{'id':'52501'}},
                       {'decoder':{'name':'soc-hillstone'},'data':{'hillstone':{'category':'Event','code':'SECURITY'}}},
                       {'decoder':{'name':'zenarmor'},'data':{'security_tags':[],'is_blocked':'1'}}):
            self.assertFalse(matches(source,security_filter()))

    def test_severities_remain_distinct_and_scan_recommendations_are_not_malware(self):
        scan=normalize(sample('suricata','drop'));malware=normalize(sample('zenarmor','0'))
        self.assertEqual(scan['vendor_severity'],'2');self.assertEqual(scan['level'],8)
        self.assertEqual(scan['soc_priority'],'medium');self.assertEqual(malware['soc_priority'],'critical')
        self.assertIn('escaneo',recommendation(scan));self.assertNotIn('aislarlo',recommendation(scan))
        self.assertIn('antivirus',recommendation(malware))


@override_settings(SOC_MFA_REQUIRED=False,SECURE_SSL_REDIRECT=False)
class EventChannelTests(TestCase):
    def setUp(self):
        self.now=timezone.now()
        self.customer=Client.objects.create(name='Lab',code='contract-lab',urgent_alerts_enabled=True,report_email='lab@example.test')
        self.site=Site.objects.create(client=self.customer,name='Historical site',code='lab')
        self.device=Device.objects.create(site=self.site,name='Firewall',vendor='opnsense')
        ExportConfiguration.objects.create(device=self.device,source_ip='192.0.2.70',receiver_ready=True)
        from .testing_access import legacy_sources
        legacy_sources()

    def event(self,engine='suricata',action='allowed'):
        event=sample(engine,action);event['timestamp']=self.now.isoformat();return event

    def test_identity_and_severity_survive_asset_and_site_rename_in_report_mail_map(self):
        asset=Asset.objects.create(device=self.device,ip='10.0.0.20',name='Historical host',mac='02:00:00:00:00:01',identified_at=self.now-timedelta(minutes=1))
        source=self.event();ingest_events([source],self.now)
        evidence=SecurityEvidence.objects.get();self.assertEqual(evidence.interpretation['contract_version'],1)
        asset.name='Current replacement';asset.mac='02:00:00:00:00:02';asset.save()
        self.site.name='Current site';self.site.save()
        inventory=inventories_for_sources(self.customer,['192.0.2.70'],events=[source])
        findings,_=build_findings([{'_source':source}],inventory)
        self.assertEqual(findings[0]['asset_name'],'Historical host')
        self.assertEqual(findings[0]['site'],'Historical site')
        self.assertEqual(findings[0]['soc_priority'],evidence.interpretation['soc_priority'])
        from .urgent_alerts import _record_event,_message
        hit={'_source':source,'_index':'wazuh-alerts-lab','_id':'mail-lab'}
        with patch('core.urgent_alerts.inventories_for_sources',return_value=inventory):
            self.assertTrue(_record_event(hit,{'192.0.2.70':self.customer},{},self.now))
        alert=UrgentAlert.objects.get()
        self.assertEqual(alert.asset_name,'Historical host');self.assertEqual(alert.site_name,'Historical site')
        self.assertEqual(alert.interpretation['soc_priority'],evidence.interpretation['soc_priority'])
        self.assertIn('Nivel Wazuh: 8',_message(alert)[1]);self.assertIn('Severidad del fabricante: 2',_message(alert)[1])
        from .threat_map import map_data
        row=map_data(self.customer)['recent'][0]
        self.assertEqual(row['asset'],'Historical host');self.assertEqual(row['site'],'Historical site')
        self.assertEqual(row['soc_priority'],evidence.interpretation['soc_priority'])

    def test_different_signatures_categories_and_emitters_never_share_recommendation(self):
        scan=self.event('suricata','allowed');malware=self.event('zenarmor','0')
        other=copy.deepcopy(scan);other['data']['alert']['signature']='Different scan'
        source2=copy.deepcopy(scan);source2['location']='192.0.2.71'
        findings,_=build_findings([{'_source':s} for s in (scan,malware,other,source2)],{})
        self.assertEqual(len(findings),4)
        for finding in findings:
            first=finding['recommendations'][0]
            self.assertIn('antivirus' if finding['engine']=='zenarmor' else 'escaneo',first)

    def test_duplicate_physical_alert_keeps_its_original_snapshot(self):
        event=self.event();ingest_events([event],self.now)
        before=SecurityEvidence.objects.get().interpretation
        event['data']['alert']['action']='blocked'
        self.assertEqual(ingest_events([event],self.now),0)
        self.assertEqual(SecurityEvidence.objects.get().interpretation,before)

    def test_exact_identity_lookup_works_outside_recent_inventory_cache(self):
        Asset.objects.create(device=self.device,ip='10.0.0.20',name='Past',identified_at=self.now)
        event=self.event();ingest_events([event],self.now)
        inventory={'192.0.2.70':{'device_id':self.device.pk,'client_scope_id':self.customer.pk,'identities':{},'hosts':{'10.0.0.20':'WRONG'}}}
        self.assertEqual(_asset(event,inventory)['name'],'Past')

    def test_old_owner_retains_frozen_identity_after_device_transfer(self):
        Asset.objects.create(device=self.device,ip='10.0.0.20',name='Old tenant host',identified_at=self.now)
        event=self.event();ingest_events([event],self.now)
        other=Client.objects.create(name='Other',code='other-contract')
        newsite=Site.objects.create(client=other,name='Other site',code='other')
        self.device.site=newsite;self.device.save()
        old=inventories_for_sources(self.customer,['192.0.2.70'],events=[event])
        new=inventories_for_sources(other,['192.0.2.70'],events=[event])
        self.assertEqual(_asset(event,old)['name'],'Old tenant host')
        self.assertNotEqual(_asset(event,new)['name'],'Old tenant host')

    def test_unknown_historical_identity_never_borrows_current_name(self):
        event=self.event();ingest_events([event],self.now)
        asset=Asset.objects.get();asset.name='New host';asset.identified_at=self.now;asset.save()
        context=inventories_for_sources(self.customer,['192.0.2.70'],events=[event])
        affected=_asset(event,context)
        self.assertFalse(affected['confirmed']);self.assertNotIn('New host',affected['name'])

    def test_incident_does_not_attach_previous_tenants_unassigned_evidence(self):
        old=self.event(action='blocked');ingest_events([old],self.now)
        historical=SecurityEvidence.objects.get();self.assertIsNone(historical.incident_id)
        other=Client.objects.create(name='Next tenant',code='next-contract')
        self.device.site=Site.objects.create(client=other,name='Next site',code='next');self.device.save()
        new=self.event();new['id']='new-owner-event';new['timestamp']=timezone.now().isoformat()
        ingest_events([new])
        historical.refresh_from_db();self.assertIsNone(historical.incident_id)
        current=SecurityEvidence.objects.get(wazuh_id='new-owner-event')
        self.assertEqual(current.incident.client_id,other.pk)
        self.assertEqual(current.incident.evidence.count(),1)

    def test_urgent_fingerprint_keeps_different_signatures_separate(self):
        from .urgent_alerts import _record_event
        one=self.event();two=copy.deepcopy(one);two['data']['alert']['signature']='Other scan'
        with patch('core.urgent_alerts.inventories_for_sources',return_value={}):
            for index,event in enumerate((one,two)):
                _record_event({'_source':event,'_index':'lab','_id':str(index)},{'192.0.2.70':self.customer},{},self.now)
        self.assertEqual(len(set(UrgentAlert.objects.values_list('fingerprint',flat=True))),2)

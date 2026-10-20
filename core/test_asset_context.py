from datetime import timedelta
from unittest.mock import patch
from django.test import TestCase,override_settings
from django.utils import timezone
from django.urls import reverse
from django.contrib.auth import get_user_model
from .models import Client,Site,Device,AttributionCatalog,ExportConfiguration,SecurityEvidence,Asset,OpnsenseConnection
from .asset_context import configuration_projection, interface_projection, review, describe, refresh
from .operations import ingest_events
from .findings import inventories_for_sources,build_findings
from .testing_access import workflow_access
from .protection import zenarmor_export_entitlement

@override_settings(SOC_MFA_REQUIRED=False,SECURE_SSL_REDIRECT=False)
class AssetContextTests(TestCase):
    def setUp(self):
        self.company=Client.objects.create(name='Company',code='context')
        self.site=Site.objects.create(client=self.company,name='Site',code='context')
        self.device=Device.objects.create(site=self.site,name='Firewall',vendor='opnsense',management_method='api')
        OpnsenseConnection.objects.create(device=self.device,api_url='https://fw.example.test')
        ExportConfiguration.objects.create(device=self.device,source_ip='198.51.100.20',receiver_ready=True)
        self.now=timezone.now()
        self.interfaces={'wan':['198.51.100.20'],'lan':['192.168.10.1']}
    def xml(self,extra='',source='<any/>',destination='(self)',target='192.168.10.10',target_port='443',port='8443',protocol='tcp',aliases=''):
        return f'<opnsense><system><password>DO-NOT-PERSIST</password></system><nat><rule uuid="rule1"><interface>wan</interface><protocol>{protocol}</protocol><source>{source}</source><destination><address>{destination}</address><port>{port}</port></destination><target>{target}</target><local-port>{target_port}</local-port>{extra}</rule></nat><OPNsense><Firewall><Alias><aliases>{aliases}</aliases></Alias></Firewall></OPNsense></opnsense>'.encode()
    def catalog(self,blob=None):
        return AttributionCatalog.objects.create(device=self.device,status='checked',checked_at=self.now,last_success_at=self.now,data=configuration_projection(blob or self.xml(),self.interfaces))
    def match(self,row,**kwargs):
        args=dict(src='203.0.113.10',dst='198.51.100.20',dstport='8443',flow={'protocol':'TCP','source_port':50000},now=self.now)
        args.update(kwargs);return review(row,**args)
    def test_candidate_does_not_certify_asset_or_historical_translation(self):
        row=self.catalog();result=self.match(row)
        self.assertEqual(result['candidates'],[{'ip':'192.168.10.10','port':443,'rule_id':'rule1'}])
        self.assertTrue(result['firewall_address']);self.assertIn('no demuestra',describe(result))
        self.assertFalse(Asset.objects.exists());self.assertNotIn('DO-NOT-PERSIST',str(row.data))
    def test_wrong_address_source_port_and_protocol_do_not_match(self):
        row=self.catalog(self.xml(source='<address>203.0.113.0/24</address><port>50000</port>'))
        for args in ({'src':'192.0.2.1'},{'dst':'198.51.100.21'},{'dstport':'443'},{'flow':{'protocol':'UDP','source_port':50000}},{'flow':{'protocol':'TCP'}},{'flow':{}}):
            self.assertEqual(self.match(row,**args)['candidates'],[])
    def test_disabled_and_bypass_rules_never_offer_targets(self):
        for extra in ('<disabled/>','<disabled>1</disabled>','<nordr>1</nordr>','<interfacenot>1</interfacenot>','<tagged>tag</tagged>'):
            data=configuration_projection(self.xml(extra=extra),self.interfaces)
            self.assertEqual(data['rules'],[])
        self.assertEqual(len(configuration_projection(self.xml(extra='<disabled>0</disabled>'),self.interfaces)['rules']),1)
    def test_inverse_unknown_alias_pool_and_network_target_remain_unresolved(self):
        for args in ({'source':'<any/><not>1</not>'},{'destination':'DynamicAlias'},{'target':'192.168.1.0/24'},{'extra':'<poolopts>round-robin</poolopts>'},{'protocol':'gre'},{'target_port':'https'}):
            data=configuration_projection(self.xml(**args),self.interfaces)
            self.assertEqual(data['rules'],[]);self.assertEqual(data['unsupported_rules'],1)
    def test_static_aliases_and_ranges_but_no_invented_port_offset(self):
        alias='<alias><name>Server</name><enabled>1</enabled><type>host</type><content>192.168.10.10</content></alias>'
        row=self.catalog(self.xml(target='Server',port='8443-8450',aliases=alias))
        self.assertEqual(self.match(row)['candidates'][0]['port'],None)
        self.assertEqual(self.match(row,dstport='8451')['candidates'],[])
    def test_multiple_candidates_remain_multiple(self):
        blob=self.xml().replace(b'</nat>',self.xml(target='192.168.10.11').split(b'<nat>')[1].split(b'</nat>')[0]+b'</nat>')
        result=self.match(self.catalog(blob));self.assertEqual(len(result['candidates']),2)
        self.assertFalse(Asset.objects.exists())
    def test_stale_failed_or_future_catalog_never_maps_a_target(self):
        row=self.catalog()
        for status,stamp in [('checked',self.now-timedelta(hours=1)),('unavailable',self.now),('checked',self.now+timedelta(minutes=1))]:
            row.status=status;row.last_success_at=stamp
            result=self.match(row);self.assertEqual(result['candidates'],[]);self.assertEqual(result['status'],'historical')
    def test_failed_refresh_preserves_history_without_renewing_success(self):
        row=self.catalog();before=row.last_success_at
        with patch('core.asset_context.collect',side_effect=ValueError('DO-NOT-EXPOSE')):refresh(self.device,self.now+timedelta(minutes=1))
        row.refresh_from_db();self.assertEqual(row.last_success_at,before);self.assertEqual(row.status,'unavailable')
        self.assertNotIn('DO-NOT-EXPOSE',str(row.data))
    def test_catalog_change_during_read_is_rejected(self):
        from .asset_context import collect
        overview={'rows':[{'identifier':'wan','addr4':'198.51.100.20/24'}],'total':1}
        with patch('core.configuration_archives.fetch_configuration',side_effect=[self.xml(),self.xml(target='192.168.10.11')]),patch('core.provisioning._api_request',return_value=overview):
            with self.assertRaises(ValueError):collect(self.device)
    def test_ipv6_matches_only_same_family_targets(self):
        ips={'wan':['2001:db8::1']}
        row=self.catalog()
        row.data=configuration_projection(self.xml(destination='any',target='2001:db8:1::10'),ips)
        self.assertEqual(len(self.match(row,src='2001:db8:2::1',dst='2001:db8::1')['candidates']),1)
        self.assertEqual(self.match(row)['candidates'],[])
    def test_parser_rejects_missing_nat_unsafe_xml_and_incomplete_interfaces(self):
        for blob in (b'<opnsense/>',b'<!DOCTYPE opnsense><opnsense><nat/></opnsense>'):
            with self.assertRaises(ValueError):configuration_projection(blob,self.interfaces)
        with self.assertRaises(ValueError):interface_projection({'rows':[{'identifier':'wan','addr4':'198.51.100.20/24'}],'total':2})
        self.assertEqual(interface_projection({'rows':[{'identifier':'wan','addr4':'198.51.100.20/24'}],'total':'1'}),{'wan':['198.51.100.20']})
        self.assertEqual(interface_projection({'rows':[{'identifier':'','ipv4':[]},{'identifier':'wan','addr4':'198.51.100.20/24'}],'total':2}),{'wan':['198.51.100.20']})
    def event(self):
        return {'id':'actual-id','location':'198.51.100.20','timestamp':self.now.isoformat(),'rule':{'id':'86601','level':3},'decoder':{'name':'json'},'data':{'event_type':'alert','proto':'TCP','src_ip':'203.0.113.10','src_port':50000,'dest_ip':'198.51.100.20','dest_port':8443,'alert':{'action':'allowed','signature':'Offline signature'}}}
    def test_ingestion_keeps_original_identity_and_deduplicates_with_flow(self):
        self.catalog();event=self.event();ingest_events([event,event],self.now)
        evidence=SecurityEvidence.objects.get()
        self.assertEqual(evidence.flow,{'protocol':'TCP','source_port':50000});self.assertIsNone(evidence.asset_id)
        self.assertEqual(evidence.action_label,'Permitida');self.assertIn('Destino observado',evidence.identified_label)
        self.assertEqual(SecurityEvidence.objects.count(),1)
    def test_report_keeps_public_destination_and_marks_candidate_as_unconfirmed(self):
        self.catalog();event=self.event();ingest_events([event],self.now)
        inventories=inventories_for_sources(self.company,['198.51.100.20'])
        findings,_=build_findings([{'_source':event}],inventories)
        finding=findings[0]
        self.assertEqual(finding['asset_ip'],'198.51.100.20');self.assertFalse(finding['asset_confirmed'])
        self.assertIn('192.168.10.10',finding['context_note']);self.assertIn('Confirmar regla efectiva',finding['recommendations'][0])
        self.assertEqual(inventories_for_sources(Client.objects.create(name='Other',code='other'),['198.51.100.20']),{})
    def test_incident_view_renders_readable_action_and_own_context(self):
        self.catalog();ingest_events([self.event()],self.now)
        user=get_user_model().objects.create_user(username='reader');workflow_access(user,reader=False);self.client.force_login(user)
        evidence=SecurityEvidence.objects.get()
        response=self.client.get(reverse('incident_detail',args=[evidence.incident_id]))
        self.assertContains(response,'Posibles destinos');self.assertContains(response,'Permitida');self.assertContains(response,'192.168.10.10')
    def test_entitlement_is_readonly_and_unknown_does_not_mean_licensed(self):
        paths=[]
        def api(c,p):paths.append(p);return {'success':True,'license':'free','secret':'DO-NOT-PERSIST'}
        result=zenarmor_export_entitlement(None,api)
        self.assertFalse(result['eligible']);self.assertNotIn('DO-NOT-PERSIST',str(result))
        self.assertEqual(paths,['/api/zenarmor/configuration/license_detail'])
        self.assertIsNone(zenarmor_export_entitlement(None,lambda *a:{'success':True,'license':None})['eligible'])
        self.assertTrue(zenarmor_export_entitlement(None,lambda *a:{'success':True,'license':'SOHO'})['eligible'])

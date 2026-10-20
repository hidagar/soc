from datetime import timedelta
from xml.etree import ElementTree as ET
from django.test import SimpleTestCase
from django.utils import timezone
from .unifi_policy_details import addresses
from .unifi_zone_scope import project
from .unifi_flow import matches,evaluate
from .test_unifi_zone_scope import fixtures,policy,uid
from .asset_context import configuration_projection
from .zenarmor_bypass import project as bypass
from .vpn import transfer_sample


class AdvancedExpansionTests(SimpleTestCase):
    def spec(self,value='192.0.2.0/24',inverse=False):
        return {'type':'IP_ADDRESSES','matchOpposite':inverse,'items':[{'type':'SUBNET','value':value}]}
    def projected(self,spec):
        return project(*fixtures([policy(destination={'zoneId':uid(2),'trafficFilter':{'type':'IP_ADDRESS','ipAddressFilter':spec}})]))['pairs'][0]['policies'][0]
    def flow(self,**kw):
        return {**{'ip':'IPV4','protocol':'TCP','state':'NEW','destination_ip':'192.0.2.3','destination_port':443},**kw}
    def test_literal_address_criteria_and_missing_input(self):
        p=self.projected(self.spec())
        self.assertFalse(p['criteria_pending'])
        self.assertTrue(matches(p,self.flow()))
        self.assertFalse(matches(p,self.flow(destination_ip='198.51.100.3')))
        self.assertIsNone(matches(p,self.flow(destination_ip='')))
        self.assertIsNone(matches(p,self.flow(destination_ip='2001:db8::1')))
        self.assertNotIn('192.0.2',str(p['criteria']))
    def test_inverse_ipv6_and_unknown_fields(self):
        p=self.projected(self.spec('2001:db8::/32',True))
        self.assertFalse(matches(p,self.flow(ip='IPV6',destination_ip='2001:db8::1')))
        self.assertTrue(matches(p,self.flow(ip='IPV6',destination_ip='2001:db9::1')))
        p=self.projected({**self.spec(),'future':'private'})
        self.assertIsNone(matches(p,self.flow()))
        pair={'order_unambiguous':True,'policies':[p,self.projected(self.spec())]}
        self.assertEqual(evaluate(pair,self.flow(),True)['status'],'unknown')
    def test_invalid_unknown_and_duplicate_addresses(self):
        for value in ('host.example','192.0.2.3','192.0.2.0/99'):
            with self.assertRaises(ValueError):addresses(self.spec(value))
        with self.assertRaises(ValueError):addresses({**self.spec(),'items':self.spec()['items']*2})
        self.assertIsNone(addresses({**self.spec(),'items':[{'type':'RANGE','value':'private'}]}))
        self.assertIsNone(addresses({'type':'TRAFFIC_MATCHING_LIST'}))
    def test_only_explicit_empty_nat_selector_is_any(self):
        def parse(source):
            xml=('<opnsense><nat><rule><interface>wan</interface><protocol>tcp</protocol>'
                '<source>'+source+'</source><destination><network>wanip</network><port>443</port></destination>'
                '<target>192.168.1.2</target><local-port>443</local-port></rule></nat>'
                '<OPNsense><Firewall><Alias><aliases/></Alias></Firewall></OPNsense></opnsense>')
            return configuration_projection(xml.encode(),{'wan':['198.51.100.1']})
        self.assertEqual(parse('<network/><port/><not>0</not>')['rules'][0]['source'],['any'])
        for source in ('','<network/><not>1</not>','<network/><unknown>private</unknown>'):
            self.assertEqual(parse(source)['unsupported_rules'],1)
    def test_bypass_is_partial_and_sso_does_not_imply_packet_exemption(self):
        xml=ET.fromstring('<opnsense><OPNsense><Zenarmor><general><hwbypass>false</hwbypass><license>SECRET</license></general><bypass><enable>true</enable></bypass><sso><exemptVlanIds>42</exemptVlanIds></sso></Zenarmor></OPNsense></opnsense>')
        result=bypass(xml)
        self.assertTrue(result['configured_bypass']);self.assertFalse(result['hardware_bypass'])
        self.assertEqual(result['global_exemptions'],'unavailable');self.assertEqual(result['status'],'partial')
        self.assertNotIn('SECRET',str(result));self.assertNotIn('42',str({k:v for k,v in result.items() if k!='fingerprint'}))
        xml.find('OPNsense/Zenarmor/bypass/enable').text='unexpected'
        self.assertIsNone(bypass(xml)['configured_bypass'])
    def test_deltas_require_two_fresh_samples_and_counter_reset_retires_proof(self):
        now=timezone.now();old={'received_bytes':100,'sent_bytes':20,'sampled_at':(now-timedelta(seconds=60)).isoformat(),'log_at':now.isoformat(),'log_device_id':3}
        result=transfer_sample(old,130,30,now)
        self.assertEqual((result['received_delta'],result['sent_delta']),(30,10))
        reset=transfer_sample(old,1,2,now)
        self.assertNotIn('log_at',reset);self.assertNotIn('log_device_id',reset);self.assertIsNone(reset['received_delta'])
        for previous in ({},{**old,'sampled_at':(now-timedelta(hours=1)).isoformat()},{**old,'received_bytes':True}):
            self.assertIsNone(transfer_sample(previous,130,30,now)['received_delta'])

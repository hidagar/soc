from unittest.mock import patch
from django.test import TestCase,override_settings
from django.utils import timezone
from .models import Client,Site,Device,ExportConfiguration,SecurityEvidence,DeviceFeed
from .operations import normalize,ingest_events
from .hillstone_events import flow,legacy_action_regexp
from .asset_context import flow_projection
from .evidence_repair import repair_hillstone
from .urgent_alerts import _event_kind

MESSAGE=('FROM 8.8.8.8:61009(ethernet0/0) to 10.20.0.8:8082(-), threat name:IP-Reputation, '
 'threat type:Attack, threat subtype:Risk IP, App/Protocol:, action:Log-Only, defender:PTF, '
 'severity:High, reason:hit ip-reputation category Bot, hit-count:1(in the last 60 seconds) ')


@override_settings(SOC_MFA_REQUIRED=False,SECURE_SSL_REDIRECT=False)
class HillstoneFlowTests(TestCase):
    def setUp(self):
        self.customer=Client.objects.create(name='Offline lab',code='flow-lab')
        self.device=Device.objects.create(name='Firewall',vendor='hillstone',site=Site.objects.create(client=self.customer,name='Lab',code='lab'))
        ExportConfiguration.objects.create(device=self.device,source_ip='198.51.100.45',receiver_ready=True)

    def event(self,message=MESSAGE,category='Threat'):
        return {'id':'stable-wazuh-id','timestamp':timezone.now().isoformat(),'location':'198.51.100.45',
            'decoder':{'name':'soc-hillstone'},'rule':{'id':'110602','level':8},
            'data':{'hillstone':{'category':category,'code':'FLOW','message':message}}}

    def test_actual_layout_log_only_becomes_unblocked_and_keeps_vendor_severity(self):
        source=self.event();result=normalize(source)
        self.assertEqual(result['action'],'allowed');self.assertTrue(result['security'])
        self.assertEqual(result['signature'],'IP-Reputation (Bot)')
        self.assertEqual((result['source_ip'],result['destination_ip'],result['destination_port']),('8.8.8.8','10.20.0.8','8082'))
        self.assertEqual(result['affected_ip'],'10.20.0.8')
        self.assertEqual(flow_projection(source)['hillstone']['severity'],'High')
        self.assertEqual(_event_kind(source,self.customer)[0],'security_allowed')

    def test_alarm_and_explicit_drop_are_distinct(self):
        self.assertEqual(normalize(self.event(MESSAGE.replace('Log-Only','ALARM')))['action'],'allowed')
        self.assertEqual(normalize(self.event(MESSAGE.replace('Log-Only','DROP')))['action'],'blocked')
        self.assertEqual(normalize(self.event(MESSAGE.replace('Log-Only','Something-New')))['action'],'unknown')

    def test_event_and_malformed_or_injected_labels_do_not_establish_allowed_traffic(self):
        self.assertFalse(normalize(self.event(category='Event'))['security'])
        invalid=MESSAGE.replace('action:Log-Only','action:Something-New')+' reason: action:Log-Only,'
        self.assertEqual(normalize(self.event(invalid))['action'],'unknown')
        self.assertIsNone(flow(self.event(MESSAGE.replace('8.8.8.8','999.8.8.8'))['data']))
        self.assertIsNone(flow(self.event(MESSAGE.replace('8082','99999'))['data']))

    def test_signature_does_not_change_with_ports_addresses_or_hit_counters(self):
        first=normalize(self.event())
        second=normalize(self.event(MESSAGE.replace('61009','40000').replace('8.8.8.8','1.1.1.1').replace('hit-count:1','hit-count:99')))
        self.assertEqual(first['signature'],second['signature'])

    def test_repair_is_idempotent_preserves_uid_and_does_not_reingest_or_inflate_feeds(self):
        source=self.event();old=normalize(source)
        old.update(action='unknown',category='FLOW',signature=MESSAGE[:240].strip(),source_ip=None,destination_ip=None,destination_port='',affected_ip=None)
        with patch('core.operations.normalize',return_value=old):ingest_events([source])
        evidence=SecurityEvidence.objects.get();uid=evidence.uid
        self.assertTrue(repair_hillstone(evidence,source))
        self.assertFalse(repair_hillstone(evidence,source))
        self.assertEqual(ingest_events([source]),0)
        self.assertEqual(SecurityEvidence.objects.count(),1)
        evidence.refresh_from_db();self.assertEqual(evidence.uid,uid)
        self.assertEqual(evidence.action,'allowed');self.assertIsNotNone(evidence.incident_id)
        self.assertEqual(DeviceFeed.objects.get().event_count,1)

    def test_repair_rejects_event_identity_or_client_mismatch(self):
        source=self.event();ingest_events([source]);evidence=SecurityEvidence.objects.get()
        other={**source,'id':'other'}
        with self.assertRaises(ValueError):repair_hillstone(evidence,other)
        customer=Client.objects.create(name='Other',code='other');self.device.site.client=customer;self.device.site.save()
        with self.assertRaises(ValueError):repair_hillstone(evidence,source)

    def test_report_legacy_pattern_requires_full_label_order(self):
        import re
        pattern=legacy_action_regexp('allowed')
        self.assertIsNotNone(re.fullmatch(pattern,MESSAGE))
        self.assertIsNone(re.fullmatch(pattern,MESSAGE.replace('Log-Only','DROP')))
        self.assertIsNone(re.fullmatch(pattern,MESSAGE.replace('Log-Only','UNKNOWN')+' action:Log-Only, defender:PTF, severity:High,'))

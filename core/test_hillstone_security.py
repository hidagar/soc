from datetime import timedelta
from unittest.mock import patch
from django.test import TestCase,override_settings
from django.utils import timezone
from .models import Client,Site,Device,ExportConfiguration,DeviceFeed,SecurityEvidence,DeviceHealth,ProtectionValidation,HillstoneConnection,WeeklyReport
from .operations import normalize,ingest_events,probe_device
from .protection import snapshot
from .operations_suite import ValidationForm,reconcile_validations
from .findings import build_findings
from .reporting import security_filter,coverage_for_week,report_context

@override_settings(SOC_MFA_REQUIRED=False,SECURE_SSL_REDIRECT=False)
class HillstoneSecurityTests(TestCase):
    def setUp(self):
        self.client_record=Client.objects.create(name='Hillstone test',code='hillstone-test')
        self.site=Site.objects.create(client=self.client_record,name='Office',code='office')
        self.device=Device.objects.create(site=self.site,name='FW',vendor='hillstone',management_method='api')
        ExportConfiguration.objects.create(device=self.device,source_ip='198.51.100.70',receiver_ready=True)
    def event(self,category='Threat',code='IPS',message='Offline test signature',**data):
        return {'id':'test-only','timestamp':timezone.now().isoformat(),'location':'198.51.100.70','decoder':{'name':'soc-hillstone'},'rule':{'id':'110602','level':8,'groups':['hillstone','hillstone_security'],'description':'Hillstone threat'},'data':{'hillstone':{'category':category,'code':code,'message':message},**data}}
    def test_administrative_security_and_updates_are_not_threats(self):
        for code,message in [('SECURITY','Start scan session, session will be deleted'),('SYS','AV updates signature successfully'),('AAA','authentication success')]:
            source=self.event('Event',code,message)
            self.assertFalse(normalize(source)['security'])
            ingest_events([source])
        self.assertFalse(SecurityEvidence.objects.exists())
        self.assertEqual(DeviceFeed.objects.get(device=self.device,kind='hillstone').security_at,None)
    def test_threat_unknown_action_does_not_infer_block_or_asset(self):
        result=normalize(self.event(message='malware blocked in message only'))
        self.assertTrue(result['security']);self.assertEqual(result['engine'],'hillstone')
        self.assertEqual(result['action'],'unknown');self.assertIsNone(result['affected_ip'])
    def test_explicit_action_addresses_and_deduplication(self):
        source=self.event(action='deny',srcip='203.0.113.10',dstip='192.168.1.23',dstport='443')
        ingest_events([source,source])
        e=SecurityEvidence.objects.get();self.assertEqual(e.action,'blocked');self.assertEqual(e.asset.ip,'192.168.1.23')
        self.assertEqual(DeviceFeed.objects.get(kind='hillstone').event_count,1)
    def test_findings_include_hillstone_with_unknown_action(self):
        source=self.event(message='Offline test signature')
        findings,_=build_findings([{'_source':source}],{})
        self.assertEqual(len(findings),1)
        self.assertIn('Offline test signature',findings[0]['signatures'])
        self.assertEqual(normalize(source)['action'],'unknown')
    def test_health_api_success_does_not_certify_ips(self):
        HillstoneConnection.objects.create(device=self.device,api_url='https://fw.test',username='soc',encrypted_password='cipher')
        with patch('core.hillstone_api.decrypt',return_value='secret'),patch('core.hillstone_api.check_connection',return_value={}):
            probe_device(self.device)
        self.device.refresh_from_db();health=DeviceHealth.objects.get(device=self.device)
        self.assertTrue(health.api_ok)
        self.assertIsNone(health.engines['Hillstone NGFW']['running'])
        result=snapshot(self.device)
        self.assertIn('hillstone-evidence',[g['code'] for g in result['gaps']])
        self.assertEqual(result['controls'][0]['state'],'unknown')
    def test_validation_requires_actual_threat_and_cannot_claim_block(self):
        form=ValidationForm({'engine':'hillstone','networks':'Authorized host','expected_signature':'Offline test signature'},device=self.device)
        self.assertTrue(form.is_valid(),form.errors)
        window=ProtectionValidation.objects.create(device=self.device,engine='hillstone',networks='Authorized host',expected_signature='Offline test signature',started_at=timezone.now()-timedelta(minutes=1),expires_at=timezone.now()+timedelta(minutes=10))
        ingest_events([self.event('Event','SECURITY','Offline test signature')]);self.assertEqual(reconcile_validations(),0)
        ingest_events([self.event()]);self.assertEqual(reconcile_validations(),1)
        window.refresh_from_db();self.assertEqual(window.evidence.action,'unknown')
    def test_report_selector_has_explicit_threat_category(self):
        self.assertIn('data.hillstone.category',str(security_filter()))
        self.assertEqual(coverage_for_week(self.client_record,timezone.localdate())['devices'][0]['expected'],['hillstone'])

    def test_report_summary_does_not_hide_unknown_actions(self):
        report=WeeklyReport.objects.create(client=self.client_record,week_start=timezone.localdate(),sources=['198.51.100.70'],security_count=1)
        context=report_context(report)
        self.assertEqual(context['summary_title'],'Detecciones con acción sin confirmar')
        self.assertIn('no permiten confirmar',context['summary_text'])
        report.availability_count=2
        self.assertEqual(report_context(report)['summary_title'],'Detecciones con acción sin confirmar')
        report.security_count=2;report.blocked_count=1
        self.assertIn('una detección con la acción sin confirmar',report_context(report)['summary_text'])

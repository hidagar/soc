from datetime import timedelta
from unittest.mock import patch,MagicMock
from django.test import TestCase,override_settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.urls import reverse
from django.utils import timezone
from .models import Client,Site,Device,DeviceHealth,DeviceFeed,ProtectionPolicy,StaffAccess,Incident
from .protection import snapshot,ids_mode,extra_opnsense,unifi_protection
from .operations import normalize
from .findings import build_findings

@override_settings(SECURE_SSL_REDIRECT=False,SOC_MFA_REQUIRED=False)
class ProtectionTests(TestCase):
    def setUp(self):
        self.now=timezone.now()
        self.c=Client.objects.create(name='Visible',code='visible');self.other=Client.objects.create(name='Oculto',code='hidden')
        self.s=Site.objects.create(client=self.c,name='Sede',code='sede');self.d=Device.objects.create(site=self.s,name='Firewall',vendor='opnsense',management_method='api')
        self.h=DeviceHealth.objects.create(device=self.d,api_ok=True,checked_at=self.now,protection_checked_at=self.now,last_log_at=self.now,
            engines={'Suricata':{'configured':True,'running':True,'mode':'ids','export':True},'Firmware':{'updates_available':False,'catalogue_checked_at':self.now.isoformat()}})
        DeviceFeed.objects.create(device=self.d,kind='system',last_seen_at=self.now,event_count=1)
        self.user=get_user_model().objects.create_user('operator');a=StaffAccess.objects.create(user=self.user,role='operator');a.clients.add(self.c)
        self.user.groups.add(Group.objects.get(name='SOC Operador'));self.client.force_login(self.user)
    def item(self):
        self.d=Device.objects.select_related('site__client','health','protection_policy').get(pk=self.d.pk)
        return snapshot(self.d,self.now)
    def codes(self):return [g['code'] for g in self.item()['gaps']]
    def test_modes_distinguish_ids_ips_and_unknown(self):
        self.assertEqual(ids_mode({'mode':{'pcap':{'selected':'1'},'netmap':{'selected':'0'}}}),'ids')
        self.assertEqual(ids_mode({'mode':'divert'}),'ips')
        self.assertEqual(ids_mode({'ips':'1'}),'ips')
        self.assertEqual(ids_mode({}),'unknown')
        self.assertEqual(ids_mode({'mode':{'pcap':{'selected':1},'netmap':{'selected':1}}}),'unknown')
    def test_required_ips_does_not_change_firewall_and_flags_ids(self):
        self.client.post(reverse('protection_device',args=[self.d.pk]),{'action':'policy','require_ips':'on','notes':'WAN y servidores'})
        self.assertTrue(ProtectionPolicy.objects.get(device=self.d).require_ips)
        self.assertIn('ips-mode',self.codes());self.assertEqual(self.item()['status'],'attention')
        self.assertNotIn('ips-mode',[g['code'] for g in snapshot(Device.objects.create(site=self.s,name='Manual',vendor='opnsense'))['gaps']])
    def test_first_security_proof_pending_is_not_a_stopped_engine(self):
        self.assertIn('suricata-evidence',self.codes());self.assertNotIn('Suricata-state',self.codes())
        self.assertEqual(self.item()['status'],'partial')
        DeviceFeed.objects.create(device=self.d,kind='suricata',last_seen_at=self.now-timedelta(days=5),security_at=self.now-timedelta(days=5),event_count=1)
        self.assertEqual(self.item()['status'],'observed')
        self.assertNotIn('silence',self.codes())
    def test_failed_or_stale_probe_does_not_confirm_preserved_engine(self):
        self.h.api_ok=False;self.h.save();item=self.item()
        self.assertFalse(item['current']);self.assertEqual(item['controls'][0]['state'],'unknown');self.assertIn('management',self.codes())
        self.h.api_ok=True;self.h.protection_checked_at=self.now-timedelta(hours=1);self.h.save()
        self.assertFalse(self.item()['current']);self.assertIn('Suricata-unknown',self.codes())
    def test_zenarmor_bypass_database_and_missing_export(self):
        self.d.zenarmor_enabled=True;self.d.save()
        self.h.engines.update({'Zenarmor':{'running':True,'bypass':True,'export':False},'Base de informes Zenarmor':{'running':False}});self.h.save()
        codes=self.codes();self.assertIn('Zenarmor-state',codes);self.assertIn('zenarmor-export',codes);self.assertIn('zenarmor-database',codes)
    def test_clamav_age_updater_and_missing_detection(self):
        self.h.engines['ClamAV']={'configured':True,'running':True,'signature_updates':False,'daily_built_at':(self.now-timedelta(days=4)).isoformat()};self.h.save()
        codes=self.codes();self.assertIn('clamav-updates',codes);self.assertIn('clamav-signatures',codes);self.assertIn('clamav-evidence',codes)
        self.assertNotIn('ClamAV-state',codes)
    def test_cached_firmware_none_is_unknown_not_up_to_date(self):
        engines={}
        def reply(c,p):
            if p.endswith('/status'):return {'status':'none'}
            return {}
        extra_opnsense(None,engines,reply)
        self.assertIsNone(engines['Firmware']['updates_available']);self.assertIsNone(engines['ClamAV']['configured'])
        self.h.engines['Firmware']=engines['Firmware'];self.h.save();self.assertIn('firmware-check',self.codes())
    def test_clamav_metadata_parses_daily_signature_build(self):
        engines={}
        def reply(c,p):
            if '/general/' in p:return {'general':{'enabled':'1','fc_enabled':'1'}}
            if p.endswith('/version'):return {'version':{'clamav':'1.5.4','daily':'version 28145, built on Tue Oct 6 08:26:12 2026','signatures':'3642833'}}
            return {'status':'running'}
        extra_opnsense(None,engines,reply)
        self.assertEqual(engines['ClamAV']['daily_built_at'],'2026-10-06T08:26:12+00:00');self.assertEqual(engines['ClamAV']['signatures'],3642833)
    def test_unifi_configuration_does_not_claim_engine_runtime(self):
        connector=MagicMock(return_value={'data':[{'key':'ips','ips_mode':'ips','utm_token':'DO-NOT-STORE'}]})
        engines=unifi_protection(self.d,'key',MagicMock(),connector)
        self.assertEqual(engines['UniFi IPS']['mode'],'ips');self.assertIsNone(engines['UniFi IPS']['running']);self.assertNotIn('DO-NOT-STORE',str(engines))
        connector.side_effect=ValueError();self.assertIsNone(unifi_protection(self.d,'key',MagicMock(),connector)['UniFi IPS']['configured'])
    def test_maintenance_and_pause_do_not_create_current_gaps(self):
        self.h.maintenance_until=self.now+timedelta(hours=1);self.h.save()
        self.assertEqual(self.item()['status'],'maintenance');self.assertFalse(self.codes())
        self.h.maintenance_until=None;self.h.save();self.d.integration='paused';self.d.save()
        self.assertEqual(self.item()['status'],'paused');self.assertFalse(self.codes())
    def test_incident_idempotency_stale_form_and_reopening(self):
        url=reverse('protection_device',args=[self.d.pk]);data={'action':'incident','code':'suricata-evidence','fingerprint':self.item()['fingerprint']}
        self.assertEqual(self.client.post(url,data).status_code,302);self.client.post(url,data)
        self.assertEqual(Incident.objects.count(),1);i=Incident.objects.get();self.assertEqual(i.client,self.c)
        i.status='resolved';i.resolved_at=self.now;i.save();self.client.post(url,data);i.refresh_from_db();self.assertEqual(i.status,'investigating')
        self.client.post(url,{**data,'fingerprint':'stale','code':'fake'});self.assertEqual(Incident.objects.count(),1)
    def test_reader_and_foreign_scope(self):
        s=Site.objects.create(client=self.other,name='Privada',code='privada');d=Device.objects.create(site=s,name='Secreto',vendor='opnsense')
        self.assertNotContains(self.client.get(reverse('protection_list')),'Secreto')
        self.assertEqual(self.client.get(reverse('protection_device',args=[d.pk])).status_code,404)
        self.assertEqual(self.client.post(reverse('protection_device',args=[d.pk]),{'action':'recheck'}).status_code,404)
        self.assertEqual(self.client.get(reverse('protection_list'),{'client':self.other.pk}).status_code,404)
        self.user.groups.clear();self.user.groups.add(Group.objects.get(name='SOC Consulta'));a=self.user.soc_access;a.role='reader';a.save()
        self.assertEqual(self.client.get(reverse('protection_device',args=[self.d.pk])).status_code,200)
        self.assertEqual(self.client.post(reverse('protection_device',args=[self.d.pk]),{'action':'recheck'}).status_code,403)
    def test_recheck_queues_without_connecting_from_web(self):
        with patch('core.provisioning._api_request') as api:
            self.client.post(reverse('protection_device',args=[self.d.pk]),{'action':'recheck'});api.assert_not_called()
        self.h.refresh_from_db();self.assertIsNone(self.h.checked_at);self.assertEqual(self.h.protection_checked_at,self.now)
    def test_clamav_detection_not_confused_with_errors_or_updates(self):
        for rule_id in ('52503','52504','52506','52508','52510'):
            event=normalize({'decoder':{'name':'clamd'},'rule':{'id':rule_id,'groups':['virus'],'level':10}})
            self.assertEqual(event['engine'],'clamav');self.assertFalse(event['security'])
        event=normalize({'decoder':{'name':'clamd'},'rule':{'id':'52502','level':8,'description':'ClamAV: Virus detected'}})
        self.assertTrue(event['security']);self.assertEqual(event['action'],'unknown');self.assertIsNone(event['affected_ip'])
        findings,_=build_findings([{'_source':{'decoder':{'name':'clamd'},'rule':{'id':'52502','level':8,'description':'ClamAV: Virus detected'},'timestamp':self.now.isoformat()}}],{})
        self.assertEqual(findings[0]['type'],'security');self.assertIn('archivo',str(findings[0]['recommendations']))

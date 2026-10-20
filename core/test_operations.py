import base64
import io
import json
import os
import sqlite3
import tarfile
import tempfile
import time
from pathlib import Path
from datetime import timedelta
from unittest.mock import patch,MagicMock
from cryptography.fernet import Fernet,InvalidToken
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.contrib.auth.hashers import make_password
from django.test import TestCase,override_settings
from django.urls import reverse
from django.utils import timezone
from .models import Client,Site,Device,ExportConfiguration,StaffAccess,MfaProfile,SecurityEvidence,Incident,Asset,DeviceHealth,DeviceFeed,FeedBucket,ChangePlan,AuditEvent,VpnPeer,WorkerState,OperationalIssue
from .security import totp,verify_token,encrypt,audit,audit_integrity
from .operations import normalize,ingest_events,evaluate_health,observe_asset

@override_settings(SECURE_SSL_REDIRECT=False,SOC_MFA_REQUIRED=False)
class OperationsTests(TestCase):
    def setUp(self):
        self.c1=Client.objects.create(name='Visible',code='visible')
        self.c2=Client.objects.create(name='Privado',code='private')
        self.s1=Site.objects.create(client=self.c1,name='Oficina',code='office')
        self.s2=Site.objects.create(client=self.c2,name='Otra oficina',code='other')
        self.d1=Device.objects.create(site=self.s1,name='FW visible',vendor='opnsense')
        self.d2=Device.objects.create(site=self.s2,name='FW privado',vendor='opnsense')
        ExportConfiguration.objects.create(device=self.d1,source_ip='8.8.8.8',receiver_ready=True)
        ExportConfiguration.objects.create(device=self.d2,source_ip='9.9.9.9',receiver_ready=True)
        from .testing_access import legacy_sources
        legacy_sources()
        self.user=get_user_model().objects.create_user('limited',password='Very-L0ng-test!975')
        access=StaffAccess.objects.create(user=self.user,role='operator')
        access.clients.add(self.c1)
        self.user.groups.add(Group.objects.get(name='SOC Operador'))
        self.client.force_login(self.user)
    def event(self,id='1',engine='zenarmor',location='8.8.8.8',action='blocked'):
        source={'id':id,'timestamp':timezone.now().isoformat(),'location':location,'rule':{'level':8,'description':'Malware','groups':['zenarmor_security']},'decoder':{'name':'zenarmor'}}
        if engine=='zenarmor': source['data']={'ip_src_saddr':'192.168.1.12','ip_dst_saddr':'1.1.1.1','ip_dst_port':'443','security_tags':['Malware'],'is_blocked':int(action=='blocked')}
        elif engine=='unifi': source.update(decoder={'name':'unifi'},data={'srcip':'8.8.4.4','dstip':'192.168.1.12','dstport':'443','unifi':{'category':'Security','ips_signature':'ET Malware','action':action}})
        else: source.update(decoder={'name':'suricata'},data={'event_type':'alert','src_ip':'8.8.4.4','dest_ip':'192.168.1.12','dest_port':443,'alert':{'signature':'ET Malware','category':'Malware','action':action}})
        return source
    def test_limited_operator_cannot_read_foreign_objects_or_write_forged_client(self):
        self.assertEqual(self.client.get(reverse('device_detail',args=[self.d2.pk])).status_code,404)
        self.assertEqual(self.client.get(reverse('health_device',args=[self.d2.pk])).status_code,404)
        page=self.client.get(reverse('health_list'))
        self.assertContains(page,self.d1.name); self.assertNotContains(page,self.d2.name)
        response=self.client.post(reverse('site_new')+'?client='+str(self.c2.pk),{'client':self.c2.pk,'name':'Forbidden'})
        self.assertEqual(response.status_code,404)
        self.assertFalse(Site.objects.filter(name='Forbidden').exists())
    def test_reader_blocked_and_unassigned_user_has_empty_scope(self):
        self.user.soc_access.role='reader'; self.user.soc_access.save()
        self.assertEqual(self.client.post(reverse('incident_new'),{}).status_code,403)
        self.user.soc_access.clients.clear()
        self.assertEqual(self.client.get(reverse('device_detail',args=[self.d1.pk])).status_code,404)
    def test_scoped_manager_cannot_read_global_audit_or_mail(self):
        self.user.soc_access.role='manager'; self.user.soc_access.save()
        self.user.groups.add(Group.objects.get(name='SOC Administrador'))
        for route in ('audit_log','mail_settings','staff','recovery'):
            self.assertEqual(self.client.get(reverse(route)).status_code,403)
    def test_three_engines_create_scoped_evidence_and_affected_assets(self):
        ingest_events([self.event('a','unifi'),self.event('b','zenarmor'),self.event('c','suricata')])
        self.assertEqual(set(SecurityEvidence.objects.values_list('engine',flat=True)),{'unifi','zenarmor','suricata'})
        self.assertEqual(Asset.objects.get(device=self.d1).ip,'192.168.1.12')
        self.assertEqual(SecurityEvidence.objects.filter(device=self.d2).count(),0)
    def test_duplicate_does_not_create_a_second_incident_occurrence(self):
        event=self.event()
        ingest_events([event,event])
        self.assertEqual(SecurityEvidence.objects.count(),1)
        self.assertEqual(Incident.objects.count(),1)
        self.assertEqual(Incident.objects.get().occurrence_count,1)
        self.assertEqual(DeviceFeed.objects.get(device=self.d1).event_count,1)
        ingest_events([self.event('new')])
        self.assertEqual(Incident.objects.get().occurrence_count,2)
    def test_reconciliation_resumes_pages_and_does_not_duplicate_local_receipts(self):
        from .operations import reconcile_security
        now=timezone.now(); first=self.event('a');second=self.event('b')
        first['timestamp']=(now-timedelta(minutes=5)).isoformat()
        second['timestamp']=(now-timedelta(minutes=3)).isoformat()
        ingest_events([first],now)
        def hit(event):return {'_source':event,'sort':[event['timestamp'],event['id'],'index']}
        responses=[{'hits':{'hits':[hit(first)]}},{'hits':{'hits':[hit(second)]}},{'hits':{'hits':[]}}]
        with patch('core.reporting.indexer_authorization',return_value='test'),patch('core.reporting._search',side_effect=responses) as search:
            self.assertEqual(reconcile_security(now,pages=1,page_size=1),0)
            state=WorkerState.objects.get(pk='security-reconciliation')
            self.assertEqual(state.details['after'],hit(first)['sort']);self.assertIsNone(state.last_success_at)
            self.assertEqual(reconcile_security(now,pages=2,page_size=1),1)
            self.assertEqual(search.call_args_list[1].args[0]['search_after'],hit(first)['sort'])
        state.refresh_from_db();self.assertIsNotNone(state.last_success_at)
        self.assertIn('completed_until',state.details)
        self.assertEqual(DeviceFeed.objects.get(device=self.d1).event_count,2)
        self.assertEqual(SecurityEvidence.objects.count(),2)
    def test_partial_indexer_response_does_not_advance_reconciliation_cursor(self):
        from .operations import reconcile_security
        with patch('core.reporting.indexer_authorization',return_value='test'),patch('core.reporting._search',return_value={'timed_out':True,'hits':{'hits':[]}}):
            reconcile_security()
        state=WorkerState.objects.get(pk='security-reconciliation')
        self.assertIsNone(state.last_success_at);self.assertEqual(state.details,{})
        self.assertTrue(OperationalIssue.objects.get(key='platform:reconciliation-error').active)
    def test_reconciliation_commits_evidence_and_cursor_together(self):
        from .operations import reconcile_security
        event=self.event();event['timestamp']=(timezone.now()-timedelta(minutes=5)).isoformat()
        response={'hits':{'hits':[{'_source':event,'sort':[event['timestamp'],event['id'],'index']}]}}
        original=WorkerState.save
        def save(instance,*args,**kwargs):
            if instance.name=='security-reconciliation' and instance.details and not kwargs.get('update_fields'): raise RuntimeError('Interrupted before checkpoint commit')
            return original(instance,*args,**kwargs)
        with patch('core.reporting.indexer_authorization',return_value='test'),patch('core.reporting._search',return_value=response),patch.object(WorkerState,'save',save):
            reconcile_security()
        self.assertFalse(SecurityEvidence.objects.exists());self.assertFalse(DeviceFeed.objects.exists())
        self.assertEqual(WorkerState.objects.get(pk='security-reconciliation').details,{})
    def test_rechecking_a_device_is_queued_and_scoped(self):
        DeviceHealth.objects.create(device=self.d1,checked_at=timezone.now())
        response=self.client.post(reverse('health_device',args=[self.d1.pk]),{'action':'recheck'})
        self.assertEqual(response.status_code,302)
        self.assertIsNone(DeviceHealth.objects.get(device=self.d1).checked_at)
        self.assertEqual(self.client.post(reverse('health_device',args=[self.d2.pk]),{'action':'recheck'}).status_code,404)
    def test_disabled_engine_does_not_raise_a_service_failure(self):
        DeviceHealth.objects.create(device=self.d1,engines={'Suricata':{'running':False,'configured':False,'export':False}})
        self.assertNotIn('Suricata',[row['code'] for row in evaluate_health(self.d1).issues])
    def test_empty_security_tags_and_malformed_agent_do_not_create_threats(self):
        event=self.event();event['data']['security_tags']=['','[]','0'];event['data']['is_blocked']=0;event['rule']['groups']=[]
        self.assertFalse(normalize(event)['security'])
        event['location']='unmapped';event['agent']=['malformed']
        self.assertEqual(ingest_events([event]),0)
    def test_source_conflicts_quarantine_both_devices(self):
        ExportConfiguration.objects.filter(device=self.d2).update(source_ip='8.8.8.8')
        ingest_events([self.event()])
        self.assertEqual(SecurityEvidence.objects.count(),0)
    def test_policy_block_is_not_a_threat_proof(self):
        event=self.event(); event['data']['security_tags']=[]; event['rule']['groups']=['zenarmor']
        ingest_events([event])
        self.assertEqual(SecurityEvidence.objects.get().category,'application_policy')
        self.assertIsNone(DeviceHealth.objects.get(device=self.d1).security_verified_at)
        self.assertFalse(Incident.objects.exists())
    def test_api_success_does_not_imply_log_reception(self):
        DeviceHealth.objects.create(device=self.d1,api_ok=True,checked_at=timezone.now())
        health=evaluate_health(self.d1)
        self.assertNotEqual(health.status,'verified')
        self.assertIsNone(health.last_log_at)
    def test_zenarmor_is_discovered_without_claiming_missing_status_is_stopped(self):
        from .models import OpnsenseConnection
        from .operations import probe_device
        self.d1.management_method='api';self.d1.save()
        OpnsenseConnection.objects.create(device=self.d1,api_url='https://fw.example.test')
        tls=MagicMock();tls.wrap_socket.return_value.__enter__.return_value.getpeercert.return_value={}
        def reply(connection,path):
            if path=='/api/zenarmor/status/index': return {'eastpect':{'status':True},'database':{}}
            if path=='/api/zenarmor/configuration/reporting_data': return {'streamReporting':{'enabled':False}}
            return {}
        with patch('core.provisioning._api_request',side_effect=reply),patch('core.operations.ssl.create_default_context',return_value=tls),patch('core.operations.socket.create_connection'):
            health=probe_device(self.d1)
        self.d1.refresh_from_db();self.assertTrue(self.d1.zenarmor_enabled)
        self.assertTrue(health.engines['Zenarmor']['running'])
        self.assertIsNone(health.engines['Base de informes Zenarmor']['running'])
        self.assertIn('Zenarmor-export',[row['code'] for row in health.issues])
    def test_backup_stream_validates_complete_archive_and_rejects_unlisted_member(self):
        from . import recovery
        import hashlib
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);db=root/'source.sqlite3'
            with sqlite3.connect(db) as connection:
                connection.execute('CREATE TABLE django_migrations (id INTEGER PRIMARY KEY)')
                connection.execute('INSERT INTO django_migrations VALUES (1)')
            connection.close()
            members={'portal.sqlite3':db.read_bytes(),'config/soc-portal/portal.env':b'test configuration'}
            manifest={'files':{k:hashlib.sha256(v).hexdigest() for k,v in members.items()}}
            archive_path=root/'archive.tar.gz'
            def build(extra=False):
                with tarfile.open(archive_path,'w:gz') as archive:
                    for name,body in list(members.items())+[('manifest.json',json.dumps(manifest).encode())]+([('extra',b'unlisted')] if extra else []):
                        entry=tarfile.TarInfo(name);entry.size=len(body);archive.addfile(entry,io.BytesIO(body))
            build()
            with tempfile.TemporaryDirectory() as target:
                self.assertEqual(recovery.validate_tar(archive_path,target)['database_integrity'],'ok')
            build(extra=True)
            with tempfile.TemporaryDirectory() as target,self.assertRaises(ValueError): recovery.validate_tar(archive_path,target)
    def test_quiet_security_only_feed_does_not_infer_failure_without_baseline(self):
        health=DeviceHealth.objects.create(device=self.d1,last_log_at=timezone.now()-timedelta(days=2))
        health=evaluate_health(self.d1)
        self.assertNotIn('silence',[i['code'] for i in health.issues])
        health.expected_silence_minutes=60; health.save()
        self.assertIn('silence',[i['code'] for i in evaluate_health(self.d1).issues])
    def test_manual_asset_name_survives_discovery(self):
        asset=Asset.objects.create(device=self.d1,ip='192.168.1.12',name='Servidor ERP')
        observe_asset(self.d1,asset.ip,'Windows-1234')
        asset.refresh_from_db(); self.assertEqual(asset.label,'Servidor ERP')
    def test_malformed_input_is_not_a_security_event(self):
        self.assertFalse(normalize({'data':[],'rule':'invalid','decoder':[]})['security'])
    def test_audit_detects_tampering_and_never_stores_credentials(self):
        row=audit('example',self.d1,{'status':'ok','password':'never-store','api_key':'never-store'})
        self.assertNotIn('password',row.details); self.assertTrue(audit_integrity())
        AuditEvent.objects.filter(pk=row.pk).update(action='tampered')
        self.assertFalse(audit_integrity())
    def test_each_site_has_a_distinct_vpn_peer_and_minimal_route(self):
        from .vpn import create_peer,client_config
        first=create_peer(self.s1); second=create_peer(self.s2)
        self.assertNotEqual(first.address,second.address)
        self.assertNotEqual(first.public_key,second.public_key)
        with patch('core.vpn.PUBLIC_KEY') as key:
            key.read_text.return_value=second.public_key
            config=client_config(first)
        self.assertIn('AllowedIPs = 10.255.251.1/32',config)
        self.assertNotIn('0.0.0.0/0',config)
    def test_deactivating_a_site_or_client_excludes_its_vpn_peer(self):
        from .vpn import create_peer,active_peers
        peer=create_peer(self.s1);peer.enabled=True;peer.save()
        self.assertEqual(list(active_peers().values_list('pk',flat=True)),[peer.pk])
        self.s1.active=False;self.s1.save()
        self.assertFalse(active_peers().exists())
        self.s1.active=True;self.s1.save();self.c1.active=False;self.c1.save()
        self.assertFalse(active_peers().exists())
    def test_change_activation_needs_permission_and_mfa(self):
        from .change_control import preview
        plan=ChangePlan.objects.create(device=self.d1,template='pyme',title='PYME',preview=preview('pyme','192.168.1.0/24','lan'))
        self.assertEqual(self.client.post(reverse('change_detail',args=[plan.pk]),{'action':'apply'}).status_code,403)
        plan.refresh_from_db(); self.assertEqual(plan.status,'draft')
    def test_staging_failure_rolls_back_only_owned_resources_without_reload(self):
        from .change_control import preview,stage
        plan=ChangePlan.objects.create(device=self.d1,template='pyme',title='PYME',preview=preview('pyme','192.168.1.0/24','lan'))
        self.d1.management_method='api'; self.d1.save()
        from .models import OpnsenseConnection
        OpnsenseConnection.objects.create(device=self.d1,api_url='https://fw.example.test')
        name=f'SOC PLAN {plan.pk} v1.0 1'
        calls=[]
        def api(c,path,payload=None,**kwargs):
            calls.append(path)
            if 'search_rule' in path: return {'rows':[{'uuid':'existing','description':'Other rule'}]}
            if 'add_rule' in path: return {'result':'saved','uuid':'owned'}
            if 'get_rule' in path: return {'rule':{'enabled':'0','description':name}}
            if 'del_rule' in path: return {'result':'deleted'}
            raise ValueError('Unsupported')
        with patch('core.change_control.api',side_effect=api),patch('core.change_control.stage_ids',side_effect=RuntimeError()): stage(plan)
        self.assertEqual(plan.status,'failed')
        self.assertIn('/api/firewall/filter/del_rule/owned',calls)
        self.assertFalse(any('apply' in v or '/existing' in v for v in calls))

@override_settings(SECURE_SSL_REDIRECT=False,SOC_MFA_REQUIRED=True)
class MfaTests(TestCase):
    def setUp(self):
        self.user=get_user_model().objects.create_user('auth-test',password='Very-L0ng-test!975')
        self.client.force_login(self.user)
        self.secret=base64.b32encode(b'12345678901234567890').decode().rstrip('=')
    def test_rfc6238_vector_and_replay_prevention(self):
        self.assertEqual(totp(self.secret,1,8),'94287082')
        p=MfaProfile.objects.create(user=self.user,encrypted_secret=encrypt(self.secret),enabled=True)
        code=totp(self.secret,100)
        self.assertTrue(verify_token(p,code,now=3000))
        self.assertFalse(verify_token(p,code,now=3000))
    def test_recovery_code_is_one_use(self):
        p=MfaProfile.objects.create(user=self.user,encrypted_secret=encrypt(self.secret),enabled=True,recovery_hashes=[make_password('abcd1234')])
        self.assertTrue(verify_token(p,'abcd1234')); self.assertFalse(verify_token(p,'abcd1234'))
    def test_login_requires_personal_enrolment_and_qr_renders(self):
        self.assertRedirects(self.client.get(reverse('dashboard')),reverse('mfa_setup'))
        response=self.client.post(reverse('mfa_setup'),{'action':'generate','password':'Very-L0ng-test!975'})
        self.assertEqual(response.status_code,200); self.assertContains(response,'svg')
        from .security import decrypt
        profile=self.user.soc_mfa
        code=totp(decrypt(profile.encrypted_secret),int(time.time()//30))
        self.client.post(reverse('mfa_setup'),{'action':'confirm','code':code})
        profile.refresh_from_db(); self.assertTrue(profile.enabled)
        self.assertEqual(self.client.get(reverse('dashboard')).status_code,200)
    def test_reset_version_invalidates_verified_session(self):
        p=MfaProfile.objects.create(user=self.user,encrypted_secret=encrypt(self.secret),enabled=True)
        session=self.client.session; session['soc_mfa_user']=self.user.pk; session['soc_mfa_version']=p.version; session.save()
        p.version+=1; p.save()
        self.assertRedirects(self.client.get(reverse('dashboard')),reverse('mfa_challenge'))
    def test_password_throttling_is_enforced(self):
        self.client.logout()
        for _ in range(8): self.client.post('/login/',{'username':'auth-test','password':'wrong'})
        self.assertEqual(self.client.post('/login/',{'username':'auth-test','password':'wrong'}).status_code,429)

class BackupFormatTests(TestCase):
    def test_streaming_encryption_detects_tampering_and_truncation(self):
        from . import recovery
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); key=root/'key'; key.write_bytes(Fernet.generate_key())
            source=root/'input'; source.write_bytes(os.urandom(2*1024*1024+70))
            encrypted=root/'encrypted'; output=root/'output'
            with patch.object(recovery,'KEY',key):
                recovery.encrypt_file(source,encrypted); recovery.decrypt_file(encrypted,output)
                self.assertEqual(source.read_bytes(),output.read_bytes())
                data=encrypted.read_bytes()
                with self.assertRaises((InvalidToken,ValueError)): recovery.decrypt_file(data[:-10],output)
                corrupt=bytearray(data); corrupt[100]^=1
                with self.assertRaises((InvalidToken,ValueError)): recovery.decrypt_file(bytes(corrupt),output)
    def test_restore_validation_rejects_traversal_without_extracting(self):
        from . import recovery
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); key=root/'key'; key.write_bytes(Fernet.generate_key())
            tar=root/'bad.tar.gz'; enc=root/'bad.socbak'
            with tarfile.open(tar,'w:gz') as archive:
                info=tarfile.TarInfo('../outside'); info.size=1; archive.addfile(info,io.BytesIO(b'x'))
            with patch.object(recovery,'KEY',key):
                recovery.encrypt_file(tar,enc)
                with self.assertRaises(ValueError): recovery.validate_archive(enc)

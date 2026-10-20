import base64
import json
import time
import uuid
import tempfile
import os
from unittest import skipIf
from pathlib import Path
from datetime import timedelta
from unittest.mock import patch
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase,override_settings,Client as Browser
from django.urls import reverse
from django.utils import timezone
from .models import (Client,Site,Device,Incident,IncidentAction,Asset,SecurityEvidence,StaffAccess,ExportConfiguration,
    RunbookStep,CustomerTask,ProtectionValidation,DeliverySettings,MailDispatch,MailEvent,ConfigurationArchive,UrgentAlert,OperationalIssue)
from .operations import ingest_events,observe_asset
from .asset_identity import identity_snapshot,discover_dhcp
from .operations_suite import reconcile_validations

@override_settings(SECURE_SSL_REDIRECT=False,SOC_MFA_REQUIRED=False)
class ImprovementTests(TestCase):
    def setUp(self):
        self.company=Client.objects.create(name='Visible',code='visible')
        self.other=Client.objects.create(name='Oculta',code='hidden')
        site=Site.objects.create(client=self.company,name='Oficina',code='office')
        self.device=Device.objects.create(site=site,name='FW',vendor='opnsense',management_method='api')
        other_site=Site.objects.create(client=self.other,name='Otra sede',code='other')
        self.other_device=Device.objects.create(site=other_site,name='Privado',vendor='opnsense')
        ExportConfiguration.objects.create(device=self.device,source_ip='8.8.8.8',receiver_ready=True)
        from .testing_access import legacy_sources
        legacy_sources()
        self.user=get_user_model().objects.create_user('operator')
        access=StaffAccess.objects.create(user=self.user,role='operator');access.clients.add(self.company)
        self.user.groups.add(Group.objects.get(name='SOC Operador'))
        self.customer=get_user_model().objects.create_user('customer')
        access=StaffAccess.objects.create(user=self.customer,role='customer');access.clients.add(self.company)
        self.client.force_login(self.user)
    def event(self,identifier,stamp=None,action='blocked',address='192.168.1.12'):
        return {'id':identifier,'timestamp':(stamp or timezone.now()).isoformat(),'location':'8.8.8.8',
            'decoder':{'name':'zenarmor'},'rule':{'level':8,'description':'Malware','groups':['zenarmor_security']},
            'data':{'ip_src_saddr':address,'ip_dst_saddr':'1.1.1.1','ip_dst_port':'443','security_tags':['Malware'],'is_blocked':int(action=='blocked')}}
    def case(self,company=None):
        return Incident.objects.create(client=company or self.company,device=self.device if company is None else self.other_device,title='Malware',description='Nota interna secreta')
    def test_repetitions_across_hours_and_actions_share_case_and_raise_severity(self):
        now=timezone.now()
        ingest_events([self.event('a',now-timedelta(hours=2)),self.event('b',now,action='allowed')],now)
        self.assertEqual(Incident.objects.count(),1)
        case=Incident.objects.get();self.assertEqual(case.occurrence_count,2);self.assertEqual(case.severity,'critical')
        self.assertEqual(case.evidence.count(),2)
        ingest_events([self.event('c',now+timedelta(minutes=1))],now+timedelta(minutes=1))
        case.refresh_from_db();self.assertEqual(case.occurrence_count,3)
    def test_separate_devices_assets_and_old_episodes_never_merge(self):
        now=timezone.now()
        ingest_events([self.event('a',now-timedelta(hours=25)),self.event('b',now),self.event('c',now,address='192.168.1.13')],now)
        self.assertEqual(Incident.objects.count(),3)
    def test_replay_does_not_reopen_but_new_detection_resets_runbook(self):
        now=timezone.now();old=self.event('a',now-timedelta(minutes=10));ingest_events([old],now)
        case=Incident.objects.get();case.status='resolved';case.resolved_at=now-timedelta(minutes=5);case.save()
        RunbookStep.objects.create(incident=case,position=1,title='Revisada',done=True,evidence='Resultado anterior')
        ingest_events([old],now);case.refresh_from_db();self.assertEqual(case.status,'resolved')
        ingest_events([self.event('b',now)],now);case.refresh_from_db();self.assertEqual(case.status,'open')
        self.assertFalse(case.runbook_steps.get().done)
    def test_new_historical_evidence_does_not_reopen_resolved_case(self):
        now=timezone.now();ingest_events([self.event('a',now-timedelta(minutes=20))],now)
        case=Incident.objects.get();case.status='resolved';case.resolved_at=now-timedelta(minutes=5);case.save()
        ingest_events([self.event('historical',now-timedelta(minutes=10))],now)
        case.refresh_from_db();self.assertEqual(case.status,'resolved');self.assertEqual(case.occurrence_count,2)
    def test_frozen_identity_does_not_follow_later_ip_reassignment(self):
        observe_asset(self.device,'192.168.1.12','Contabilidad','00:11:22:33:44:55',source='dhcp')
        now=timezone.now();ingest_events([self.event('a',now)],now)
        evidence=SecurityEvidence.objects.get();self.assertEqual(evidence.identified_label,'Contabilidad')
        observe_asset(self.device,'192.168.1.12','Visitante','00:11:22:33:44:66',source='dhcp')
        asset=Asset.objects.get();self.assertTrue(asset.identity_conflict)
        self.assertEqual(evidence.identified_label,'Contabilidad')
        self.assertEqual(identity_snapshot(asset,timezone.now())['confidence'],'unknown')
        self.assertEqual(len(asset.identity_history),1)
    def test_old_and_future_discoveries_do_not_identify_historical_event(self):
        asset=Asset.objects.create(device=self.device,ip='192.168.1.12',discovered_name='PC',identified_at=timezone.now()-timedelta(days=2))
        self.assertEqual(identity_snapshot(asset,timezone.now())['confidence'],'unknown')
        asset.identified_at=timezone.now()+timedelta(hours=1)
        self.assertEqual(identity_snapshot(asset,timezone.now())['confidence'],'unknown')
    def test_automatic_discovery_preserves_manual_name_and_skips_bad_leases(self):
        asset=Asset.objects.create(device=self.device,ip='192.168.1.12',name='Servidor negocio')
        api=lambda *args:{'rows':[{'address':asset.ip,'hostname':'dhcp-name','hwaddr':'00:11:22:33:44:55','state':0},
            {'address':'192.168.1.14','hostname':'expired','state':2}]}
        self.assertEqual(discover_dhcp(self.device,None,api),1)
        asset.refresh_from_db();self.assertEqual(asset.name,'Servidor negocio');self.assertEqual(asset.discovered_name,'dhcp-name')
        self.assertFalse(Asset.objects.filter(ip='192.168.1.14').exists())
    def test_runbook_preparation_idempotent_and_requires_evidence(self):
        case=self.case();url=reverse('runbook',args=[case.pk])
        for _ in range(2):self.client.post(url,{'operation':'prepare'})
        self.assertEqual(case.runbook_steps.count(),5)
        step=case.runbook_steps.first()
        self.client.post(url,{'step':step.pk,'done':'1','evidence':''});step.refresh_from_db();self.assertFalse(step.done)
        self.client.post(url,{'step':step.pk,'done':'1','evidence':'EDR revisado, informe LAB-001'})
        step.refresh_from_db();self.assertTrue(step.done);self.assertEqual(step.completed_by,self.user)
    def test_runbook_cannot_change_foreign_case_and_title_contains_no_html(self):
        other=self.case(self.other)
        self.assertEqual(self.client.post(reverse('runbook',args=[other.pk]),{'operation':'prepare'}).status_code,404)
        case=self.case();response=self.client.get(reverse('incident_detail',args=[case.pk]))
        title=response.content.decode().split('<title>',1)[1].split('</title>',1)[0]
        self.assertNotIn('<section',title)
    def test_customer_reply_is_scoped_published_and_cannot_close_case(self):
        case=self.case();task=CustomerTask.objects.create(incident=case,title='Actualizar equipo',instructions='Pasos publicados',visible=True)
        hidden=CustomerTask.objects.create(incident=case,title='Borrador',instructions='Interna')
        other=CustomerTask.objects.create(incident=self.case(self.other),title='Privada',instructions='Privada',visible=True)
        self.client.force_login(self.customer)
        for private in (hidden,other):self.assertEqual(self.client.get(reverse('customer_task_reply',args=[private.pk])).status_code,404)
        page=self.client.get(reverse('customer_task_reply',args=[task.pk]));self.assertNotContains(page,'Nota interna secreta')
        self.assertEqual(self.client.post(reverse('customer_task_reply',args=[task.pk]),{'response':'Actualizado y analizado; sin persistencia','status':'accepted','visible':'0'}).status_code,302)
        task.refresh_from_db();case.refresh_from_db()
        self.assertEqual(task.status,'submitted');self.assertTrue(task.visible);self.assertEqual(case.status,'open')
        self.client.post(reverse('customer_task_reply',args=[task.pk]),{'response':'Sustituir evidencia'})
        task.refresh_from_db();self.assertNotEqual(task.response,'Sustituir evidencia')
        self.assertEqual(self.client.post(reverse('incident_note',args=[case.pk]),{'text':'injected'}).status_code,403)
    def test_customer_post_requires_csrf_and_mfa(self):
        task=CustomerTask.objects.create(incident=self.case(),title='Tarea',instructions='Pasos',visible=True)
        browser=Browser(enforce_csrf_checks=True);browser.force_login(self.customer)
        self.assertEqual(browser.post(reverse('customer_task_reply',args=[task.pk]),{'response':'Respuesta'}).status_code,403)
        with override_settings(SOC_MFA_REQUIRED=True):
            response=self.client.post(reverse('customer_task_reply',args=[task.pk]),{'response':'Respuesta'})
            self.assertEqual(response.status_code,302);self.assertIn('/security/mfa/',response.url)
    def test_soc_review_completes_only_linked_action_with_evidence(self):
        case=self.case();action=IncidentAction.objects.create(incident=case,title='Interna',responsible_party='client')
        task=CustomerTask.objects.create(incident=case,action=action,title='Publicada',instructions='Pasos',response='Hecho y comprobado',status='submitted')
        data={'title':task.title,'instructions':task.instructions,'status':'accepted','review_note':'Resultado verificado en el firewall','action':action.pk,'visible':'on'}
        self.assertEqual(self.client.post(reverse('customer_task_edit',args=[task.pk]),data).status_code,302)
        action.refresh_from_db();self.assertEqual(action.status,'done');self.assertIn('Hecho y comprobado',action.resolution)
        case.refresh_from_db();self.assertEqual(case.status,'open')
    def test_case_closure_blocked_by_guide_and_customer_tasks(self):
        from .forms import IncidentForm
        case=self.case();RunbookStep.objects.create(incident=case,position=1,title='Pendiente')
        CustomerTask.objects.create(incident=case,title='Tarea',instructions='Pasos')
        form=IncidentForm({'client':self.company.pk,'device':self.device.pk,'title':case.title,'description':'Caso','status':'resolved','severity':'high','observed_at':timezone.now().isoformat()},instance=case)
        self.assertFalse(form.is_valid());self.assertIn('guía',str(form.errors));self.assertIn('tareas',str(form.errors))
    def test_validation_requires_matching_engine_signature_device_and_window(self):
        now=timezone.now();item=ProtectionValidation.objects.create(device=self.device,engine='zenarmor',networks='LAN PC',expected_signature='Firma prueba',started_at=now,expires_at=now+timedelta(hours=1))
        for uid,engine,signature,stamp,d in [('old','zenarmor','Firma prueba',now-timedelta(seconds=1),self.device),('engine','suricata','Firma prueba',now,self.device),('device','zenarmor','Firma prueba',now,self.other_device),('signature','zenarmor','Otra firma',now,self.device)]:
            SecurityEvidence.objects.create(uid=uid,device=d,observed_at=stamp,engine=engine,signature=signature,action='blocked')
        self.assertEqual(reconcile_validations(now+timedelta(seconds=1)),0)
        e=SecurityEvidence.objects.create(uid='correct',device=self.device,observed_at=now,engine='zenarmor',signature='Firma prueba',action='unknown')
        self.assertEqual(reconcile_validations(now+timedelta(seconds=1)),1)
        item.refresh_from_db();self.assertEqual(item.evidence,e);self.assertEqual(item.evidence.action,'unknown')
        self.assertEqual(reconcile_validations(now+timedelta(seconds=2)),0)
    def test_signed_webhook_rejects_forgery_and_is_idempotent_and_recipient_scoped(self):
        private=ec.generate_private_key(ec.SECP256R1())
        public=base64.b64encode(private.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
        DeliverySettings.objects.create(pk=1,public_key=public,enabled=True)
        dispatch=MailDispatch.objects.create(token=uuid.uuid4(),client=self.company,recipient='client@example.com')
        def send(events,signature_ok=True,old=False):
            raw=json.dumps(events).encode();stamp=str(int(time.time())-8*86400 if old else int(time.time()))
            signature=private.sign(stamp.encode()+raw,ec.ECDSA(hashes.SHA256()))
            if not signature_ok:raw+=b' '
            return self.client.post(reverse('delivery_webhook'),raw,content_type='application/json',HTTP_X_TWILIO_EMAIL_EVENT_WEBHOOK_TIMESTAMP=stamp,HTTP_X_TWILIO_EMAIL_EVENT_WEBHOOK_SIGNATURE=base64.b64encode(signature).decode())
        event={'event':'delivered','timestamp':int(time.time()),'sg_event_id':'a','email':dispatch.recipient,'soc_dispatch':str(dispatch.token)}
        self.assertEqual(send([event],False).status_code,403)
        self.assertEqual(send([event],old=True).status_code,403)
        self.assertEqual(send([dict(event,email='bcc@example.com')]).status_code,204);self.assertEqual(MailEvent.objects.count(),0)
        for _ in range(2):self.assertEqual(send([event]).status_code,204)
        self.assertEqual(MailEvent.objects.count(),1);dispatch.refresh_from_db();self.assertEqual(dispatch.status,'delivered')
        send([dict(event,event='deferred',sg_event_id='earlier',timestamp=int(time.time())-1)])
        dispatch.refresh_from_db();self.assertEqual(dispatch.status,'delivered')
        send([dict(event,event='bounce',sg_event_id='bounce')]);dispatch.refresh_from_db();self.assertEqual(dispatch.status,'bounce')
    def test_delivery_views_scoped_and_global_config_protected(self):
        MailDispatch.objects.create(token=uuid.uuid4(),client=self.other,recipient='private@example.com')
        page=self.client.get(reverse('delivery_status'));self.assertNotContains(page,'private@example.com')
        self.assertEqual(self.client.get(reverse('delivery_settings')).status_code,403)
    def test_internal_escalation_and_acknowledgment_are_idempotent(self):
        from .delivery_tracking import escalate_unacknowledged
        alert=UrgentAlert.objects.create(client=self.company,event_uid='urgent',fingerprint='f',kind='security_critical',observed_at=timezone.now(),source_ip='8.8.8.8',recipient='client@example.com')
        UrgentAlert.objects.filter(pk=alert.pk).update(created_at=timezone.now()-timedelta(hours=1))
        escalate_unacknowledged();escalate_unacknowledged()
        self.assertEqual(OperationalIssue.objects.filter(active=True).count(),1)
        for _ in range(2):self.client.post(reverse('acknowledge_alert',args=[alert.pk]))
        alert.refresh_from_db();self.assertEqual(alert.acknowledged_by,self.user)
        escalate_unacknowledged();self.assertFalse(OperationalIssue.objects.filter(active=True).exists())
    @skipIf(os.name!='posix','POSIX file permissions are verified on Ubuntu')
    def test_backup_redacts_secrets_rejects_xml_entities_and_encrypts(self):
        from .configuration_archives import summarize_xml,archive_device
        blob=b'<opnsense><system><webgui><password>SECRET_VALUE</password></webgui></system><filter><rule><enabled>1</enabled></rule></filter></opnsense>'
        self.assertNotIn('SECRET_VALUE',json.dumps(summarize_xml(blob)))
        with self.assertRaises(ValueError):summarize_xml(b'<!DOCTYPE opnsense [<!ENTITY x "y">]><opnsense/>')
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/'firewalls';box=Fernet(Fernet.generate_key())
            with patch('core.configuration_archives.ROOT',root),patch('core.configuration_archives.os.geteuid',return_value=0,create=True),patch('core.configuration_archives.fetch_configuration',return_value=blob),patch('core.configuration_archives.cipher',return_value=box):
                saved=archive_device(self.device)
                self.assertEqual(saved.status,'saved')
                encrypted=(root/(str(saved.pk)+'.fernet')).read_bytes();self.assertNotIn(b'SECRET_VALUE',encrypted)
                self.assertEqual(box.decrypt(encrypted),blob)
                saved2=archive_device(self.device);self.assertEqual(saved2.changes,[])
                changed=blob.replace(b'<enabled>1</enabled>',b'<enabled>0</enabled>')
                with patch('core.configuration_archives.fetch_configuration',return_value=changed):
                    third=archive_device(self.device);self.assertEqual(third.changes,['Reglas de firewall'])
    def test_backup_failure_does_not_mark_saved_or_expose_remote_error(self):
        from .configuration_archives import archive_device
        with patch('core.configuration_archives.os.geteuid',return_value=0,create=True),patch('core.configuration_archives.fetch_configuration',side_effect=ValueError('SECRET_VALUE')):
            item=archive_device(self.device)
            self.assertEqual(item.status,'failed');self.assertNotIn('SECRET_VALUE',item.note)
    def test_private_pages_and_validation_controls_are_scoped(self):
        self.assertEqual(self.client.get(reverse('validations',args=[self.other_device.pk])).status_code,404)
        self.assertEqual(self.client.get(reverse('configuration_archives',args=[self.other_device.pk])).status_code,404)
        for route in ('validations','configuration_archives'):
            self.assertEqual(self.client.get(reverse(route,args=[self.device.pk])).status_code,200)
    def test_findings_preserve_event_identity_and_mark_current_name_unconfirmed(self):
        from .findings import _asset
        event=self.event('identity');stamp=timezone.now().isoformat();event['timestamp']=stamp
        inventories={'8.8.8.8':{'hosts':{'192.168.1.12':'Nuevo ocupante'},'identities':{('identity',stamp):{'label':'Anterior ocupante','confidence':'recent'}}}}
        row=_asset(event,inventories);self.assertEqual(row['name'],'Anterior ocupante');self.assertTrue(row['confirmed'])
        inventories['8.8.8.8']['identities']={}
        row=_asset(event,inventories);self.assertFalse(row['confirmed']);self.assertIn('confirmar',row['name'])
    def test_new_case_resolution_gets_timestamp_and_reopening_clears_it(self):
        from .forms import IncidentForm
        case=self.case()
        data={'client':self.company.pk,'site':self.device.site_id,'device':self.device.pk,'title':case.title,'description':'Caso','status':'resolved','severity':'high','observed_at':timezone.now().isoformat()}
        form=IncidentForm(data,instance=case);self.assertTrue(form.is_valid(),form.errors)
        saved=form.save();self.assertIsNotNone(saved.resolved_at)
        data['status']='investigating';data['resolved_at']=saved.resolved_at.isoformat()
        form=IncidentForm(data,instance=saved);self.assertTrue(form.is_valid(),form.errors)
        self.assertIsNone(form.save().resolved_at)
    def test_configuration_review_requires_scope_and_preserves_newer_unreviewed_change(self):
        from .operations import set_issue
        older=ConfigurationArchive.objects.create(device=self.device,status='saved',changes=['Interfaces'])
        ConfigurationArchive.objects.create(device=self.device,status='saved',changes=['Reglas de firewall'])
        key='device:'+str(self.device.pk)+':configuration-change';set_issue(key,'Revisar',self.device)
        self.client.post(reverse('configuration_archives',args=[self.device.pk]),{'archive':older.pk,'review_note':'Cambio autorizado'})
        older.refresh_from_db();self.assertEqual(older.reviewed_by,self.user)
        self.assertTrue(OperationalIssue.objects.get(key=key).active)
        self.assertEqual(self.client.post(reverse('configuration_archives',args=[self.other_device.pk]),{'archive':older.pk,'review_note':'Cambio autorizado'}).status_code,404)
    def test_tracking_dispatch_in_sendgrid_payload_without_message_content(self):
        from .models import MailSettings
        from .mail_delivery import send_via_sendgrid,encrypt_sendgrid_key
        box_key=Fernet.generate_key().decode()
        with patch.dict(os.environ,{'SOC_PORTAL_MAIL_KEY':box_key}):
            config=MailSettings.objects.create(from_email='soc@example.com',encrypted_api_key=encrypt_sendgrid_key('SG.TEST'))
            class Response:
                status=202;headers={'X-Message-Id':'provider'}
                def __enter__(self):return self
                def __exit__(self,*args):return False
            with patch('core.mail_delivery.request.build_opener') as opener:
                opener.return_value.open.return_value=Response()
                send_via_sendgrid(config,'customer@example.com','Subject','PRIVATE_TEXT','<p>PRIVATE_TEXT</p>',delivery_context={'client':self.company,'kind':'report'})
                payload=json.loads(opener.return_value.open.call_args.args[0].data)
            dispatch=MailDispatch.objects.get()
            self.assertEqual(payload['personalizations'][0]['custom_args']['soc_dispatch'],str(dispatch.token))
            self.assertEqual(dispatch.status,'accepted');self.assertEqual(dispatch.provider_id,'provider')
            self.assertFalse(hasattr(dispatch,'body'))

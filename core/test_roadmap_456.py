import base64,json,time,uuid
from datetime import timedelta
from unittest.mock import patch
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.asymmetric import ec
from django.test import TestCase,SimpleTestCase,override_settings,Client as Browser
from django.contrib.auth import get_user_model
from django.utils import timezone
from .models import Client,Site,Device,StaffAccess,MfaProfile,WorkerState,SecurityEvidence,DeliverySettings,MailDispatch,MailEvent,VpnPeer,AdvancedReview
from .wazuh_scoped import role_definition,document,binding_ready
from .unifi_flow import matches,evaluate
from .vpn import record_log_transport,transport_snapshot
from .testing_access import workflow_access

@override_settings(SECURE_SSL_REDIRECT=False,SOC_MFA_REQUIRED=True,SOC_WAZUH_PROXY_KEY='private-proxy')
class ScopedDashboardTests(TestCase):
    def setUp(self):
        self.a=Client.objects.create(name='A',code='a');self.b=Client.objects.create(name='B',code='b')
        self.user=get_user_model().objects.create_user('scoped-reader')
        self.access=StaffAccess.objects.create(user=self.user,role='customer');self.access.clients.add(self.a)
        self.profile=MfaProfile.objects.create(user=self.user,enabled=True)
        self.client.force_login(self.user);s=self.client.session;s.update({'soc_mfa_user':self.user.pk,'soc_mfa_version':self.profile.version,'soc_mfa_at':time.time()});s.save()
        self.ready=WorkerState.objects.create(name='wazuh-customer-'+str(self.a.pk),last_success_at=timezone.now(),details={'version':1,'ready':True})
    def check(self):return self.client.get('/security/wazuh/check/',HTTP_X_SOC_WAZUH_KEY='private-proxy',HTTP_SECURITYTENANT='global_tenant',HTTP_X_PROXY_ROLES='all_access')
    def test_customer_headers_derived_and_foreign_entry_denied(self):
        r=self.check();self.assertEqual(r.status_code,200);self.assertEqual(r['X-SOC-Wazuh-Tenant'],'soc_customer_'+str(self.a.pk))
        self.assertNotIn('soc_portal_reader',r['X-SOC-Wazuh-Roles']);self.assertNotIn('all_access',r['X-SOC-Wazuh-Roles'])
        self.assertEqual(self.client.get('/security/wazuh/enter/',{'client':'b'}).status_code,404)
        r=self.client.get('/security/wazuh/enter/');self.assertIn('security_tenant=soc_customer_',r['Location'])
    def test_revocation_and_stale_provisioning_fail_closed(self):
        self.ready.last_success_at=timezone.now()-timedelta(minutes=16);self.ready.save();self.assertEqual(self.check().status_code,403)
        self.ready.last_success_at=timezone.now();self.ready.save();self.access.clients.clear();self.assertEqual(self.check().status_code,403)
    def test_mfa_revocation_and_logout_remove_access(self):
        self.profile.version+=1;self.profile.save();self.assertEqual(self.check().status_code,401)
        self.client.logout();self.assertEqual(self.check().status_code,401)
    def test_scoped_operator_selects_only_assigned_companies(self):
        self.access.role='reader';self.access.save();self.access.clients.add(self.b)
        self.assertContains(self.client.get('/security/wazuh/enter/'),'Selecciona una empresa')
        self.assertEqual(self.check().status_code,403)
        self.client.get('/security/wazuh/enter/',{'client':'a'});self.assertEqual(self.check().status_code,200)
        self.access.clients.remove(self.a);self.assertEqual(self.check().status_code,403)
    def test_role_has_exact_index_dls_and_own_tenant(self):
        r=role_definition(self.a.pk)
        self.assertEqual(r['index_permissions'][0]['index_patterns'],['soc-customer-'+str(self.a.pk)+'-events'])
        self.assertEqual(json.loads(r['index_permissions'][0]['dls']),{'term':{'soc.client_id':self.a.pk}})
        self.assertEqual(r['tenant_permissions'][0]['tenant_patterns'],['soc_customer_'+str(self.a.pk)])
    def test_projection_uses_frozen_owner_and_omits_internal_notes(self):
        d=Device.objects.create(site=Site.objects.create(client=self.b,name='Now B',code='b-site'),name='Secret current name',vendor='opnsense')
        e=SecurityEvidence.objects.create(uid='frozen',device=d,client_scope_id=self.a.pk,observed_at=timezone.now(),engine='suricata',signature='Observed',identity={'label':'Private DHCP name'},recommendation='Internal note')
        payload=document(e);self.assertEqual(payload['soc']['client_id'],self.a.pk)
        self.assertNotIn('Internal note',json.dumps(payload));self.assertNotIn('Private DHCP',json.dumps(payload));self.assertNotIn('Secret current name',json.dumps(payload))
        e.client_scope_id=None
        with self.assertRaises(ValueError):document(e)
    def test_evidence_scope_does_not_follow_a_device_move(self):
        from .scope import customer_scope
        site=Site.objects.create(client=self.a,name='A site',code='a-site')
        d=Device.objects.create(site=site,name='FW',vendor='opnsense')
        e=SecurityEvidence.objects.create(uid='owned',device=d,observed_at=timezone.now(),engine='suricata')
        d.site=Site.objects.create(client=self.b,name='B site',code='b-site');d.save()
        token=customer_scope.set([self.b.pk])
        try:self.assertFalse(SecurityEvidence.objects.filter(pk=e.pk).exists())
        finally:customer_scope.reset(token)
        token=customer_scope.set([self.a.pk])
        try:self.assertTrue(SecurityEvidence.objects.filter(pk=e.pk).exists())
        finally:customer_scope.reset(token)
        e.client_scope_id=self.b.pk
        with self.assertRaises(ValueError):e.save()

@override_settings(SECURE_SSL_REDIRECT=False,SOC_MFA_REQUIRED=False)
class DeliveryEvidenceTests(TestCase):
    def setUp(self):
        self.key=ec.generate_private_key(ec.SECP256R1());public=self.key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        self.cfg=DeliverySettings.objects.create(pk=1,enabled=True,public_key=public)
        self.dispatch=MailDispatch.objects.create(token=uuid.uuid4(),recipient='client@example.test',status='accepted')
    def post(self,events,offset=0):
        body=json.dumps(events).encode();stamp=str(int(time.time())+offset);signature=self.key.sign(stamp.encode()+body,ec.ECDSA(hashes.SHA256()))
        return self.client.post('/reports/delivery-events/',body,content_type='application/json',HTTP_X_TWILIO_EMAIL_EVENT_WEBHOOK_TIMESTAMP=stamp,HTTP_X_TWILIO_EMAIL_EVENT_WEBHOOK_SIGNATURE=base64.b64encode(signature).decode())
    def event(self,kind='delivered',**changes):return {'event':kind,'email':self.dispatch.recipient,'timestamp':int(time.time()),'soc_dispatch':str(self.dispatch.token),'sg_event_id':str(uuid.uuid4()),**changes}
    def test_valid_signature_is_not_real_delivery_without_correlation(self):
        self.assertEqual(self.post([self.event(email='bcc@example.test')]).status_code,204)
        self.cfg.refresh_from_db();self.assertIsNotNone(self.cfg.last_signed_at);self.assertIsNone(self.cfg.last_matched_at);self.assertEqual(MailEvent.objects.count(),0)
    def test_retry_and_out_of_order_failure_do_not_report_delivered(self):
        event=self.event('bounce');self.post([event]);self.post([event]);self.post([self.event()])
        self.dispatch.refresh_from_db();self.assertEqual(self.dispatch.status,'bounce');self.assertEqual(self.dispatch.events.count(),2)
        self.cfg.refresh_from_db();self.assertIsNotNone(self.cfg.last_matched_at)
    def test_future_signature_and_mutated_payload_rejected(self):
        self.assertEqual(self.post([self.event()],offset=3600).status_code,403)
        r=self.client.post('/reports/delivery-events/',b'[]',content_type='application/json',HTTP_X_TWILIO_EMAIL_EVENT_WEBHOOK_TIMESTAMP=str(int(time.time())),HTTP_X_TWILIO_EMAIL_EVENT_WEBHOOK_SIGNATURE='invalid')
        self.assertEqual(r.status_code,403);self.cfg.refresh_from_db();self.assertIsNone(self.cfg.last_signed_at)
    def test_readonly_provider_permission_failure_is_explicit(self):
        from urllib.error import HTTPError
        from .delivery_provider import diagnose
        with patch('core.delivery_provider.MailSettings.objects.first',return_value=type('Config',(),{'region':'global','encrypted_api_key':'private'})()),patch('core.delivery_provider.decrypt_sendgrid_key',return_value='private'),patch('core.delivery_provider.request.build_opener') as opener:
            opener.return_value.open.side_effect=HTTPError('https://api.sendgrid.com',403,'Forbidden',None,None)
            state=diagnose()
        self.assertEqual(state.details['status'],'permission');self.assertNotIn('private',json.dumps(state.details))

class FlowTests(SimpleTestCase):
    def policy(self,**values):return {'enabled':True,'index':1,'name':'Policy','action':'Bloquear','criteria_pending':False,'flow_match':{'ip':{'ipVersion':'IPV4'},'states':None,'pending':False,'endpoints':[{'network':None,'ports':None,'pending':False}]*2},**values}
    def flow(self):return {'protocol':'TCP','ip':'IPV4','state':'NEW','source_port':12345,'destination_port':443}
    def test_unknown_preceding_policy_blocks_later_verdict(self):
        p=self.policy(criteria_pending=True);pair={'order_unambiguous':True,'policies':[p,self.policy(index=2)]}
        self.assertEqual(evaluate(pair,self.flow(),True)['status'],'unknown')
    def test_definite_mismatch_can_skip_unknown_rule(self):
        p=self.policy(criteria_pending=True);p['flow_match']['ip']['ipVersion']='IPV6'
        result=evaluate({'order_unambiguous':True,'policies':[p,self.policy(index=2)]},self.flow(),True)
        self.assertEqual(result['status'],'match');self.assertEqual(result['policy']['index'],2)
    def test_duplicate_order_stale_and_no_match_never_infer_default(self):
        for pair,current in (({'order_unambiguous':False,'policies':[self.policy()]},True),({'order_unambiguous':True,'policies':[]},True),({'order_unambiguous':True,'policies':[self.policy()]},False)):
            self.assertEqual(evaluate(pair,self.flow(),current)['status'],'unknown')
    def test_inverse_ports_and_unspecified_network_are_three_valued(self):
        p=self.policy();p['flow_match']['endpoints'][1]={'network':None,'pending':False,'ports':{'type':'PORTS','matchOpposite':True,'items':[{'type':'PORT_NUMBER','value':443}]}}
        self.assertIs(matches(p,self.flow()),False)
        p['flow_match']['endpoints'][1]={'network':{'networkIds':['id'],'matchOpposite':False},'ports':None,'pending':False}
        self.assertIsNone(matches(p,self.flow()))

class VpnTransportTests(TestCase):
    def setUp(self):
        self.client_org=Client.objects.create(name='VPN',code='vpn');self.site=Site.objects.create(client=self.client_org,name='Sede',code='sede')
        self.device=Device.objects.create(site=self.site,name='FW',vendor='opnsense')
        self.peer=VpnPeer.objects.create(site=self.site,address='10.255.251.2',public_key='key',encrypted_private_key='secret',encrypted_preshared_key='psk',enabled=True)
    def test_logs_require_peer_source_ownership_and_recent_observation(self):
        now=timezone.now();record_log_transport(self.device,'8.8.8.8',now,now);self.peer.refresh_from_db();self.assertNotIn('log_at',self.peer.transport)
        record_log_transport(self.device,self.peer.address,now-timedelta(hours=1),now);self.peer.refresh_from_db();self.assertNotIn('log_at',self.peer.transport)
        record_log_transport(self.device,self.peer.address,now,now);self.peer.refresh_from_db();self.assertIn('log_at',self.peer.transport)
        self.assertFalse(transport_snapshot(self.peer,now)['logs_current'])
        self.peer.handshake_at=now;self.peer.transport.update(sampled_at=now.isoformat(),received_bytes=500)
        self.assertTrue(transport_snapshot(self.peer,now)['logs_current'])
        self.peer.handshake_at=now+timedelta(hours=1);self.assertFalse(transport_snapshot(self.peer,now)['handshake_current'])
    def test_different_site_cannot_claim_peer(self):
        other=Site.objects.create(client=self.client_org,name='Other',code='other');self.device.site=other;self.device.save()
        now=timezone.now();record_log_transport(self.device,self.peer.address,now,now);self.peer.refresh_from_db();self.assertEqual(self.peer.transport,{})

class AdvancedReadTests(SimpleTestCase):
    def test_empty_complete_acl_is_known_but_missing_upnp_is_unknown(self):
        from .advanced_coverage import collect_unifi
        from .test_unifi_zone_scope import uid
        connection=type('Connection',(),{'encrypted_api_key':'secret','remote_host_id':'host'})()
        def catalogue(read,path,deadline):return [{'id':uid(1),'internalReference':'default'}] if path=='/v1/sites' else []
        with patch('core.unifi_cloud.decrypt_api_key',return_value='private'),patch('core.unifi_zone_scope.catalogue',side_effect=catalogue),patch('core.unifi_cloud.connector_json',return_value={'meta':{'rc':'ok'},'data':[]}):
            result=collect_unifi(connection)
        self.assertEqual(result['acl']['status'],'checked');self.assertEqual(result['acl']['count'],0)
        self.assertEqual(result['upnp']['status'],'unavailable');self.assertNotIn('enabled',result['upnp'])
    def test_failed_acl_preserves_history_without_renewing_it(self):
        from .advanced_coverage import collect_unifi
        old={'acl':{'status':'checked','count':2,'last_success_at':'2026-01-01T00:00:00Z'}}
        connection=type('Connection',(),{'encrypted_api_key':'secret','remote_host_id':'host'})()
        with patch('core.unifi_cloud.decrypt_api_key',return_value='private'),patch('core.unifi_zone_scope.catalogue',side_effect=ValueError('partial')),patch('core.unifi_cloud.connector_json',side_effect=ValueError('unknown')):
            result=collect_unifi(connection,old)
        self.assertEqual(result['acl']['status'],'unavailable');self.assertEqual(result['acl']['historical']['last_success_at'],old['acl']['last_success_at'])
    def test_projection_snapshots_include_exact_customer_indices(self):
        from .recovery_components import selected_indices
        result=selected_indices([{'index':i} for i in ('.kibana_1','wazuh-alerts-test','soc-customer-1-events','soc-customer-2-events','.opendistro_security','soc-customer-test-events')])
        self.assertIn('soc-customer-2-events',result);self.assertNotIn('.opendistro_security',result);self.assertNotIn('soc-customer-test-events',result)

@override_settings(SECURE_SSL_REDIRECT=False,SOC_MFA_REQUIRED=False)
class AdvancedReviewTests(TestCase):
    def setUp(self):
        from django.contrib.auth.models import Group
        self.c=Client.objects.create(name='Allowed',code='allowed');other=Client.objects.create(name='Other',code='other')
        self.d=Device.objects.create(site=Site.objects.create(client=self.c,name='Office',code='office'),name='FW',vendor='opnsense',zenarmor_enabled=True)
        self.hidden=Device.objects.create(site=Site.objects.create(client=other,name='Private',code='private'),name='Private',vendor='opnsense',zenarmor_enabled=True)
        self.user=get_user_model().objects.create_user('reviewer');self.user.groups.add(Group.objects.get(name='SOC Operador'))
        access=StaffAccess.objects.create(user=self.user,role='operator');access.clients.add(self.c);self.client.force_login(self.user)
    def data(self):
        from .advanced_views import revision
        return {'note':'Revisión manual documentada del listado global de exenciones. Referencia de laboratorio.','valid_until':(timezone.now()+timedelta(days=7)).isoformat(),'revision':revision(self.d)}
    def test_foreign_review_and_stale_revision_rejected(self):
        with patch('core.advanced_views.mfa_fresh',return_value=True):
            self.assertEqual(self.client.post(f'/devices/{self.hidden.pk}/advanced/',self.data()).status_code,404)
            data=self.data();data['revision']='old';self.client.post(f'/devices/{self.d.pk}/advanced/',data)
        self.assertFalse(AdvancedReview.objects.exists())
    def test_manual_declaration_does_not_become_api_proof_and_mfa_required(self):
        with patch('core.advanced_views.mfa_fresh',return_value=False):
            response=self.client.post(f'/devices/{self.d.pk}/advanced/',self.data());self.assertIn('/security/mfa/',response['Location'])
        self.assertFalse(AdvancedReview.objects.exists())
        with patch('core.advanced_views.mfa_fresh',return_value=True):self.client.post(f'/devices/{self.d.pk}/advanced/',self.data())
        self.assertEqual(AdvancedReview.objects.count(),1)
        self.assertContains(self.client.get(f'/devices/{self.d.pk}/advanced/'),'lectura automática pendiente')

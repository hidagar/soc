from datetime import timedelta
from unittest.mock import patch
from django.test import TestCase,override_settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.urls import reverse
from django.utils import timezone
from .models import Client,Site,Device,StaffAccess,ExposureFinding,ExposureCheck,Incident
from .exposure import assess,save_result,opnsense_rows,refresh_due,collect

@override_settings(SECURE_SSL_REDIRECT=False,SOC_MFA_REQUIRED=False)
class ExposureTests(TestCase):
    def setUp(self):
        self.c=Client.objects.create(name='Visible',code='visible')
        self.other=Client.objects.create(name='Oculto',code='hidden')
        self.s=Site.objects.create(client=self.c,name='Sede',code='sede')
        self.d=Device.objects.create(site=self.s,name='Firewall',vendor='opnsense',management_method='api')
        self.u=get_user_model().objects.create_user('operator')
        a=StaffAccess.objects.create(user=self.u,role='operator');a.clients.add(self.c)
        self.u.groups.add(Group.objects.get(name='SOC Operador'));self.client.force_login(self.u)
        self.rule={'uuid':'nat1','disabled':'0','interface':'wan','source.network':'any','destination.port':'3389','target':'192.168.1.2','local-port':'3389','protocol':'tcp'}
    def finding(self,rule=None):
        save_result(self.d,{'nat':assess(rule or self.rule,'opnsense','nat')},{'nat':{'status':'checked'}},'Consulta parcial')
        return ExposureFinding.objects.get(device=self.d)
    def test_disabled_inverted_and_no_redirect_are_not_exposure(self):
        for changes in ({'disabled':'1'},{'source.not':'1'},{'nordr':'1'},{'interface':'lan'}):
            self.assertEqual(assess({**self.rule,**changes},'opnsense','nat'),[])
    def test_sensitive_ranges_aliases_and_restricted_source(self):
        f=assess({**self.rule,'destination.port':'3300:3400'},'opnsense','nat')[0]
        self.assertEqual(f['severity'],'high')
        f=assess({**self.rule,'destination.port':'CUSTOM','local-port':'CUSTOM'},'opnsense','nat')[0]
        self.assertEqual(f['severity'],'medium');self.assertEqual(f['evidence']['port_interpretation'],'Alias sin resolver')
        f=assess({**self.rule,'source.network':'192.0.2.0/24'},'opnsense','nat')[0]
        self.assertEqual(f['severity'],'medium')
    def test_management_and_internal_broad_rule(self):
        r={'uuid':'fw1','enabled':'1','action':'pass','direction':'in','interface':'wan','source_net':'any','destination_net':'(self)','destination_port':'443','protocol':'tcp'}
        self.assertEqual(assess(r,'opnsense','filter')[0]['kind'],'management')
        self.assertEqual(assess({**r,'interface':'lan','destination_net':'any','destination_port':''},'opnsense','filter')[0]['kind'],'broad_rule')
        self.assertEqual(assess({**r,'source_net':'TRUSTED'},'opnsense','filter'),[])
        self.assertEqual(assess({**r,'direction':'out'},'opnsense','filter'),[])
        self.assertEqual(assess({**r,'interface':''},'opnsense','filter'),[])
    def test_unifi_portforward(self):
        r={'_id':'u1','enabled':True,'pfwd_interface':'wan2','fwd':'10.0.0.2','dst_port':'9000','fwd_port':'22','proto':'tcp','src':'0.0.0.0/0'}
        f=assess(r,'unifi','nat')[0];self.assertEqual(f['severity'],'high');self.assertEqual(f['evidence']['destination'],'10.0.0.2')
        self.assertEqual(assess({**r,'enabled':False},'unifi','nat'),[])
    def test_failed_section_preserves_findings_complete_absence_removes(self):
        f=self.finding()
        save_result(self.d,{}, {'nat':{'status':'unavailable'}},'Error')
        f.refresh_from_db();self.assertTrue(f.present)
        save_result(self.d,{'nat':[]},{'nat':{'status':'checked'}},'Completo')
        f.refresh_from_db();self.assertFalse(f.present);self.assertIsNotNone(f.removed_at)
    def test_changed_or_reappeared_rule_invalidates_exception(self):
        f=self.finding();f.review='accepted';f.review_note='Negocio';f.review_until=timezone.now()+timedelta(days=2);f.save()
        self.finding();f.refresh_from_db();self.assertTrue(f.exception_active)
        self.finding({**self.rule,'target':'192.168.1.3'});f.refresh_from_db();self.assertEqual(f.review,'pending');self.assertTrue(f.history)
        f.review='accepted';f.review_until=timezone.now()+timedelta(days=2);f.save()
        save_result(self.d,{'nat':[]},{'nat':{'status':'checked'}},'')
        self.finding({**self.rule,'target':'192.168.1.3'});f.refresh_from_db();self.assertFalse(f.exception_active)
    def test_pagination_refuses_truncation_or_duplicate_pages(self):
        with patch('core.provisioning._api_request',side_effect=[{'total':2,'rows':[{'uuid':'a'}]},{'total':2,'rows':[{'uuid':'b'}]}]):
            self.assertEqual(len(opnsense_rows(None,'/api/firewall/filter/search_rule')),2)
        with patch('core.provisioning._api_request',return_value={'total':2,'rows':[{'uuid':'a'}]}):
            with self.assertRaises(ValueError):opnsense_rows(None,'/api/firewall/filter/search_rule')
        with patch('core.provisioning._api_request',return_value={'total':1000,'rows':[]}):
            with self.assertRaises(ValueError):opnsense_rows(None,'/api/firewall/filter/search_rule')
    def test_partial_collect_does_not_claim_full_check(self):
        # Missing API credential relation is unavailable, with no disclosure of errors/secrets.
        sections,coverage,notes=collect(self.d)
        self.assertFalse(sections);self.assertEqual(coverage['nat']['status'],'unavailable')
        self.assertNotIn('encrypted',notes)
    def test_legacy_nat_lockout_surplus_is_narrowly_recognized(self):
        data={'total':1,'rows':[{'uuid':'lockout_0','interface':'lan','target':''},{'uuid':'real','interface':'wan','target':'10.0.0.2'}]}
        with patch('core.provisioning._api_request',return_value=data):
            self.assertEqual(len(opnsense_rows(None,'/api/firewall/d_nat/search_rule')),2)
        data['rows'][0]['interface']='wan'
        with patch('core.provisioning._api_request',return_value=data):
            with self.assertRaises(ValueError):opnsense_rows(None,'/api/firewall/d_nat/search_rule')
    def test_review_expiry_history_and_stale_form(self):
        f=self.finding();url=reverse('exposure_detail',args=[f.pk])
        data={'review':'accepted','note':'Servicio requerido por contrato','until':timezone.localtime(timezone.now()+timedelta(days=2)).strftime('%Y-%m-%dT%H:%M'),'fingerprint':f.fingerprint}
        self.assertEqual(self.client.post(url,{**data,'until':''}).status_code,200)
        f.refresh_from_db();self.assertEqual(f.review,'pending')
        self.assertEqual(self.client.post(url,data).status_code,302)
        f.refresh_from_db();self.assertTrue(f.exception_active);self.assertEqual(f.history[0]['actor'],'operator')
        self.finding({**self.rule,'target':'192.168.1.5'})
        self.client.post(url,data);f.refresh_from_db();self.assertEqual(f.review,'pending')
        f.review='accepted';f.review_until=timezone.now()-timedelta(days=1);f.save()
        self.assertContains(self.client.get(reverse('exposure_list')),f.title)
    def test_incident_creation_is_idempotent_and_correctly_scoped(self):
        f=self.finding();url=reverse('exposure_detail',args=[f.pk]);data={'action':'incident','fingerprint':f.fingerprint}
        self.assertEqual(self.client.post(url,data).status_code,302)
        self.client.post(url,data);self.assertEqual(Incident.objects.count(),1)
        i=Incident.objects.get();self.assertEqual(i.client,self.c);self.assertEqual(i.device,self.d)
    def test_foreign_access_and_reader_mutations_denied(self):
        f=self.finding();s=Site.objects.create(client=self.other,name='Privada',code='privada');d=Device.objects.create(site=s,name='Secreto',vendor='opnsense')
        save_result(d,{'nat':assess(self.rule,'opnsense','nat')},{'nat':{'status':'checked'}},'')
        foreign=ExposureFinding.objects.get(device=d)
        self.assertNotContains(self.client.get(reverse('exposure_list')),'Secreto')
        self.assertEqual(self.client.get(reverse('exposure_detail',args=[foreign.pk])).status_code,404)
        self.assertEqual(self.client.post(reverse('exposure_recheck',args=[d.pk])).status_code,404)
        self.assertEqual(self.client.get(reverse('exposure_list'),{'client':self.other.pk}).status_code,404)
        self.u.groups.clear();self.u.groups.add(Group.objects.get(name='SOC Consulta'));a=self.u.soc_access;a.role='reader';a.save()
        self.assertEqual(self.client.get(reverse('exposure_detail',args=[f.pk])).status_code,200)
        self.assertEqual(self.client.post(reverse('exposure_detail',args=[f.pk]),{'action':'incident','fingerprint':f.fingerprint}).status_code,403)
        self.assertEqual(self.client.post(reverse('exposure_recheck',args=[self.d.pk])).status_code,403)
    def test_recheck_is_queued_and_rate_limited(self):
        self.finding();self.client.post(reverse('exposure_recheck',args=[self.d.pk]))
        self.assertIsNotNone(ExposureCheck.objects.get(device=self.d).requested_at)
        with patch('core.exposure.collect') as collector:
            self.assertEqual(refresh_due(),0);collector.assert_not_called()
        c=ExposureCheck.objects.get(device=self.d);c.checked_at=timezone.now()-timedelta(minutes=11);c.save()
        with patch('core.exposure.collect',return_value=({}, {},'No disponible')) as collector:
            self.assertEqual(refresh_due(),1);collector.assert_called_once()

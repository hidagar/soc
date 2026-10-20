from django.test import TestCase,override_settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.urls import reverse
from .exposure_context import alias_catalog,expand,interface_catalog
from .exposure import assess,save_result,port_risk
from .models import Client,Site,Device,StaffAccess,ExposureCheck,ExposureFinding

@override_settings(SECURE_SSL_REDIRECT=False,SOC_MFA_REQUIRED=False)
class ExposureContextTests(TestCase):
    def setUp(self):
        self.aliases={'ADMIN':{'enabled':True,'type':'port','content':['22','443']},'NESTED':{'enabled':True,'type':'port','content':['ADMIN','3389']},
            'EVERYWHERE':{'enabled':True,'type':'network','content':['0.0.0.0/0']},'DYNAMIC':{'enabled':True,'type':'url','content':['https://example.com']}}
        self.rule={'uuid':'fw','enabled':'1','action':'pass','interface':'opt1','source_net':'EVERYWHERE','destination_net':'(self)','destination_port':'NESTED'}
        self.c=Client.objects.create(name='Client',code='client');self.other=Client.objects.create(name='Other',code='other')
        site=Site.objects.create(client=self.c,name='Site',code='site');self.d=Device.objects.create(site=site,name='Firewall',vendor='opnsense')
        self.user=get_user_model().objects.create_user('operator');a=StaffAccess.objects.create(user=self.user,role='operator');a.clients.add(self.c)
        self.user.groups.add(Group.objects.get(name='SOC Operador'));self.client.force_login(self.user)
    def test_static_nested_ports_and_networks_raise_review_priority(self):
        result=assess(self.rule,'opnsense','filter',self.aliases,['opt1'])
        self.assertEqual(result[0]['kind'],'management');self.assertEqual(result[0]['severity'],'high')
        self.assertEqual(result[0]['evidence']['alias_resolution']['port']['values'],['22','443','3389'])
    def test_long_expanded_port_alias_does_not_hide_sensitive_port(self):
        ports=','.join([str(61000+i) for i in range(250)]+['3389'])
        self.assertGreater(len(ports),240)
        self.assertEqual(port_risk(ports),'sensitive')
    def test_cycles_dynamic_dns_disabled_and_size_are_unknown(self):
        self.aliases['CYCLE']={'enabled':True,'type':'port','content':['CYCLE']}
        self.aliases['DNS']={'enabled':True,'type':'host','content':['example.com']}
        self.aliases['DISABLED']={'enabled':False,'type':'port','content':['22']}
        self.aliases['HUGE']={'enabled':True,'type':'port','content':['22']*257}
        for value,kind in [('CYCLE','port'),('DNS','network'),('DISABLED','port'),('HUGE','port'),('DYNAMIC','network')]:self.assertIsNone(expand(value,self.aliases,kind))
    def test_alias_catalog_retains_no_password_or_arbitrary_fields(self):
        row={'enabled':'1','name':'ADMIN','type':{'port':{'selected':'1'}},'content':{'22':{'selected':'1'}},'password':'SECRET','username':'SECRET'}
        catalog=alias_catalog({'alias':{'aliases':{'alias':{'uuid':row}}}})
        self.assertNotIn('SECRET',str(catalog));self.assertEqual(expand('ADMIN',catalog,'port'),['22'])
    def test_alias_catalog_rejects_duplicate_names_and_wrong_shape(self):
        row={'name':'ADMIN','type':'port','content':'22','enabled':'1'}
        with self.assertRaises(ValueError):alias_catalog({'alias':{'aliases':{'alias':{'a':row,'b':row}}}})
        with self.assertRaises(ValueError):alias_catalog({})
    def test_interfaces_explicit_only_no_guess_from_opt_name(self):
        literal={**self.rule,'source_net':'any','destination_port':'22'}
        self.assertFalse(assess(literal,'opnsense','filter'))
        self.assertTrue(assess(literal,'opnsense','filter',external_interfaces=['opt1']))
        catalog=interface_catalog({'interfaces':{'items':[{'id':'opt1','text':'Private transit','secret':'SECRET'}]}})
        self.assertNotIn('SECRET',str(catalog));self.assertEqual(catalog[0]['id'],'opt1')
        self.assertEqual(interface_catalog({'interfaces':{'items':[{'value':'opt2','label':'Transit','count':2,'type':'interface'}]}})[0]['id'],'opt2')
    def test_unresolved_rule_and_failed_catalog_preserve_previous_findings(self):
        findings=assess(self.rule,'opnsense','filter',self.aliases,['opt1'])
        save_result(self.d,{'filter':findings},{'filter':{'status':'checked'}},'Initial')
        finding=ExposureFinding.objects.get(device=self.d)
        for coverage in ({'status':'checked','unresolved_rules':['fw']},{'status':'checked','preserve_unseen':True}):
            save_result(self.d,{'filter':[]},{'filter':coverage},'Unknown')
            finding.refresh_from_db();self.assertTrue(finding.present)
        save_result(self.d,{'filter':[]},{'filter':{'status':'checked'}},'Complete')
        finding.refresh_from_db();self.assertFalse(finding.present)
    def test_operator_interfaces_scope_validation_and_readonly(self):
        path=reverse('exposure_interfaces',args=[self.d.pk])
        self.client.post(path,{'interfaces':'opt1,opt2'})
        self.assertEqual(ExposureCheck.objects.get(device=self.d).external_interfaces,['opt1','opt2'])
        self.client.post(path,{'interfaces':'../../etc/passwd'})
        self.assertEqual(ExposureCheck.objects.get(device=self.d).external_interfaces,['opt1','opt2'])
        site=Site.objects.create(client=self.other,name='Other',code='other');other=Device.objects.create(site=site,name='Other',vendor='opnsense')
        self.assertEqual(self.client.post(reverse('exposure_interfaces',args=[other.pk]),{'interfaces':'opt1'}).status_code,404)
        self.user.soc_access.role='reader';self.user.soc_access.save()
        self.assertEqual(self.client.post(path,{'interfaces':'opt3'}).status_code,403)

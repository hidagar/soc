from datetime import timedelta
from unittest.mock import patch
from django.test import TestCase,override_settings
from django.contrib.auth import get_user_model
from django.utils import timezone
from .models import Client,Site,Device,StaffAccess,SecurityEvidence,Asset,ExportConfiguration
from .vpn_security import VpnAccessEvent,parse,record,analysis

@override_settings(SECURE_SSL_REDIRECT=False,SOC_MFA_REQUIRED=False)
class InvestigationTests(TestCase):
    def setUp(self):
        self.a=Client.objects.create(name='Visible',code='visible')
        self.b=Client.objects.create(name='Secreto',code='secret')
        self.da=Device.objects.create(name='Firewall A',vendor='opnsense',site=Site.objects.create(client=self.a,name='Sede A',code='a'))
        self.db=Device.objects.create(name='Firewall secreto',vendor='opnsense',site=Site.objects.create(client=self.b,name='Sede B',code='b'))
        self.user=get_user_model().objects.create_user('reader')
        grant=StaffAccess.objects.create(user=self.user,role='reader');grant.clients.add(self.a)
        self.client.force_login(self.user)
    def evidence(self,uid='one',device=None,**kwargs):
        fields=dict(device=device or self.da,observed_at=timezone.now(),engine='suricata',signature='Prueba de laboratorio',action='blocked',source_ip='8.8.8.8',destination_ip='10.0.0.2')
        fields.update(kwargs)
        return SecurityEvidence.objects.create(uid=uid,**fields)
    def test_ip_scope_invalid_and_private_address(self):
        self.evidence();self.evidence('hidden',self.db,signature='Dato secreto')
        response=self.client.get('/operations/investigation/ip/',{'ip':'8.8.8.8'})
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.context['metrics']['total'],1)
        self.assertNotContains(response,'Dato secreto')
        self.assertEqual(self.client.get('/operations/investigation/ip/',{'ip':'8.8.8.8','client':self.b.pk}).status_code,404)
        self.assertEqual(self.client.get('/operations/investigation/ip/',{'ip':'<script>'}).status_code,404)
        self.assertEqual(self.client.get('/operations/investigation/ip/',{'ip':'10.0.0.2'}).status_code,200)
        self.client.logout();self.assertEqual(self.client.get('/operations/investigation/').status_code,302)
    def test_country_query_uses_all_events_not_recent_twenty_and_paginates(self):
        for i in range(55):self.evidence(str(i),geography={'country_code':'US'})
        self.evidence('elsewhere',geography={'country_code':'ES'})
        r=self.client.get('/operations/investigation/',{'country':'US','page':'2'})
        self.assertEqual(r.context['metrics']['total'],55)
        self.assertEqual(len(r.context['page']),5)
    def test_reassignment_never_leaks_new_owner_metadata(self):
        self.evidence()
        self.da.site=self.db.site;self.da.save()
        self.assertEqual(self.client.get('/operations/investigation/ip/',{'ip':'8.8.8.8'}).status_code,404)
        self.assertEqual(self.client.get('/operations/map/data/').json()['total'],0)
    def test_identity_belongs_to_related_endpoint_and_is_escaped(self):
        asset=Asset.objects.create(device=self.da,ip='10.0.0.2',name='New DHCP name')
        self.evidence(asset=asset,identity={'confidence':'recent','label':'<script>old name</script>'})
        r=self.client.get('/operations/investigation/ip/',{'ip':'8.8.8.8'})
        self.assertContains(r,'&lt;script&gt;old name&lt;/script&gt;')
        self.assertNotContains(r,'New DHCP name')
        r=self.client.get('/operations/investigation/ip/',{'ip':'10.0.0.2'})
        self.assertEqual(r.context['targets'][0]['identity'],'Identidad histórica sin confirmar')
    def test_customer_gets_only_opted_in_aggregate_summary(self):
        self.evidence(signature='Technical confidential signature')
        access=StaffAccess.objects.get(user=self.user);access.role='customer';access.save()
        self.assertEqual(self.client.get('/operations/investigation/').status_code,403)
        self.assertNotContains(self.client.get('/cliente/'),'Vuestra seguridad')
        self.a.customer_live_map_enabled=True;self.a.save()
        r=self.client.get('/cliente/')
        self.assertContains(r,'Vuestra seguridad')
        self.assertNotContains(r,'Technical confidential signature')
        self.assertNotContains(r,'8.8.8.8')
    def test_unrelated_and_unknown_vpn_records_do_not_claim_success(self):
        self.assertIsNone(parse({'data':{'status':'success'},'decoder':{'name':'sshd'}}))
        self.assertEqual(parse({'decoder':{'name':'openvpn'},'data':{'status':'connected'}})['outcome'],'unknown')
        self.assertEqual(parse({'rule':{'groups':['openvpn','authentication_failed']}})['outcome'],'failed')
    def test_ingestion_deduplicates_vpn_without_changing_threat_counts(self):
        from .operations import ingest_events
        ExportConfiguration.objects.create(device=self.da,source_ip='1.1.1.1',receiver_ready=True)
        source={'id':'vpn-id','timestamp':timezone.now().isoformat(),'location':'1.1.1.1','decoder':{'name':'openvpn'},'data':{'status':'failed','srcip':'10.0.0.3','user':'do-not-store'},'full_log':'SECRET'}
        ingest_events([source,source])
        self.assertEqual(VpnAccessEvent.objects.count(),1)
        self.assertEqual(SecurityEvidence.objects.count(),0)
        row=VpnAccessEvent.objects.get()
        self.assertEqual(row.client_scope_id,self.a.pk)
        self.assertNotIn('SECRET',str(row.__dict__))
        self.assertNotIn('do-not-store',str(row.__dict__))
    def test_burst_requires_same_peer_device_and_time_window(self):
        now=timezone.now();start=now-timedelta(days=1)
        rows=[]
        for i in range(5):
            rows.append(VpnAccessEvent(uid=str(i),device=self.da,client_scope_id=self.a.pk,observed_at=now-timedelta(minutes=6-i),peer_ip='8.8.8.8',outcome='failed',protocol='openvpn'))
        rows.append(VpnAccessEvent(uid='ok',device=self.da,client_scope_id=self.a.pk,observed_at=now,peer_ip='8.8.8.8',outcome='success',protocol='openvpn'))
        titles=[n['title'] for n in analysis(rows,start)]
        self.assertIn('Fallos de autenticación repetidos',titles)
        self.assertIn('Acceso correcto después de fallos desde la misma IP',titles)
        rows[0].observed_at=now-timedelta(hours=2)
        self.assertNotIn('Fallos de autenticación repetidos',[n['title'] for n in analysis(rows,start)])
    def test_vpn_dashboard_filters_foreign_clients_and_future_records(self):
        for pk,dev,stamp in [('a',self.da,timezone.now()),('b',self.db,timezone.now()),('f',self.da,timezone.now()+timedelta(days=1))]:
            VpnAccessEvent.objects.create(uid=pk,device=dev,client_scope_id=dev.site.client_id,observed_at=stamp,peer_ip='8.8.8.8',outcome='failed',protocol='openvpn')
        r=self.client.get('/operations/vpn-security/')
        self.assertEqual(r.context['total'],1)
        self.assertNotContains(r,'Firewall secreto')
    def test_country_change_needs_real_baseline_and_frozen_owner(self):
        now=timezone.now();start=now-timedelta(days=1)
        old=VpnAccessEvent.objects.create(uid='old',device=self.da,client_scope_id=self.a.pk,observed_at=start-timedelta(days=1),peer_ip='8.8.4.4',outcome='success',protocol='openvpn',country='ES')
        new=VpnAccessEvent.objects.create(uid='new',device=self.da,client_scope_id=self.a.pk,observed_at=now,peer_ip='8.8.8.8',outcome='success',protocol='openvpn',country='US')
        title='País sin antecedentes en el histórico del firewall'
        self.assertNotIn(title,[n['title'] for n in analysis([new],start)])
        self.assertIn(title,[n['title'] for n in analysis([old,new],start)])
        new.client_scope_id=self.b.pk
        with self.assertRaises(ValueError):new.save()
    @patch('core.asn.lookup',return_value={'status':'found','label':'AS15169','number':15169,'organization':'<script>Example</script>','database_date':'2026-10-01','stale':False})
    def test_asn_lookup_only_after_scope_check_and_html_is_escaped(self,lookup):
        self.evidence()
        self.assertEqual(self.client.get('/operations/investigation/ip/',{'ip':'8.8.8.8','client':self.b.pk}).status_code,404)
        lookup.assert_not_called()
        r=self.client.get('/operations/investigation/ip/',{'ip':'8.8.8.8'})
        self.assertContains(r,'AS15169');self.assertContains(r,'&lt;script&gt;Example&lt;/script&gt;')
        self.assertContains(r,'https://db-ip.com')

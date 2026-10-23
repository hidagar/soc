from datetime import date,timedelta
from django.test import TestCase,override_settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.utils import timezone
from django.urls import reverse
from .models import Client,Site,Device,StaffAccess,CustomerPublication,WeeklyReport,DeviceHealth,DeviceObservation,Asset,SecurityEvidence,Incident
from .service_development import record_observation,monthly_context,monthly_pdf,intelligence_rows,is_outbound
from .operations_views import StaffForm
from .testing_access import collected_report

@override_settings(SECURE_SSL_REDIRECT=False,SOC_MFA_REQUIRED=False)
class ServiceDevelopmentTests(TestCase):
    def setUp(self):
        self.c=Client.objects.create(name='Visible',code='visible');self.other=Client.objects.create(name='Oculto',code='hidden')
        self.site=Site.objects.create(client=self.c,name='Sede',code='sede')
        self.device=Device.objects.create(site=self.site,name='Firewall',vendor='opnsense')
        self.user=get_user_model().objects.create_user('customer')
        self.access=StaffAccess.objects.create(user=self.user,role='customer');self.access.clients.add(self.c)
        self.client.force_login(self.user)
    def event(self,uid,**kw):
        defaults=dict(device=self.device,engine='suricata',signature='Malware test',action='allowed',observed_at=timezone.now()-timedelta(minutes=1))
        defaults.update(kw);return SecurityEvidence.objects.create(uid=uid,**defaults)
    def operator(self):
        self.access.role='operator';self.access.save();self.user.groups.add(Group.objects.get(name='SOC Operador'))
    def test_customer_only_reads_published_text(self):
        self.c.notes='CONFIDENTIAL SECRET';self.c.save()
        CustomerPublication.objects.create(client=self.c,title='Visible title',summary='Approved explanation',visible=True)
        CustomerPublication.objects.create(client=self.c,title='DRAFT SECRET',summary='Internal',visible=False)
        CustomerPublication.objects.create(client=self.other,title='OTHER SECRET',summary='Other',visible=True)
        response=self.client.get('/cliente/')
        self.assertContains(response,'Approved explanation')
        for text in ('CONFIDENTIAL SECRET','DRAFT SECRET','OTHER SECRET','Conexiones','Usuarios y permisos'):self.assertNotContains(response,text)
    def test_customer_internal_routes_are_denied_even_with_permission(self):
        self.user.groups.add(Group.objects.get(name='SOC Administrador'))
        for path in ('/clients/','/operations/intelligence/','/operations/protection/','/admin/','/devices/1/history/'):
            self.assertEqual(self.client.get(path).status_code,403,path)
        self.assertRedirects(self.client.get('/gestion/'),'/cliente/',fetch_redirect_response=False)
    def test_customer_mutations_denied(self):
        self.assertEqual(self.client.post('/cliente/',{}).status_code,403)
        self.assertEqual(self.client.post(reverse('customer_publish',args=[self.c.pk]),{}).status_code,403)
    def test_customer_reports_cannot_cross_tenants_or_open_drafts(self):
        mine=WeeklyReport.objects.create(client=self.c,week_start=date(2026,9,28))
        theirs=WeeklyReport.objects.create(client=self.other,week_start=date(2026,9,28),sent_at=timezone.now())
        for r in (mine,theirs):
            self.assertEqual(self.client.get(reverse('customer_weekly',args=[r.pk])).status_code,404)
            self.assertEqual(self.client.get(reverse('customer_weekly_pdf',args=[r.pk])).status_code,404)
        CustomerPublication.objects.create(client=self.c,title='Report',summary='Approved',visible=True,weekly_report=mine)
        # Una publicación que enlaza un borrador no lo publica: hace falta una recopilación completa.
        self.assertEqual(self.client.get(reverse('customer_weekly',args=[mine.pk])).status_code,404)
        WeeklyReport.objects.filter(pk=mine.pk).update(sources=['192.0.2.1']);mine.refresh_from_db();collected_report(mine)
        Incident.objects.create(client=self.c,site=self.site,device=self.device,title='PRIVATE INCIDENT TITLE',observed_at=timezone.make_aware(__import__('datetime').datetime(2026,9,29,12)))
        self.assertNotContains(self.client.get(reverse('customer_weekly',args=[mine.pk])),'PRIVATE INCIDENT TITLE')
        self.assertTrue(self.client.get(reverse('customer_weekly_pdf',args=[mine.pk])).content.startswith(b'%PDF'))
    def test_invalid_customer_global_access_fails_closed(self):
        self.access.all_clients=True;self.access.save()
        self.assertEqual(self.client.get('/cliente/').status_code,403)
    def test_inactive_client_cannot_enter(self):
        self.c.active=False;self.c.save();self.assertEqual(self.client.get('/cliente/').status_code,404)
    def test_staff_form_rejects_multiple_customer_companies(self):
        form=StaffForm({'username':'new','password':'AStrong!Pass989823','role':'customer','clients':[self.c.pk,self.other.pk],'active':True})
        self.assertFalse(form.is_valid());self.assertIn('clients',form.errors)
    def test_publication_form_rejects_other_client_report(self):
        self.operator()
        report=WeeklyReport.objects.create(client=self.other,week_start=date(2026,9,28))
        response=self.client.post(reverse('customer_publish',args=[self.c.pk]),dict(title='Test',summary='Safe',status='open',visible='on',weekly_report=report.pk))
        self.assertEqual(response.status_code,200);self.assertFalse(CustomerPublication.objects.exists())
    def test_reader_cannot_publish(self):
        self.access.role='reader';self.access.save()
        self.assertEqual(self.client.post(reverse('customer_publish',args=[self.c.pk]),{}).status_code,403)
    def test_observation_dedup_redaction_and_preserved_engine(self):
        health=DeviceHealth.objects.create(device=self.device,api_ok=True,engines={'Suricata':{'running':True,'mode':'ids','api_key':'SECRET','check':'SECRET'}})
        record_observation(self.device,health);record_observation(self.device,health)
        self.assertEqual(DeviceObservation.objects.count(),1);self.assertNotIn('SECRET',str(DeviceObservation.objects.first().snapshot))
        health.api_ok=False;health.engines={};record_observation(self.device,health)
        self.assertEqual(DeviceObservation.objects.count(),2)
        self.assertTrue(DeviceObservation.objects.first().snapshot['engines']['Suricata']['running'])
    def test_intelligence_recurrence_and_critical_asset(self):
        asset=Asset.objects.create(device=self.device,ip='10.0.0.4',critical=True)
        self.event('a',asset=asset,source_ip=asset.ip,destination_ip='8.8.8.8')
        self.event('b',asset=asset,source_ip=asset.ip,destination_ip='8.8.8.8',observed_at=timezone.now()-timedelta(days=2))
        rows,limited=intelligence_rows(self.c.pk)
        self.assertFalse(limited);self.assertEqual(rows[0]['count'],2);self.assertEqual(len(rows[0]['reasons']),4)
    def test_outbound_requires_private_source_global_destination(self):
        self.assertTrue(is_outbound('192.168.1.4','8.8.8.8'))
        for src,dst in [('8.8.8.8','10.0.0.1'),('10.0.0.1','192.168.1.1'),('bad','8.8.8.8')]:self.assertFalse(is_outbound(src,dst))
    def test_month_boundaries_and_policy_events_excluded(self):
        now=timezone.make_aware(__import__('datetime').datetime(2026,10,6,12))
        self.event('a',observed_at=now-timedelta(days=1))
        self.event('b',observed_at=now-timedelta(days=1),category='application_policy')
        self.event('c',observed_at=now+timedelta(days=1))
        context=monthly_context(self.c,date(2026,10,1),now)
        self.assertEqual(context['metrics']['total'],1);self.assertTrue(context['provisional'])
        self.assertTrue(monthly_pdf(context).startswith(b'%PDF'))
    def test_internal_views_remain_scoped_and_render(self):
        self.operator()
        for route,args in [('monthly_summary',[self.c.pk]),('device_history',[self.device.pk]),('intelligence',[]),('customer_publish',[self.c.pk])]:
            self.assertEqual(self.client.get(reverse(route,args=args)).status_code,200,route)
        self.assertEqual(self.client.get(reverse('monthly_summary',args=[self.other.pk])).status_code,404)
        self.assertEqual(self.client.get('/operations/intelligence/?client='+str(self.other.pk)).status_code,404)
    def test_intelligence_incident_is_idempotent_and_scoped(self):
        self.operator();event=self.event('abc')
        path=reverse('intelligence')
        for _ in range(2):self.assertEqual(self.client.post(path,{'evidence':event.uid}).status_code,302)
        self.assertEqual(Incident.objects.count(),1)
        other_site=Site.objects.create(client=self.other,name='Other',code='other')
        other_device=Device.objects.create(site=other_site,name='Other',vendor='opnsense')
        foreign=self.event('foreign',device=other_device)
        self.assertEqual(self.client.post(path,{'evidence':foreign.uid}).status_code,404)
    @override_settings(SOC_MFA_REQUIRED=True)
    def test_customer_requires_mfa(self):
        self.assertRedirects(self.client.get('/cliente/'),'/security/mfa/setup/',fetch_redirect_response=False)
    def test_customer_map_disabled_until_company_opt_in(self):
        self.assertEqual(self.client.get('/cliente/mapa/').status_code,404)
        self.assertEqual(self.client.get('/cliente/mapa/data/').status_code,404)
    def test_customer_map_is_aggregated_and_cannot_override_company(self):
        self.c.customer_live_map_enabled=True;self.c.save()
        self.event('mine',source_ip='8.8.8.8',destination_ip='10.0.0.4',signature='PRIVATE SIGNATURE',geography={'status':'located','country_code':'US','country':'United States','lat':40,'lon':-100,'peer_ip':'8.8.8.8','direction':'inbound'})
        site=Site.objects.create(client=self.other,name='Other',code='other');device=Device.objects.create(site=site,name='Other',vendor='opnsense')
        self.event('other',device=device,signature='OTHER PRIVATE')
        response=self.client.get('/cliente/mapa/data/?client='+str(self.other.pk));payload=response.json()
        self.assertEqual(payload['total'],1);self.assertEqual(payload['recent'],[])
        for secret in ('PRIVATE SIGNATURE','OTHER PRIVATE','8.8.8.8','/incidents/'):
            self.assertNotIn(secret,response.content.decode())
        page=self.client.get('/cliente/mapa/');self.assertEqual(page.status_code,200)
        self.assertNotContains(page,'name="client"');self.assertNotContains(page,'PRIVATE SIGNATURE')

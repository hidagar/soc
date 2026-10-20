import json,sys,types
from datetime import timedelta
from unittest.mock import patch,MagicMock
from django.test import TestCase,override_settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.urls import reverse
from django.utils import timezone
from .models import Client,Site,Device,StaffAccess,SecurityEvidence,WorkerState,ExportConfiguration
from .threat_map import map_data,peer_for,enrich_geography,backfill_map_history

@override_settings(SECURE_SSL_REDIRECT=False,SOC_MFA_REQUIRED=False)
class ThreatMapTests(TestCase):
    def setUp(self):
        self.c1=Client.objects.create(name='Visible',code='visible')
        self.c2=Client.objects.create(name='Privado',code='private')
        self.d1=Device.objects.create(site=Site.objects.create(client=self.c1,name='Sede visible',code='visible'),name='FW visible',vendor='opnsense')
        self.d2=Device.objects.create(site=Site.objects.create(client=self.c2,name='Sede privada',code='private'),name='FW privado',vendor='unifi')
        self.user=get_user_model().objects.create_user('limited')
        a=StaffAccess.objects.create(user=self.user,role='reader');a.clients.add(self.c1)
        self.user.groups.add(Group.objects.get(name='SOC Consulta'))
    def event(self,uid='1',device=None,**values):
        return SecurityEvidence.objects.create(uid=uid,device=device or self.d1,observed_at=timezone.now(),engine='zenarmor',signature='Malware/Virus',category='Malware',source_ip='8.8.8.8',destination_ip='192.168.1.2',action='blocked',**values)
    def test_auth_and_tenant_isolation_cover_page_data_and_explicit_client(self):
        self.event();self.event('2',self.d2)
        self.assertEqual(self.client.get(reverse('threat_map_data')).status_code,302)
        self.client.force_login(self.user)
        response=self.client.get(reverse('threat_map_data'))
        self.assertEqual(response.json()['total'],1)
        self.assertNotIn('Privado',response.content.decode())
        self.assertEqual(self.client.get(reverse('threat_map_data'),{'client':self.c2.pk}).status_code,404)
        response=self.client.get(reverse('threat_map'))
        self.assertContains(response,'Mapa de detecciones')
        self.assertNotContains(response,'FW privado')
    def test_private_outbound_and_public_sources_are_not_confused(self):
        e=self.event()
        self.assertEqual(peer_for(e),('8.8.8.8','inbound','source'))
        e.source_ip='192.168.1.2';e.destination_ip='1.1.1.1'
        self.assertEqual(peer_for(e),('1.1.1.1','outbound','destination'))
        e.destination_ip='192.168.1.3'
        self.assertEqual(peer_for(e),(None,'internal','none'))
        e.source_ip='127.0.0.1';e.destination_ip='169.254.1.2'
        self.assertEqual(peer_for(e),(None,'internal','none'))
    def test_unknown_geography_keeps_detection_counts_without_fake_points(self):
        e=self.event();e.geography={'status':'unknown','direction':'inbound'};e.save()
        result=map_data(self.c1)
        self.assertEqual(result['total'],1)
        self.assertEqual(result['blocked'],1)
        self.assertEqual(result['unknown_location'],1)
        self.assertEqual(result['points'],[])
    def test_application_policy_is_not_reported_as_an_attack(self):
        e=self.event();e.category='application_policy';e.save()
        self.assertEqual(map_data(self.c1)['total'],0)

    def test_noc_watch_uses_recent_real_evidence_and_current_filters(self):
        now=timezone.now()
        latest=self.event('latest',level=13)
        latest.observed_at=now-timedelta(minutes=2);latest.action='allowed';latest.save()
        old=self.event('old',level=14)
        old.observed_at=now-timedelta(minutes=16);old.save()
        policy=self.event('policy',level=15);policy.category='application_policy';policy.save()
        future=self.event('future',level=15);future.observed_at=now+timedelta(minutes=1);future.save()
        self.event('foreign',self.d2,level=15)
        result=map_data(self.c1)
        self.assertEqual(result['watch'],{'window_minutes':15,'total':1,'allowed':1,'critical':1})
        self.assertEqual(result['total'],2)
        self.assertEqual(result['recent'][0]['uid'],'latest')
        self.assertEqual(result['recent'][0]['level'],13)
        self.assertEqual(result['recent'][0]['observed_at'],latest.observed_at.isoformat())
        self.assertEqual(map_data(self.c1,action='blocked')['watch']['total'],0)

    def test_historic_country_totals_do_not_pretend_to_be_recent_activity(self):
        event=self.event('history')
        event.observed_at=timezone.now()-timedelta(hours=1)
        event.geography={'status':'located','country_code':'US','country':'Estados Unidos','lat':40,'lon':-100,'direction':'inbound'}
        event.save()
        result=map_data(self.c1)
        self.assertEqual(result['points'][0]['count'],1)
        self.assertEqual(result['points'][0]['recent_count'],0)
        self.assertEqual(result['watch']['total'],0)

    def test_noc_watch_remains_scoped_for_operator(self):
        self.event('mine',level=13);self.event('foreign',self.d2,level=15)
        self.client.force_login(self.user)
        result=self.client.get(reverse('threat_map_data')).json()
        self.assertEqual(result['watch']['critical'],1)
        self.assertEqual([event['uid'] for event in result['recent']],['mine'])
    def test_country_and_direction_filters_use_real_enriched_evidence(self):
        e=self.event();e.geography={'status':'located','country_code':'US','country':'Estados Unidos','direction':'inbound','lat':40,'lon':-100};e.save()
        self.assertEqual(map_data(self.c1,direction='outbound')['total'],0)
        result=map_data(self.c1,direction='inbound')
        self.assertEqual(result['countries'][0]['count'],1)
        self.assertEqual(result['points'][0]['code'],'US')
    def test_local_enrichment_preserves_event_identity_and_never_looks_up_private_ip(self):
        e=self.event();private=self.event('2');private.source_ip='192.168.1.3';private.save()
        reader=MagicMock();reader.metadata.return_value.build_epoch=1700000000
        reader.get.return_value={'country':{'iso_code':'US','names':{'es':'Estados Unidos'}},'location':{'latitude':40,'longitude':-100}}
        opener=MagicMock();opener.return_value.__enter__.return_value=reader
        with patch.dict(sys.modules,{'maxminddb':types.SimpleNamespace(open_database=opener)}):
            self.assertEqual(enrich_geography(),2)
        e.refresh_from_db();private.refresh_from_db()
        self.assertEqual(e.geography['status'],'located')
        self.assertEqual(private.geography['status'],'internal')
        reader.get.assert_called_once_with('8.8.8.8')
        self.assertEqual(SecurityEvidence.objects.count(),2)
        self.assertTrue(WorkerState.objects.get(name='geography').last_success_at)

    @patch('core.reporting.indexer_authorization',return_value='auth')
    @patch('core.reporting._search',return_value={'hits':{'hits':[]}})
    def test_history_backfill_is_bounded_scoped_and_stops_after_completion(self,search,auth):
        ExportConfiguration.objects.create(device=self.d1,source_ip='8.8.8.8',receiver_ready=True)
        self.assertEqual(backfill_map_history(),0)
        filters=search.call_args.args[0]['query']['bool']['filter']
        self.assertEqual(filters[0],{'terms':{'location':['8.8.8.8']}})
        from django.utils.dateparse import parse_datetime
        self.assertGreater((timezone.now()-parse_datetime(filters[2]['range']['timestamp']['gte'])).days,29)
        self.assertTrue(WorkerState.objects.get(name='map-history').details['completed_until'])
        backfill_map_history()
        search.assert_called_once()

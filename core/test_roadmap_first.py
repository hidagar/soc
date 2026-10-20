import copy
from datetime import timedelta,datetime,timezone as utc
from unittest.mock import patch
from django.test import TestCase,override_settings
from django.contrib.auth import get_user_model
from django.core.management import call_command,CommandError
from django.urls import reverse
from django.utils import timezone
from .models import (Client,Site,Device,ExportConfiguration,SourceOwnership,FirewallOnboarding,
    StaffAccess,Incident,WeeklyReport,CustomerPublication,AuthAttempt,UrgentMonitorCursor,SecurityEvidence,WorkerState)
from .testing_access import legacy_sources


@override_settings(SOC_MFA_REQUIRED=False,SECURE_SSL_REDIRECT=False)
class FirstRoadmapTests(TestCase):
    def setUp(self):
        self.now=timezone.now();self.week=timezone.localdate()-timedelta(days=timezone.localdate().weekday())
        self.a=Client.objects.create(name='A',code='a',urgent_alerts_enabled=True,report_email='a@example.test')
        self.b=Client.objects.create(name='B',code='b')
        self.sa=Site.objects.create(client=self.a,name='A',code='a')
        self.sb=Site.objects.create(client=self.b,name='B',code='b')
        self.da=Device.objects.create(site=self.sa,name='A FW',vendor='unifi')
        self.db=Device.objects.create(site=self.sb,name='B FW',vendor='unifi')
        ExportConfiguration.objects.create(device=self.da,source_ip='192.0.2.1',receiver_ready=True)
        ExportConfiguration.objects.create(device=self.db,source_ip='192.0.2.2',receiver_ready=True)
        legacy_sources()
        self.user=get_user_model().objects.create_user('reader',email='reader@example.test',password='A-strong-password-27!')
        access=StaffAccess.objects.create(user=self.user,role='reader');access.clients.add(self.a)

    def test_json_status_obeys_same_scope_as_device(self):
        FirewallOnboarding.objects.create(device=self.da)
        FirewallOnboarding.objects.create(device=self.db,verification_error='PRIVATE-B')
        self.client.force_login(self.user)
        self.assertEqual(self.client.get(f'/devices/{self.da.pk}/connect/status/').status_code,200)
        self.assertEqual(self.client.get(f'/devices/{self.db.pk}/connect/status/').status_code,404)

    def test_failed_login_with_existing_session_is_throttled(self):
        self.client.force_login(self.user)
        for _ in range(8):self.assertEqual(self.client.post('/login/',{'username':'victim@example.test','password':'wrong'}).status_code,200)
        self.assertEqual(AuthAttempt.objects.count(),8)
        self.assertEqual(self.client.post('/login/',{'username':'victim@example.test','password':'wrong'}).status_code,429)

    def test_real_success_clears_only_the_attempted_identity(self):
        self.client.post('/login/',{'username':'reader@example.test','password':'wrong'})
        self.assertEqual(AuthAttempt.objects.count(),1)
        self.assertEqual(self.client.post('/login/',{'username':'reader@example.test','password':'A-strong-password-27!'}).status_code,302)
        self.assertEqual(AuthAttempt.objects.count(),0)

    def test_public_html_and_pdf_use_published_customer_projection(self):
        from .models import ReportShare
        from .report_sharing import share_path
        report=WeeklyReport.objects.create(client=self.a,week_start=self.week,sources=['192.0.2.1'])
        private=Incident.objects.create(client=self.a,title='PRIVATE-INTERNAL',description='Hidden',observed_at=self.now)
        public=Incident.objects.create(client=self.a,title='INTERNAL-ORIGINAL',description='Hidden',observed_at=self.now)
        CustomerPublication.objects.create(client=self.a,incident=public,title='Approved summary',summary='Approved',visible=True)
        share=ReportShare.objects.create(report=report,expires_at=self.now+timedelta(days=1))
        # El PDF se genera al congelar la versión publicada (primera visita), no al descargarlo.
        with patch('core.report_pdf.render_report_pdf',return_value=b'%PDF-test') as render:
            page=self.client.get(share_path(share))
            self.assertContains(page,'Approved summary');self.assertNotContains(page,private.title);self.assertNotContains(page,public.title)
            download=self.client.get(share_path(share,download=True))
        self.assertEqual((download.status_code,download.content),(200,b'%PDF-test'))
        rows=render.call_args.kwargs['context_override']['incidents']
        self.assertEqual([r.title for r in rows],['Approved summary'])

    def results(self):
        return [{'hits':{'total':{'value':3,'relation':'eq'}},'aggregations':{'high':{'doc_count':2},'availability':{'doc_count':0},'security':{'doc_count':2,'allowed':{'doc_count':1},'blocked':{'doc_count':1}}}},
            {'hits':{'total':{'value':0,'relation':'eq'},'hits':[]}}]

    def test_partial_or_malformed_search_never_becomes_a_zero_report(self):
        from .reporting import collect_client_week
        for page,field,value in ((0,'timed_out',True),(0,'_shards',{'failed':1}),(1,'timed_out',True),(1,'_shards',{'failed':1}),(0,'aggregations',{})):
            responses=copy.deepcopy(self.results());responses[page][field]=value
            with patch('core.reporting._search',side_effect=responses),self.assertRaises(ValueError):
                collect_client_week(self.a,self.week,'auth')

    def test_successful_collection_keeps_original_id_and_scope(self):
        from .reporting import collect_client_week
        with patch('core.reporting._search',side_effect=self.results()) as search:
            values=collect_client_week(self.a,self.week,'auth')
        self.assertIn('id',search.call_args_list[1].args[0]['_source'])
        self.assertEqual(values['coverage']['collection_schema'],2)
        self.assertEqual(values['security_count'],2)

    def test_ownership_change_during_search_discards_the_collection(self):
        from .reporting import collect_client_week
        responses=iter(self.results())
        def search(*args):
            result=next(responses)
            if 'aggregations' not in result:
                self.da.site=self.sb;self.da.save()
            return result
        with patch('core.reporting._search',side_effect=search),self.assertRaises(ValueError):
            collect_client_week(self.a,self.week,'auth')

    def test_transfer_closes_old_interval_and_does_not_reassign_past(self):
        from .source_ownership import report_scope,owns_at
        before=timezone.now()-timedelta(seconds=1)
        self.da.site=self.sb;self.da.save()
        rows=list(SourceOwnership.objects.filter(source='192.0.2.1').order_by('valid_from'))
        self.assertEqual(len(rows),2);self.assertEqual(rows[0].valid_until,rows[1].valid_from)
        self.assertTrue(owns_at('192.0.2.1',self.a.pk,before));self.assertFalse(owns_at('192.0.2.1',self.b.pk,before))
        a_sources,a_filter,_=report_scope(self.a,self.week);b_sources,b_filter,_=report_scope(self.b,self.week)
        self.assertIn('192.0.2.1',a_sources);self.assertIn('192.0.2.1',b_sources)
        self.assertIn(rows[0].valid_until.isoformat(),str(a_filter));self.assertIn(rows[1].valid_from.isoformat(),str(b_filter))

    def test_bulk_transfer_without_history_is_rejected(self):
        from .source_ownership import report_scope
        Device.objects.filter(pk=self.da.pk).update(site=self.sb)
        for c in (self.a,self.b):
            with self.assertRaises(ValueError):report_scope(c,self.week)

    def test_unrelated_save_cannot_legalize_an_untracked_transfer(self):
        from .source_ownership import report_scope
        Device.objects.filter(pk=self.da.pk).update(site=self.sb)
        self.b.name='Renamed B';self.b.save()
        self.db.name='Renamed unrelated firewall';self.db.save()
        for c in (self.a,self.b):
            with self.assertRaises(ValueError):report_scope(c,self.week)
        self.assertEqual(SourceOwnership.objects.get(source='192.0.2.1').client_scope_id,self.a.pk)

    def test_reprovisioning_same_source_does_not_retire_ownership(self):
        before=SourceOwnership.objects.get(source='192.0.2.1')
        config=self.da.export_configuration;config.receiver_ready=False;config.save()
        config.receiver_ready=True;config.save()
        self.assertEqual(SourceOwnership.objects.filter(source='192.0.2.1').count(),1)
        self.assertEqual(SourceOwnership.objects.get(source='192.0.2.1').valid_from,before.valid_from)

    def test_baseline_does_not_assign_known_foreign_history(self):
        from django.apps import apps
        from importlib import import_module
        from .source_ownership import owns_at
        SecurityEvidence.objects.create(uid='old-owner',device=self.da,client_scope_id=self.b.pk,observed_at=self.now-timedelta(days=1),engine='unifi',signature='Old')
        SourceOwnership.objects.all().delete()
        import_module('core.migrations.0040_source_ownership_urgent_checkpoint').baseline(apps,None)
        self.assertFalse(owns_at('192.0.2.1',self.a.pk,self.now-timedelta(hours=1)))

    def test_foreign_delayed_event_is_not_ingested_for_the_new_client(self):
        from .operations import ingest_events
        stamp=self.now-timedelta(minutes=1);self.da.site=self.sb;self.da.save()
        event={'id':'late','timestamp':stamp.isoformat(),'location':'192.0.2.1','rule':{'level':10},'data':{'unifi':{'category':'Security','action':'allowed','ips_signature':'ET SCAN'}}}
        ingest_events([event])
        self.assertFalse(SecurityEvidence.objects.filter(wazuh_id='late').exists())

    def test_draft_without_new_collection_cannot_be_mailed(self):
        from .reporting import send_report
        self.a.weekly_reports_enabled=True;self.a.save()
        report=WeeklyReport.objects.create(client=self.a,week_start=self.week,sources=['192.0.2.1'])
        with patch('core.reporting.send_report_email') as send:self.assertFalse(send_report(report))
        send.assert_not_called()

    def test_known_older_evidence_is_a_visible_blocker_not_a_clean_zero(self):
        from .reporting import report_context,send_report
        from .source_ownership import coverage_metadata
        from .testing_access import collected_report
        SourceOwnership.objects.filter(source='192.0.2.1').update(valid_from=self.now)
        stamp=timezone.make_aware(datetime.combine(self.week,datetime.min.time()))
        SecurityEvidence.objects.create(uid='older',device=self.da,observed_at=stamp,engine='zenarmor',signature='Malware')
        metadata=coverage_metadata(self.a,self.week)
        self.assertTrue(metadata['ownership_pending'])
        report=WeeklyReport.objects.create(client=self.a,week_start=self.week,sources=['192.0.2.1'],coverage=metadata)
        collected_report(report)
        self.a.weekly_reports_enabled=True;self.a.save()
        self.assertEqual(report_context(report)['summary_title'],'Histórico pendiente de revisión')
        with patch('core.reporting.send_report_email') as send:self.assertFalse(send_report(report))
        send.assert_not_called()

    def test_critical_old_group_is_not_hidden_by_recent_routine_groups(self):
        from .service_development import intelligence_rows
        SecurityEvidence.objects.bulk_create([SecurityEvidence(uid=f'routine-{i}',client_scope_id=self.a.pk,device=self.da,
            observed_at=self.now-timedelta(seconds=1),engine='suricata',signature=f'Scan-{i}',action='blocked',level=5) for i in range(501)])
        SecurityEvidence.objects.create(uid='critical-old',device=self.da,observed_at=self.now-timedelta(days=2),engine='zenarmor',signature='Malware',action='allowed',level=15)
        rows,limited=intelligence_rows(self.a.pk,self.now)
        self.assertTrue(limited);self.assertEqual(rows[0]['signature'],'Malware')

    def test_partial_urgent_search_does_not_advance_cursor(self):
        from .urgent_alerts import scan_events
        start=self.now-timedelta(minutes=3);UrgentMonitorCursor.objects.create(pk=1,last_checked_at=start)
        with patch('core.urgent_alerts.indexer_authorization',return_value='auth'),patch('core.urgent_alerts._search',return_value={'timed_out':True,'hits':{'hits':[]}}),self.assertRaises(ValueError):scan_events(self.now)
        cursor=UrgentMonitorCursor.objects.get(pk=1)
        self.assertEqual(cursor.last_checked_at,start);self.assertEqual(cursor.checkpoint,{})

    def test_scan_failure_does_not_prevent_delivery(self):
        with patch('core.management.commands.poll_urgent_alerts.scan_events',side_effect=ValueError),patch('core.management.commands.poll_urgent_alerts.deliver_pending',return_value=0) as deliver,self.assertRaises(CommandError):
            call_command('poll_urgent_alerts')
        self.assertEqual(deliver.call_count,2)

    def test_fifty_thousand_candidates_resume_without_result_window_limit(self):
        from .urgent_alerts import scan_events,PAGE_SIZE,INDEXING_DELAY
        start=self.now-timedelta(minutes=3);UrgentMonitorCursor.objects.create(pk=1,last_checked_at=start)
        seen=[];fixed_ends=set()
        def search(query,authorization):
            self.assertNotIn('from',query)
            fixed_ends.add(query['query']['bool']['filter'][1]['range']['timestamp']['lt'])
            offset=int(query['search_after'][1])+1 if query.get('search_after') else 0
            values=[{'_source':{'id':str(i)},'sort':[self.now.isoformat(),str(i),'index']} for i in range(offset,min(offset+PAGE_SIZE,50000))]
            return {'hits':{'hits':values},'_shards':{'failed':0},'timed_out':False}
        with patch('core.urgent_alerts.indexer_authorization',return_value='auth'),patch('core.urgent_alerts._search',side_effect=search),patch('core.urgent_alerts._record_event',side_effect=lambda h,*a:seen.append(h['_source']['id']) or False):
            for _ in range(60):
                scan_events(self.now,pages=2)
                if not UrgentMonitorCursor.objects.get(pk=1).checkpoint:break
        self.assertEqual(len(seen),50000);self.assertEqual(len(set(seen)),50000)
        self.assertEqual(len(fixed_ends),1)
        self.assertEqual(UrgentMonitorCursor.objects.get(pk=1).last_checked_at,self.now-INDEXING_DELAY)

    def test_source_change_keeps_existing_reconciliation_progress(self):
        from .operations import reconcile_security
        checkpoint={'start':(self.now-timedelta(days=3)).isoformat(),'end':(self.now-timedelta(days=2)).isoformat(),'after':['stamp','id','index'],'source_signature':'old','sources':['192.0.2.1']}
        WorkerState.objects.create(name='security-reconciliation',details=checkpoint)
        with patch('core.reporting.indexer_authorization',return_value='auth'),patch('core.reporting._search',return_value={'hits':{'hits':[]}}) as search:reconcile_security(self.now)
        query=search.call_args.args[0]
        self.assertEqual(query['search_after'],checkpoint['after']);self.assertEqual(query['query']['bool']['filter'][2]['range']['timestamp']['gte'],checkpoint['start'])

from datetime import timedelta
from unittest.mock import patch
from django.test import TestCase, override_settings
from django.utils import timezone
from django.urls import reverse
from django.contrib.auth import get_user_model
from .models import Client,Site,Device,ExportConfiguration,WeeklyReport,Incident,OperationalIssue
from .reporting import refresh_current_reports
from .testing_access import workflow_access

@override_settings(SECURE_SSL_REDIRECT=False,SOC_MFA_REQUIRED=False)
class ReportFreshnessTests(TestCase):
    def setUp(self):
        self.c=Client.objects.create(name='Rosello',code='rosello')
        self.other=Client.objects.create(name='Otro cliente',code='other')
        s=Site.objects.create(client=self.c,name='Llubi',code='llubi')
        d=Device.objects.create(site=s,name='OPNsense',vendor='opnsense')
        ExportConfiguration.objects.create(device=d,source_ip='192.0.2.10',receiver_ready=True)
        self.today=timezone.localdate()
        self.monday=self.today-timedelta(days=self.today.weekday())
        self.user=get_user_model().objects.create_user('viewer')
        workflow_access(self.user,reader=True)
        self.client.force_login(self.user)

    def test_default_shows_current_incident_even_if_previous_report_exists(self):
        WeeklyReport.objects.create(client=self.c,week_start=self.monday-timedelta(days=7))
        Incident.objects.create(client=self.c,title='Malware/Virus actual',description='Bloqueado',observed_at=timezone.now())
        Incident.objects.create(client=self.other,title='Secreto otro cliente',description='X')
        response=self.client.get(reverse('weekly_report',args=[self.c.pk]))
        self.assertContains(response,'Malware/Virus actual')
        self.assertContains(response,'Semana en curso')
        self.assertNotContains(response,'Secreto otro cliente')
        response=self.client.get(reverse('weekly_report',args=[self.c.pk]),{'week':(self.monday-timedelta(days=7)).isoformat()})
        self.assertNotContains(response,'Malware/Virus actual')

    @patch('core.reporting.indexer_authorization',return_value='auth')
    @patch('core.reporting.collect_client_week')
    def test_refresh_updates_draft_and_throttles_without_touching_sent_history(self,collect,auth):
        previous=WeeklyReport.objects.create(client=self.c,week_start=self.monday-timedelta(days=7),sent_at=timezone.now(),security_count=7)
        collect.return_value={'sources':['192.0.2.10'],'security_count':4,'blocked_count':4,'findings':[{'description':'Malware/Virus','asset_ip':'192.168.0.53'}]}
        self.assertEqual(refresh_current_reports(),1)
        r=WeeklyReport.objects.get(client=self.c,week_start=self.monday)
        self.assertEqual(r.security_count,4)
        self.assertEqual(r.findings[0]['asset_ip'],'192.168.0.53')
        self.assertEqual(refresh_current_reports(),0)
        collect.assert_called_once()
        previous.refresh_from_db()
        self.assertEqual(previous.security_count,7)
        r.sent_at=timezone.now();r.save()
        self.assertEqual(refresh_current_reports(now=timezone.now()+timedelta(minutes=20)),0)

    @patch('core.reporting.indexer_authorization',return_value='auth')
    @patch('core.reporting.collect_client_week',side_effect=TimeoutError)
    def test_failed_refresh_preserves_evidence_and_flags_the_failure(self,collect,auth):
        r=WeeklyReport.objects.create(client=self.c,week_start=self.monday,security_count=4,collected_at=timezone.now()-timedelta(hours=1))
        self.assertEqual(refresh_current_reports(),0)
        r.refresh_from_db()
        self.assertEqual(r.security_count,4)
        self.assertTrue(OperationalIssue.objects.filter(key=f'platform:report-refresh:{self.c.pk}',active=True).exists())

from unittest.mock import patch
from django.test import TestCase,override_settings,Client as Browser
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from .models import Client,Site,Device,OpnsenseConnection,ExportConfiguration,ZenarmorExportRequest
from .zenarmor_export import queue,configure,refresh_due,ExportError
from .testing_access import workflow_access
from .security import decrypt

@override_settings(SOC_MFA_REQUIRED=False,SECURE_SSL_REDIRECT=False)
class ZenarmorExportTests(TestCase):
    def setUp(self):
        self.company=Client.objects.create(name='Office',code='zen-export')
        self.site=Site.objects.create(client=self.company,name='Office',code='office')
        self.device=Device.objects.create(site=self.site,name='FW',vendor='opnsense',management_method='api',zenarmor_enabled=True)
        OpnsenseConnection.objects.create(device=self.device,api_url='https://fw.test')
        self.config=ExportConfiguration.objects.create(device=self.device,source_ip='198.51.100.70',destination='172.20.10.20',port=5514,status='configured',receiver_ready=True)
        self.before={'enabled':False,'syslogServerIpAddress':'','syslogServerPort':514,'syslogServerProtocol':'UDP','indexes':['conn']}
        self.current=dict(self.before);self.paths=[];self.posts=[];self.license='soho'
    def api(self,connection,path,payload=None):
        self.paths.append(path)
        if path.endswith('license_detail'):return {'success':True,'license':self.license}
        if path.endswith('reporting_data'):return {'streamReporting':self.current.copy()}
        if path.endswith('stream_reporting'):
            self.posts.append(payload);self.current=payload['streamReporting'].copy();return {'error':False}
        raise AssertionError(path)
    def test_licensed_setup_preserves_categories_and_encrypted_previous(self):
        row=queue(self.device);configure(row,self.api);row.save()
        self.assertEqual(row.status,'configured');self.assertEqual(self.current['indexes'],['conn','alert'])
        self.assertEqual(self.current['syslogServerIpAddress'],self.config.destination)
        self.assertEqual(len(self.posts),1);self.assertEqual(__import__('json').loads(decrypt(row.encrypted_previous)),self.before)
        self.assertIn('Falta validar',row.note)
    def test_unlicensed_unknown_and_home_never_write(self):
        for license in ('free','home',None,'new-unknown'):
            self.license=license;row=queue(self.device);configure(row,self.api)
            self.assertEqual(row.status,'waiting_license');self.assertEqual(self.posts,[])
    def test_existing_foreign_destination_is_preserved(self):
        self.current={**self.before,'enabled':True,'syslogServerIpAddress':'foreign.test'}
        with self.assertRaises(ExportError):configure(queue(self.device),self.api)
        self.assertEqual(self.posts,[])
    def test_already_configured_is_idempotent_even_port_is_string(self):
        self.current={**self.before,'enabled':True,'syslogServerIpAddress':self.config.destination,'syslogServerPort':'5514','indexes':['alert','conn']}
        row=queue(self.device);configure(row,self.api)
        self.assertEqual(row.status,'configured');self.assertEqual(self.posts,[])
    def test_unknown_stream_fields_and_changed_settings_are_not_overwritten(self):
        self.current={**self.before,'futureField':'unknown'}
        with self.assertRaises(ExportError):configure(queue(self.device),self.api)
        self.assertEqual(self.posts,[])
        self.current=dict(self.before);reads=0
        def changed(c,p,payload=None):
            nonlocal reads
            if p.endswith('reporting_data'):
                reads+=1
                if reads==2:self.current['indexes']=['tls']
            return self.api(c,p,payload)
        with self.assertRaises(ExportError):configure(queue(self.device),changed)
        self.assertEqual(self.posts,[])
    def test_receiver_must_be_prepared_and_target_allowed(self):
        for values in ({'receiver_ready':False},{'destination':'203.0.113.9'}):
            ExportConfiguration.objects.filter(pk=self.config.pk).update(**values)
            self.device.refresh_from_db()
            row=queue(self.device)
            if values.get('receiver_ready') is False:
                configure(row,self.api);self.assertEqual(row.status,'queued')
            else:
                with self.assertRaises(ExportError):configure(row,self.api)
            ExportConfiguration.objects.filter(pk=self.config.pk).update(receiver_ready=True,destination='172.20.10.20')
        self.assertEqual(self.posts,[])
    def test_worker_errors_are_redacted_and_waiting_requests_are_rate_limited(self):
        row=queue(self.device)
        def unavailable(c,p,payload=None):
            if p.endswith('license_detail'):return {'success':True,'license':'soho'}
            raise RuntimeError('SECRET')
        with patch('core.provisioning._api_request',side_effect=unavailable):self.assertEqual(refresh_due(),1)
        row.refresh_from_db();self.assertEqual(row.status,'error');self.assertNotIn('SECRET',row.note)
        row=queue(self.device);self.license=None
        with patch('core.provisioning._api_request',side_effect=self.api):
            self.assertEqual(refresh_due(),1);self.assertEqual(refresh_due(),0)
        row.refresh_from_db();self.assertEqual(row.status,'waiting_license')
    def test_ui_requires_connection_permission_csrf_and_recent_mfa(self):
        user=get_user_model().objects.create_user(username='operator');workflow_access(user,reader=False)
        user.user_permissions.add(Permission.objects.get(codename='manage_operations'))
        self.client.force_login(user);url=reverse('protection_device',args=[self.device.pk])
        with patch.object(type(user),'has_perm',side_effect=lambda p:p!='core.manage_connections'):
            self.assertEqual(self.client.post(url,{'action':'configure_zenarmor'}).status_code,403)
        user.user_permissions.add(Permission.objects.get(codename='manage_connections'))
        browser=Browser(enforce_csrf_checks=True);browser.force_login(user)
        self.assertEqual(browser.post(url,{'action':'configure_zenarmor'}).status_code,403)
        self.assertFalse(ZenarmorExportRequest.objects.exists())
        self.assertEqual(self.client.post(url,{'action':'configure_zenarmor'}).status_code,302)
        self.assertEqual(ZenarmorExportRequest.objects.get().status,'queued')
        self.assertContains(self.client.get(url),'Solicitar configuración de Zenarmor')
        self.assertContains(self.client.get(url),'Pendiente de comprobar')
    def test_view_refuses_configuration_without_recent_second_factor(self):
        from django.test import RequestFactory
        from .protection_views import protection_device
        user=get_user_model().objects.create_user(username='mfa-operator');workflow_access(user,reader=False)
        user.user_permissions.add(Permission.objects.get(codename='manage_operations'),Permission.objects.get(codename='manage_connections'))
        request=RequestFactory().post('/operations/protection/',{'action':'configure_zenarmor'});request.user=user
        with override_settings(SOC_MFA_REQUIRED=True),patch('core.security.mfa_fresh',return_value=False):
            self.assertEqual(protection_device(request,self.device.pk).status_code,403)
        self.assertFalse(ZenarmorExportRequest.objects.exists())

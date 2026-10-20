import hashlib,json,time,uuid
from datetime import timedelta
from unittest.mock import patch,MagicMock
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import TestCase,Client as Browser,override_settings
from django.urls import reverse
from django.utils import timezone
from .models import Client,Site,Device,StaffAccess,UserInvitation,SecureLogChannel,SecureLogReceipt,ExportConfiguration
from .security import decrypt
from .invitations import queue,send_pending
from .secure_logs import prepare

@override_settings(SECURE_SSL_REDIRECT=False,SOC_MFA_REQUIRED=False,SOC_PUBLIC_ORIGIN='https://soc.ibred.es')
class AccessOnboardingTests(TestCase):
    def setUp(self):
        self.customer=Client.objects.create(name='A',code='a')
        self.other=Client.objects.create(name='B',code='b')
        self.device=Device.objects.create(name='Firewall',vendor='opnsense',site=Site.objects.create(client=self.customer,name='Oficina',code='office'))
        self.admin=get_user_model().objects.create_user('manager')
        StaffAccess.objects.create(user=self.admin,role='manager',all_clients=True)
        self.admin.user_permissions.add(*Permission.objects.filter(codename__in=['manage_security','manage_connections','change_device']))
        self.client.force_login(self.admin)
        session=self.client.session;session.update({'soc_mfa_user':self.admin.pk,'soc_mfa_at':time.time()});session.save()
    def invite(self):
        user=get_user_model().objects.create_user('new-user',email='new@example.test');user.set_unusable_password();user.save()
        row=queue(user);token=decrypt(row.encrypted_token)
        return user,row,reverse('accept_invitation',args=[user.pk,token])
    def channel(self):
        row=prepare(self.device);row.receiver_ready=True;row.save(update_fields=['receiver_ready'])
        return row,reverse('secure_log_ingest',args=[row.pk]),'Bearer '+decrypt(row.encrypted_token)
    def test_create_queues_welcome_without_admin_password(self):
        r=self.client.post(reverse('staff'),{'username':'new','email':'hello@example.test','password':'ignored-input','role':'customer','clients':[self.customer.pk],'active':True})
        self.assertEqual(r.status_code,302)
        user=get_user_model().objects.get(username='new')
        self.assertFalse(user.has_usable_password());self.assertEqual(user.soc_invitation.status,'queued')
        self.assertNotContains(self.client.get(reverse('staff')),'name="password"')
    def test_welcome_requires_email_and_fresh_mfa(self):
        r=self.client.post(reverse('staff'),{'username':'new','role':'reader','all_clients':True,'active':True})
        self.assertEqual(r.status_code,200);self.assertFalse(get_user_model().objects.filter(username='new').exists())
        session=self.client.session;session['soc_mfa_at']=0;session.save()
        self.assertRedirects(self.client.post(reverse('staff'),{}),reverse('mfa_challenge'),fetch_redirect_response=False)
    def test_password_set_once_without_login_or_mfa_bypass(self):
        user,row,url=self.invite();browser=Browser()
        response=browser.get(url);self.assertEqual(response.status_code,302)
        self.assertNotIn(decrypt(row.encrypted_token),response['Location'])
        row.refresh_from_db();self.assertIsNone(row.accepted_at)
        target=response['Location']
        response=browser.post(target,{'new_password1':'A-secure-example!98372','new_password2':'A-secure-example!98372'})
        self.assertEqual(response.status_code,200);user.refresh_from_db();row.refresh_from_db()
        self.assertTrue(user.check_password('A-secure-example!98372'));self.assertIsNotNone(row.accepted_at)
        self.assertNotIn('_auth_user_id',browser.session)
        self.assertEqual(browser.get(url).status_code,400)
        self.assertEqual(browser.post(target,{'new_password1':'Other!7897987','new_password2':'Other!7897987'}).status_code,400)
    @override_settings(ALLOWED_HOSTS=['testserver','soc.ibred.es'],CSRF_TRUSTED_ORIGINS=['https://soc.ibred.es'])
    def test_activation_https_form_policy_and_real_csrf_validation(self):
        user,row,url=self.invite();browser=Browser(enforce_csrf_checks=True)
        redirect=browser.get(url,secure=True,HTTP_HOST='soc.ibred.es')
        self.assertEqual(redirect['Referrer-Policy'],'no-referrer')
        target=redirect['Location']
        self.assertNotIn(decrypt(row.encrypted_token),target)
        page=browser.get(target,secure=True,HTTP_HOST='soc.ibred.es')
        self.assertEqual(page['Referrer-Policy'],'same-origin')
        self.assertContains(page,'name="referrer" content="same-origin"')
        data={'new_password1':'A-secure-example!98372','new_password2':'A-secure-example!98372',
              'csrfmiddlewaretoken':page.cookies['csrftoken'].value}
        for origin in ('null','https://foreign.invalid'):
            response=browser.post(target,data,secure=True,HTTP_HOST='soc.ibred.es',HTTP_ORIGIN=origin)
            self.assertEqual(response.status_code,403)
            row.refresh_from_db();self.assertIsNone(row.accepted_at)
        response=browser.post(target,data,secure=True,HTTP_HOST='soc.ibred.es',HTTP_ORIGIN='https://soc.ibred.es',HTTP_REFERER='https://soc.ibred.es'+target)
        self.assertEqual(response.status_code,200)
        self.assertContains(response,'Acceso preparado')
        user.refresh_from_db();self.assertTrue(user.check_password(data['new_password1']))
        self.assertNotIn('_auth_user_id',browser.session)

    def test_expired_changed_email_inactive_and_resend_revoke_old_link(self):
        user,row,url=self.invite();browser=Browser()
        UserInvitation.objects.filter(pk=row.pk).update(expires_at=timezone.now()-timedelta(seconds=1))
        self.assertEqual(browser.get(url).status_code,400)
        row=queue(user);new_url=reverse('accept_invitation',args=[user.pk,decrypt(row.encrypted_token)])
        self.assertEqual(browser.get(url).status_code,400)
        user.email='changed@example.test';user.save();self.assertEqual(browser.get(new_url).status_code,400)
        user.email=row.recipient;user.is_active=False;user.save();self.assertEqual(browser.get(new_url).status_code,400)
    def test_activation_requires_session_csrf_and_strong_matching_passwords(self):
        user,row,url=self.invite();browser=Browser(enforce_csrf_checks=True)
        target=browser.get(url)['Location']
        self.assertEqual(browser.post(target,{'new_password1':'foo','new_password2':'foo'}).status_code,403)
        self.assertEqual(Browser().get(target).status_code,400)
        other=Browser();other.get(url)
        response=other.post(target,{'new_password1':'123','new_password2':'123'})
        self.assertEqual(response.status_code,200);user.refresh_from_db();self.assertFalse(user.has_usable_password())
    @patch('core.mail_delivery.send_customer_email',return_value='provider-reference')
    def test_worker_sends_welcome_without_copy_or_password_and_clears_secret(self,send):
        user,row,url=self.invite();send_pending()
        row.refresh_from_db();self.assertEqual(row.status,'accepted');self.assertEqual(row.encrypted_token,'')
        args=send.call_args.args
        self.assertEqual(args[0],user.email);self.assertIn('https://soc.ibred.es'+url,args[2]);self.assertNotIn('copy_to',send.call_args.kwargs)
        self.assertIn('ib-red empresas',args[3]);self.assertNotIn('IB-RED',args[3])
        send_pending();send.assert_called_once()
    def test_dynamic_origins_token_identity_and_dedup(self):
        channel,url,auth=self.channel();batch=str(uuid.uuid4());data={'batch_id':batch,'messages':['<13>Oct 19 12:00:00 fw app: normal activity']}
        with patch('core.log_delivery.socket.socket') as sock:
            for remote in ('8.8.8.8','1.1.1.1'):
                response=Browser().post(url,json.dumps(data),content_type='application/json',secure=True,HTTP_AUTHORIZATION=auth,REMOTE_ADDR=remote)
                self.assertEqual(response.status_code,202)
            sock.assert_not_called()
            self.assertTrue(response.json()['persisted'])
            self.assertEqual(SecureLogReceipt.objects.count(),1)
            data['messages']=['different'];self.assertEqual(Browser().post(url,json.dumps(data),content_type='application/json',secure=True,HTTP_AUTHORIZATION=auth).status_code,409)
    def test_invalid_credentials_disabled_device_and_reassignment_are_denied(self):
        channel,url,auth=self.channel();data=json.dumps({'batch_id':str(uuid.uuid4()),'messages':['hello']})
        browser=Browser()
        self.assertEqual(browser.post(url,data,content_type='application/json',secure=True).status_code,401)
        self.device.site.client=self.other;self.device.site.save()
        self.assertEqual(browser.post(url,data,content_type='application/json',secure=True,HTTP_AUTHORIZATION=auth).status_code,401)
        self.assertEqual(SecureLogReceipt.objects.count(),0)
    def test_reject_multiline_large_payload_http_and_pending_receiver(self):
        channel,url,auth=self.channel();browser=Browser()
        for messages in (['first\nsecond'],['x'*8193],['x']*33):
            self.assertEqual(browser.post(url,json.dumps({'batch_id':str(uuid.uuid4()),'messages':messages}),content_type='application/json',secure=True,HTTP_AUTHORIZATION=auth).status_code,400)
        self.assertEqual(browser.post(url,'{}',content_type='application/json',HTTP_AUTHORIZATION=auth).status_code,400)
        channel.receiver_ready=False;channel.save()
        self.assertEqual(browser.post(url,'{}',content_type='application/json',secure=True,HTTP_AUTHORIZATION=auth).status_code,503)
    def test_channel_preparation_does_not_change_existing_static_export(self):
        ExportConfiguration.objects.create(device=self.device,source_ip='8.8.8.8',status='configured')
        first=prepare(self.device);self.assertEqual(first.pk,prepare(self.device).pk)
        self.assertEqual(self.device.export_configuration.source_ip,'8.8.8.8')
    def test_ready_channel_is_in_reports_and_ingestion_scope(self):
        from .operations import source_map
        from .reporting import report_sources
        channel,url,auth=self.channel()
        owners,_=source_map();self.assertEqual(owners[channel.source_identity].pk,self.device.pk)
        self.assertIn(channel.source_identity,report_sources(self.customer));self.assertNotIn(channel.source_identity,report_sources(self.other))
    def test_wizard_has_dynamic_option_without_public_ip_field(self):
        from .models import FirewallOnboarding
        from .onboarding import MethodForm
        form=MethodForm(device=self.device,can_manage=True)
        self.assertIn('https',dict(form.fields['method'].choices))
        row=FirewallOnboarding.objects.create(device=self.device,method='https',step=4)
        self.assertRedirects(self.client.get(reverse('device_onboarding',args=[self.device.pk])),reverse('secure_log_setup',args=[self.device.pk]),fetch_redirect_response=False)
    def test_relay_package_is_protected_and_contains_unique_config(self):
        import io,zipfile
        channel,url,auth=self.channel()
        path=reverse('secure_log_setup',args=[self.device.pk])
        response=self.client.post(path,{'action':'download'})
        self.assertEqual(response.status_code,200)
        with zipfile.ZipFile(io.BytesIO(response.content)) as bundle:
            config=json.loads(bundle.read('soc-log-relay.json'))
            self.assertEqual(config['token'],auth[7:]);self.assertIn(str(channel.pk),config['url'])
            self.assertIn('soc_log_relay.py',bundle.namelist())
        session=self.client.session;session['soc_mfa_at']=0;session.save()
        self.assertEqual(self.client.post(path,{'action':'download'}).status_code,302)
    def test_bearer_ingestion_needs_no_browser_csrf_and_can_be_revoked(self):
        channel,url,auth=self.channel();body=json.dumps({'batch_id':str(uuid.uuid4()),'messages':['ordinary activity']})
        browser=Browser(enforce_csrf_checks=True)
        with patch('core.log_delivery.socket.socket'):
            self.assertEqual(browser.post(url,body,content_type='application/json',secure=True,HTTP_AUTHORIZATION=auth).status_code,202)
        channel.enabled=False;channel.save()
        self.assertEqual(browser.post(url,body,content_type='application/json',secure=True,HTTP_AUTHORIZATION=auth).status_code,401)
    def test_rate_limit_and_socket_error_do_not_prevent_durable_acceptance(self):
        channel,url,auth=self.channel();body=json.dumps({'batch_id':str(uuid.uuid4()),'messages':['ordinary activity']})
        browser=Browser()
        with patch('core.log_delivery.socket.socket',side_effect=OSError('unavailable')):
            self.assertEqual(browser.post(url,body,content_type='application/json',secure=True,HTTP_AUTHORIZATION=auth).status_code,202)
        self.assertEqual(SecureLogReceipt.objects.count(),1)
        SecureLogReceipt.objects.create(channel=channel,batch_id=uuid.uuid4(),digest='a'*64,bytes_count=10*1024*1024,messages_count=32)
        body=json.dumps({'batch_id':str(uuid.uuid4()),'messages':['ordinary activity']})
        self.assertEqual(browser.post(url,body,content_type='application/json',secure=True,HTTP_AUTHORIZATION=auth).status_code,429)
    @patch('core.mail_delivery.send_customer_email')
    def test_mail_timeout_is_not_automatically_resent(self,send):
        from .mail_delivery import MailDeliveryError
        user,row,url=self.invite();send.side_effect=MailDeliveryError('timeout')
        send_pending();send_pending();send.assert_called_once()
        row.refresh_from_db();self.assertEqual(row.status,'uncertain')
    def test_api_refresh_does_not_replace_https_export(self):
        from .models import FirewallOnboarding
        from .provisioning import provision_export
        channel=prepare(self.device)
        FirewallOnboarding.objects.create(device=self.device,method='https',step=5)
        self.assertEqual(provision_export(self.device).source_ip,channel.source_identity)
    def test_queued_zenarmor_configuration_cannot_overwrite_relay_destination(self):
        from .models import FirewallOnboarding,ZenarmorExportRequest
        from .zenarmor_export import configure
        FirewallOnboarding.objects.create(device=self.device,method='https',step=5)
        row=ZenarmorExportRequest.objects.create(device=self.device)
        api=MagicMock();configure(row,api)
        api.assert_not_called();self.assertEqual(row.status,'error');self.assertIn('reenviador',row.note)
    def test_https_transport_keeps_existing_api_for_inventory(self):
        self.device.management_method='api';self.device.save()
        response=self.client.post(reverse('device_onboarding',args=[self.device.pk]),{'method':'https','profile':'opnsense'})
        self.assertEqual(response.status_code,302);self.device.refresh_from_db()
        self.assertEqual(self.device.management_method,'api')

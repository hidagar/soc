import base64
import json
import os
from unittest.mock import patch
from cryptography.fernet import Fernet
from django.test import TestCase, SimpleTestCase, override_settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.urls import reverse
from . import hillstone_api as api
from .models import Client, Site, Device, HillstoneConnection, StaffAccess
from .testing_access import workflow_access

PAYLOAD={'success':True,'result':{'token':'SESSION-MUST-NOT-PERSIST','sysInfo':{'hw_platform':'SG6000-A','sw_version':'5.5R10P5','sn_number':'SERIAL-TEST','extra':'IGNORE'}}}

class TransportTests(SimpleTestCase):
    def test_real_stoneos_session_list_without_inventory(self):
        self.assertEqual(api.inventory({'success':True,'result':[{'token':'PRIVATE','role':'admin'}]}),{})
        for result in ([],[{'token':'a'},{'token':'b'}],[{}]):
            with self.assertRaises(api.HillstoneApiError):
                api.inventory({'success':True,'result':result})
    def test_inventory_does_not_return_session_or_unknown_fields(self):
        self.assertEqual(api.inventory(PAYLOAD),{'model':'SG6000-A','software_version':'5.5R10P5','serial_number':'SERIAL-TEST'})
    def test_denied_malformed_and_missing_inventory_rejected(self):
        for body in ({'success':False},[],{'success':True,'result':{}},{'success':True,'result':{'token':'x','sysInfo':{}}}):
            with self.assertRaises(api.HillstoneApiError): api.inventory(body)
    def test_https_only_and_no_embedded_credentials(self):
        for url in ('http://fw.test','https://user:pass@fw.test','https://fw.test/rest/login','https://fw.test/?x=1'):
            with self.assertRaises(api.HillstoneApiError): api.validate_url(url)
    def test_login_payload_bounded_and_inventory_only(self):
        with patch.object(api.request,'build_opener') as builder:
            response=builder.return_value.open.return_value.__enter__.return_value
            response.headers={'Content-Type':'application/json'}
            response.read.return_value=json.dumps(PAYLOAD).encode()
            data=api.check_connection('https://fw.test','soc','p a s s')
            req=builder.return_value.open.call_args.args[0]
            self.assertEqual(req.full_url,'https://fw.test/rest/login')
            self.assertEqual(req.method,'POST')
            sent=json.loads(req.data)
            self.assertEqual(base64.b64decode(sent['userName']),b'soc')
            self.assertEqual(base64.b64decode(sent['password']),b'p a s s')
            self.assertEqual(builder.return_value.open.call_args.kwargs['timeout'],10)
            response.read.assert_called_once_with(262145)
            self.assertNotIn('token',data)
            response.read.return_value=b'x'*262145
            with self.assertRaises(api.HillstoneApiError): api.check_connection('https://fw.test','soc','pass')
    def test_redirects_not_followed(self):
        self.assertIsNone(api.NoRedirect().redirect_request(None,None,302,'',{},'https://other.test'))

@override_settings(SECURE_SSL_REDIRECT=False,SOC_MFA_REQUIRED=False)
class ConnectionTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user=get_user_model().objects.create_user('hillstone-operator')
        workflow_access(cls.user)
        cls.user.user_permissions.add(Permission.objects.get(codename='manage_connections'))
        cls.customer=Client.objects.create(name='Test customer',code='hillstone')
        cls.site=Site.objects.create(client=cls.customer,name='Office',code='office')
        cls.device=Device.objects.create(site=cls.site,name='Firewall',vendor='hillstone')
    def setUp(self):
        self.client.force_login(self.user)
        self.url=reverse('hillstone_api',args=[self.device.pk])
        self.env=patch.dict(os.environ,{'SOC_PORTAL_SSH_KEY':Fernet.generate_key().decode()})
        self.env.start();self.addCleanup(self.env.stop)
    def save_connection(self):
        return self.client.post(self.url,{'action':'save','api_url':'https://fw.test','username':'soc','password':'PASSWORD-PRIVATE'})
    def test_save_encrypted_no_network_and_no_password_echo(self):
        with patch.object(api,'check_connection') as check:
            self.assertEqual(self.save_connection().status_code,302)
            check.assert_not_called()
        conn=HillstoneConnection.objects.get(device=self.device)
        self.assertNotIn('PASSWORD-PRIVATE',conn.encrypted_password)
        self.assertEqual(api.decrypt(conn.encrypted_password),'PASSWORD-PRIVATE')
        self.assertFalse(conn.last_ok)
        self.assertNotContains(self.client.get(self.url),'PASSWORD-PRIVATE')
    def test_discovery_does_not_activate_events(self):
        self.save_connection()
        with patch.object(api,'check_connection',return_value=api.inventory(PAYLOAD)):
            self.assertEqual(self.client.post(self.url,{'action':'test'}).status_code,200)
        self.device.refresh_from_db()
        self.assertEqual(self.device.model,'SG6000-A')
        self.assertEqual(self.device.software_version,'5.5R10P5')
        self.assertEqual(self.device.management_method,'api')
        self.assertEqual(self.device.integration,'pending')
        self.assertTrue(HillstoneConnection.objects.get(device=self.device).last_ok)
        with patch.object(api,'check_connection') as check:
            self.client.post(self.url,{'action':'test'});check.assert_not_called()
    def test_error_does_not_show_credentials_or_mark_ready(self):
        self.save_connection()
        with patch.object(api,'check_connection',side_effect=api.HillstoneApiError('Acceso rechazado.')):
            response=self.client.post(self.url,{'action':'test'})
        self.assertContains(response,'Acceso rechazado.')
        self.assertNotContains(response,'PASSWORD-PRIVATE')
        self.assertFalse(HillstoneConnection.objects.get(device=self.device).last_ok)
    def test_credentials_required_when_changing_destination(self):
        self.save_connection()
        response=self.client.post(self.url,{'action':'save','api_url':'https://other.test','username':'soc','password':''})
        self.assertContains(response,'Introduce la contraseña')
        self.assertEqual(HillstoneConnection.objects.get(device=self.device).api_url,'https://fw.test')
    def test_wrong_vendor_is_not_connectable(self):
        self.device.vendor='unifi';self.device.save()
        self.assertEqual(self.client.get(self.url).status_code,404)
    def test_permissions_and_customer_scope(self):
        reader=get_user_model().objects.create_user('hillstone-reader')
        workflow_access(reader,reader=True)
        self.client.force_login(reader)
        self.assertEqual(self.client.get(self.url).status_code,403)
        access=StaffAccess.objects.get(user=self.user)
        access.all_clients=False;access.save()
        self.client.force_login(self.user)
        self.assertEqual(self.client.get(self.url).status_code,404)
    def test_remove_preserves_event_configuration(self):
        self.save_connection()
        self.assertEqual(self.client.post(self.url,{'action':'remove'}).status_code,302)
        self.assertFalse(HillstoneConnection.objects.filter(device=self.device).exists())
    def test_csrf_required(self):
        from django.test import Client as HttpClient
        client=HttpClient(enforce_csrf_checks=True)
        client.force_login(self.user)
        response=client.post(self.url,{'action':'save','api_url':'https://fw.test','username':'soc','password':'PRIVATE'})
        self.assertEqual(response.status_code,403)
        self.assertFalse(HillstoneConnection.objects.filter(device=self.device).exists())

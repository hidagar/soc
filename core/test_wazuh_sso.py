import time
from django.test import TestCase,override_settings
from django.contrib.auth import get_user_model
from .models import StaffAccess,MfaProfile

@override_settings(SECURE_SSL_REDIRECT=False,SOC_WAZUH_PROXY_KEY='test-proxy-secret',SOC_MFA_REQUIRED=True)
class WazuhSsoTests(TestCase):
    def setUp(self):
        self.user=get_user_model().objects.create_user('analyst')
        self.access=StaffAccess.objects.create(user=self.user,role='reader',all_clients=True)
        self.profile=MfaProfile.objects.create(user=self.user,enabled=True,encrypted_secret='unused')
        self.client.force_login(self.user)
        self.mark()
    def mark(self):
        session=self.client.session
        session.update({'soc_mfa_user':self.user.pk,'soc_mfa_version':self.profile.version,'soc_mfa_at':time.time()})
        session.save()
    def check(self,**headers):
        return self.client.get('/security/wazuh/check/',HTTP_X_SOC_WAZUH_KEY='test-proxy-secret',**headers)
    def test_identity_is_server_derived_and_read_only(self):
        r=self.check(HTTP_X_PROXY_USER='admin',HTTP_X_PROXY_ROLES='admin')
        self.assertEqual(r.status_code,200)
        self.assertEqual(r['X-SOC-Wazuh-User'],f'soc-portal-{self.user.pk}')
        self.assertEqual(r['X-SOC-Wazuh-Roles'],'soc_portal_reader')
        self.assertEqual(r['X-SOC-Wazuh-Tenant'],'global')
    def test_secret_and_session_required(self):
        self.assertEqual(self.client.get('/security/wazuh/check/').status_code,403)
        self.client.logout();self.assertEqual(self.check().status_code,401)
    def test_mfa_missing_expired_or_revoked_rejected(self):
        session=self.client.session;session['soc_mfa_at']=0;session.save()
        self.assertEqual(self.check().status_code,401)
        self.mark();self.profile.version+=1;self.profile.save()
        self.assertEqual(self.check().status_code,401)
    def test_scoped_staff_denied(self):
        self.access.all_clients=False;self.access.save()
        self.assertEqual(self.check().status_code,403)
    def test_customer_denied_even_with_global_flag(self):
        self.access.role='customer';self.access.save()
        self.assertEqual(self.check().status_code,403)
    def test_entry_and_no_open_redirect(self):
        r=self.client.get('/security/wazuh/enter/',{'next':'https://evil.test'})
        self.assertEqual(r.status_code,302)
        self.assertEqual(r['Location'],'/wazuh/app/dashboards#/view/soc-general')
    def test_disabled_user_denied(self):
        self.user.is_active=False;self.user.save()
        self.assertEqual(self.check().status_code,401)

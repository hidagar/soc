from django.contrib.auth import authenticate,get_user_model
from django.db import IntegrityError,transaction
from django.test import TestCase,override_settings
from .operations_views import StaffForm
from .models import Client


@override_settings(SECURE_SSL_REDIRECT=False,SOC_MFA_REQUIRED=False)
class EmailLoginTests(TestCase):
    def setUp(self):
        self.user=get_user_model().objects.create_user('Ana Garcia',email='Ana@example.test',password='test-password-345')

    def test_email_case_and_whitespace_and_no_name_login(self):
        self.assertEqual(authenticate(username=' ANA@example.test ',password='test-password-345'),self.user)
        self.assertIsNone(authenticate(username='Ana Garcia',password='test-password-345'))
        self.assertIsNone(authenticate(username='Ana@example.test',password='wrong'))
        self.user.is_active=False;self.user.save()
        self.assertIsNone(authenticate(username='Ana@example.test',password='test-password-345'))

    def test_only_explicit_legacy_accounts_can_use_name_without_email(self):
        User=get_user_model()
        for name in ('kico','ibred','other'):
            user=User.objects.create_user(name,password='test-password-345')
            result=authenticate(username=name,password='test-password-345')
            self.assertEqual(result,user if name!='other' else None)
        user=User.objects.get(username='kico');user.email='kico@example.test';user.save()
        self.assertIsNone(authenticate(username='kico',password='test-password-345'))

    def test_database_rejects_duplicate_email_even_case_and_spaces(self):
        with self.assertRaises(IntegrityError),transaction.atomic():
            get_user_model().objects.create_user('duplicate',email=' ana@EXAMPLE.test ')

    def test_staff_validation_and_normalization(self):
        data={'username':'Otra persona','email':' ANA@example.test ','role':'reader','all_clients':True,'active':True}
        form=StaffForm(data)
        self.assertFalse(form.is_valid())
        self.assertIn('email',form.errors)
        data['email']=' OTHER@example.test '
        form=StaffForm(data)
        self.assertTrue(form.is_valid(),form.errors)
        self.assertEqual(form.cleaned_data['email'],'other@example.test')

    def test_portal_and_admin_share_email_login(self):
        self.user.is_staff=True;self.user.is_superuser=True;self.user.save()
        for path in ('/login/','/admin/login/'):
            self.client.logout()
            page=self.client.get(path)
            self.assertContains(page,'Correo electrónico')
            response=self.client.post(path,{'username':'ana@example.test','password':'test-password-345'})
            self.assertEqual(response.status_code,302)
            self.assertEqual(int(self.client.session['_auth_user_id']),self.user.pk)

    def test_duplicate_validation_allows_editing_same_user(self):
        form=StaffForm({'username':self.user.username,'email':'ANA@example.test','role':'reader','all_clients':True,'active':True},instance=self.user)
        self.assertTrue(form.is_valid(),form.errors)

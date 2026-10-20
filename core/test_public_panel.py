from .testing_access import workflow_access
from django.contrib.auth import get_user_model
from django.test import Client as HttpClient, TestCase, override_settings
from django.urls import reverse

from .models import Client


@override_settings(ALLOWED_HOSTS=['testserver', 'soc.ibred.es'], SECURE_SSL_REDIRECT=False,
                   CSRF_TRUSTED_ORIGINS=['https://soc.ibred.es'])
class PublicPanelAccessTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.operator = get_user_model().objects.create_user('panel-test', email='panel@example.test', password='test-only-password')
        workflow_access(cls.operator, reader=False)
        cls.customer = Client.objects.create(name='Private company sentinel', code='panel-test')

    def test_dashboard_and_customers_require_login(self):
        self.assertEqual(reverse('dashboard'), '/gestion/')
        for path in ('/gestion/', '/clients/', '/connections/', '/mail/'):
            with self.subTest(path=path):
                response = self.client.get(path, secure=True, HTTP_HOST='soc.ibred.es')
                self.assertEqual(response.status_code, 302)
                self.assertTrue(response.url.startswith('/login/'))
                self.assertNotIn(b'Private company sentinel', response.content)

    def test_login_works_with_https_csrf_and_redirects_to_dashboard(self):
        client = HttpClient(enforce_csrf_checks=True)
        response = client.get('/login/', secure=True, HTTP_HOST='soc.ibred.es')
        self.assertEqual(response.status_code, 200)
        token = response.cookies['csrftoken'].value
        response = client.post('/login/', {'username': 'panel@example.test', 'password': 'test-only-password',
                                           'csrfmiddlewaretoken': token}, secure=True,
                               HTTP_HOST='soc.ibred.es', HTTP_ORIGIN='https://soc.ibred.es')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, '/gestion/')
        response = client.get(response.url, secure=True, HTTP_HOST='soc.ibred.es')
        self.assertContains(response, 'Private company sentinel')

    def test_foreign_origin_cannot_modify_customer(self):
        client = HttpClient(enforce_csrf_checks=True)
        client.force_login(self.operator)
        response = client.get('/clients/new/', secure=True, HTTP_HOST='soc.ibred.es')
        token = response.cookies['csrftoken'].value
        response = client.post('/clients/new/', {'name': 'Unexpected company', 'code': 'unexpected',
                                                'csrfmiddlewaretoken': token}, secure=True,
                               HTTP_HOST='soc.ibred.es', HTTP_ORIGIN='https://foreign.invalid')
        self.assertEqual(response.status_code, 403)
        self.assertFalse(Client.objects.filter(code='unexpected').exists())

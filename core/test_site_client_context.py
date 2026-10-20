from .testing_access import workflow_access
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from .models import Client, Site


@override_settings(SECURE_SSL_REDIRECT=False)
class SiteClientContextTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.operator = get_user_model().objects.create_user('site-context-operator')
        workflow_access(cls.operator, reader=False)
        cls.customer = Client.objects.create(name='Conservas cliente seleccionado', code='selected')
        cls.other = Client.objects.create(name='Otro cliente ajeno al formulario', code='other')

    def setUp(self):
        self.client.force_login(self.operator)
        self.url = reverse('site_new') + f'?client={self.customer.pk}'
        self.data = {'name': 'Nueva sede', 'code': '', 'devices-TOTAL_FORMS': '0',
                     'devices-INITIAL_FORMS': '0', 'devices-MIN_NUM_FORMS': '0', 'devices-MAX_NUM_FORMS': '20'}

    def test_selected_customer_is_shown_without_other_customer_choices(self):
        response = self.client.get(self.url)
        self.assertContains(response, self.customer.name)
        self.assertNotContains(response, self.other.name)
        self.assertNotContains(response, '<select name="client"')
        self.assertContains(response, 'id="selected-client-name"')

    def test_site_remains_attached_to_context_even_if_posted_customer_is_changed(self):
        response = self.client.post(self.url, {**self.data, 'client': self.other.pk})
        site = Site.objects.get(name='Nueva sede')
        self.assertEqual(site.client_id, self.customer.pk)
        self.assertRedirects(response, reverse('site_detail', args=[site.pk]))

    def test_validation_retry_keeps_context_and_can_save_without_client_input(self):
        response = self.client.post(self.url, {**self.data, 'name': ''})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.customer.name)
        self.assertNotContains(response, self.other.name)
        self.assertFalse(Site.objects.exists())
        self.client.post(self.url, self.data)
        self.assertEqual(Site.objects.get(name='Nueva sede').client_id, self.customer.pk)

    def test_invalid_client_context_does_not_offer_all_customers(self):
        for value in ('invalid', '99999999', '99999999999999999999999'):
            with self.subTest(value=value):
                response = self.client.get(reverse('site_new'), {'client': value})
                self.assertEqual(response.status_code, 404)

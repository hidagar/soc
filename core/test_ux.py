"""Reglas de experiencia de usuario que no deben perderse: accesibilidad básica de las dos bases de página."""
import time
from pathlib import Path

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from .client_services import ClientServicesForm
from .models import Client, StaffAccess


class UxRulesTests(TestCase):
    def setUp(self):
        self.company = Client.objects.create(name='Empresa A', code='a', customer_portal_detail_enabled=True)
        self.admin = get_user_model().objects.create_superuser('admin', 'admin@soc.test', 'x')
        self.customer = get_user_model().objects.create_user('cliente', email='cliente@a.test')
        StaffAccess.objects.create(user=self.customer, role='customer').clients.add(self.company)

    def login(self, user):
        self.client.force_login(user)
        session = self.client.session
        session.update({'soc_mfa_user': user.pk, 'soc_mfa_at': time.time()})
        session.save()

    def assert_base(self, html):
        self.assertIn('class="skip-link" href="#contenido"', html)
        self.assertIn('id="contenido"', html)
        self.assertIn('js/forms.js', html)

    def test_soc_pages_have_skip_link_main_target_and_form_script(self):
        self.login(self.admin)
        self.assert_base(self.client.get(reverse('client_list')).content.decode())

    def test_customer_pages_have_skip_link_main_target_and_form_script(self):
        self.login(self.customer)
        response = self.client.get(reverse('customer_requests'), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assert_base(response.content.decode())

    def test_messages_carry_their_level_so_errors_do_not_look_like_confirmations(self):
        for template in ('base.html', 'partials/customer_nav.html'):
            source = (Path(settings.BASE_DIR) / 'templates' / template).read_text(encoding='utf-8')
            self.assertIn('class="message {{ message.tags }}"', source, template)
        css = (Path(settings.BASE_DIR) / 'static/css/ui.css').read_text(encoding='utf-8')
        for level in (messages.DEFAULT_TAGS[messages.ERROR], messages.DEFAULT_TAGS[messages.WARNING]):
            self.assertIn(f'.message.{level}', css)

    def test_service_table_fields_are_named_for_screen_readers(self):
        form = ClientServicesForm(instance=self.company)
        for name, field in form.fields.items():
            self.assertTrue(field.widget.attrs.get('aria-label'), name)

"""Portal del cliente fácil de usar: estado de un vistazo, ayuda, resumen en lenguaje llano y tablas en el móvil."""
from datetime import timedelta
from pathlib import Path

from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from .models import AuditEvent, Client, CustomerRequest, EndpointAgent, StaffAccess
from .operations import ingest_events
from .test_endpoints import alert, detected


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class PortalFriendlyTests(TestCase):
    def setUp(self):
        self.company = Client.objects.create(name='Talleres Ejemplo', code='te')
        self.customer = get_user_model().objects.create_user('ana', email='ana@te.test')
        StaffAccess.objects.create(user=self.customer, role='customer').clients.add(self.company)
        self.client.force_login(self.customer)

    def test_home_says_all_is_well_when_nothing_is_pending(self):
        page = self.client.get(reverse('customer_home'))
        self.assertContains(page, 'Todo en orden')
        self.assertContains(page, 'Pedir algo al SOC')
        self.assertContains(page, reverse('customer_help'))

    def test_home_lists_what_needs_attention_with_links(self):
        CustomerRequest.objects.create(client=self.company, kind='question', subject='Duda', status='waiting')
        page = self.client.get(reverse('customer_home'))
        self.assertContains(page, 'Hay una cosa que necesita vuestra atención')
        self.assertContains(page, 'Contestar al SOC en una solicitud')
        self.assertNotContains(page, 'Todo en orden')

    def test_unresolved_malware_is_never_all_well(self):
        now = timezone.now()
        Client.objects.filter(pk=self.company.pk).update(customer_endpoints_enabled=True)
        ingest_events([alert('1150', stamp=now - timedelta(minutes=5), ident='s')], now)
        EndpointAgent.objects.update(status='assigned', client=self.company, assigned_at=now - timedelta(minutes=1))
        ingest_events([alert('1118', detected(), ident='d')], now)
        page = self.client.get(reverse('customer_home'))
        self.assertContains(page, 'Revisar un equipo con malware sin eliminar')
        self.assertNotContains(page, 'Todo en orden')

    def test_help_page_is_in_the_menu_and_in_the_soc_preview(self):
        page = self.client.get(reverse('customer_help'))
        self.assertContains(page, '¿Es una emergencia?')
        self.assertContains(page, 'aria-current="page">Ayuda</a>')
        self.assertNotContains(page, 'Protección en tiempo real')  # sin el antivirus en el portal, no se explica
        admin = get_user_model().objects.create_superuser('admin', 'a@a.test', 'x')
        StaffAccess.objects.create(user=admin, role='operator', all_clients=True)
        self.client.force_login(admin)
        preview = self.client.get(reverse('customer_preview_help', args=[self.company.pk]))
        self.assertContains(preview, 'Vista previa como Talleres Ejemplo')
        self.assertTrue(AuditEvent.objects.filter(action='customer.preview', details__status='ayuda').exists())

    def test_mobile_tables_and_empty_cells(self):
        js = (Path(settings.BASE_DIR) / 'static/js/forms.js').read_text(encoding='utf-8')
        self.assertIn("classList.add('stacked')", js)
        css = (Path(settings.BASE_DIR) / 'static/css/ui.css').read_text(encoding='utf-8')
        # Ocultar celdas vacías solo en el móvil: en escritorio descolocaba las columnas.
        self.assertIn('@media(max-width:700px){.stacked td:empty{display:none}}', css)
        self.assertNotIn('\n.stacked td:empty{display:none}', css)

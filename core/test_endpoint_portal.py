"""Antivirus de equipos en el portal del cliente: opción por cliente y proyección explícita (invariante 3)."""
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from .models import AuditEvent, Client, EndpointAgent, Site, StaffAccess
from .operations import ingest_events
from .test_endpoints import alert, detected


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class EndpointPortalTests(TestCase):
    def setUp(self):
        self.now = timezone.now()
        self.company = Client.objects.create(name='Talleres Ejemplo', code='te', customer_endpoints_enabled=True)
        self.other = Client.objects.create(name='Otra Empresa', code='ot', customer_endpoints_enabled=True)
        self.site = Site.objects.create(client=self.company, name='Palma', code='palma')
        ingest_events([alert('1150', stamp=self.now - timedelta(minutes=5), ident='seed')], self.now)
        EndpointAgent.objects.update(status='assigned', client=self.company, site=self.site,
                                     assigned_at=self.now - timedelta(minutes=1))
        ingest_events([alert('1151', {'rTP state': 'Enabled', 'aV Signature Age': '0'}, ident='h'),
                       alert('1116', detected(), ident='d1'), alert('1118', detected(), ident='d2')], self.now)
        User = get_user_model()
        self.customer = User.objects.create_user('ana', email='ana@te.test')
        StaffAccess.objects.create(user=self.customer, role='customer').clients.add(self.company)
        self.stranger = User.objects.create_user('otro', email='x@ot.test')
        StaffAccess.objects.create(user=self.stranger, role='customer').clients.add(self.other)

    def test_customer_sees_status_and_detections_without_internal_data(self):
        self.client.force_login(self.customer)
        page = self.client.get(reverse('customer_endpoints'))
        self.assertContains(page, 'PC-CONTA-01')
        self.assertContains(page, 'Protegido')
        self.assertContains(page, 'Trojan:Win32/Wacatac.B!ml')
        self.assertContains(page, 'El antivirus no pudo actuar')
        for internal in ('Downloads', 'factura.exe', 'explorer.exe', 'EMPRESA\\ana', '10.0.0.25', 'agente 003'):
            self.assertNotContains(page, internal)
        home = self.client.get(reverse('customer_home'))
        self.assertContains(home, 'Antivirus de vuestros equipos')
        self.assertContains(home, '1 de 1')
        self.assertContains(home, reverse('customer_endpoints'))

    def test_other_customers_see_only_their_own_equipment(self):
        self.client.force_login(self.stranger)
        page = self.client.get(reverse('customer_endpoints'))
        self.assertNotContains(page, 'PC-CONTA-01')
        self.assertNotContains(page, 'Wacatac')

    def test_the_page_and_its_menu_entry_need_the_option(self):
        Client.objects.filter(pk=self.company.pk).update(customer_endpoints_enabled=False)
        self.client.force_login(self.customer)
        self.assertEqual(self.client.get(reverse('customer_endpoints')).status_code, 404)
        home = self.client.get(reverse('customer_home'))
        self.assertNotContains(home, reverse('customer_endpoints'))
        self.assertNotContains(home, 'Antivirus de vuestros equipos')

    def test_soc_preview_shows_the_same_page_and_is_audited(self):
        admin = get_user_model().objects.create_superuser('admin', 'a@a.test', 'x')
        StaffAccess.objects.create(user=admin, role='operator', all_clients=True)
        self.client.force_login(admin)
        page = self.client.get(reverse('customer_preview_endpoints', args=[self.company.pk]))
        self.assertContains(page, 'Vista previa como Talleres Ejemplo')
        self.assertContains(page, 'Trojan:Win32/Wacatac.B!ml')
        self.assertNotContains(page, 'Downloads')
        self.assertTrue(AuditEvent.objects.filter(action='customer.preview', details__status='equipos').exists())
        Client.objects.filter(pk=self.company.pk).update(customer_endpoints_enabled=False)
        self.assertEqual(self.client.get(reverse('customer_preview_endpoints', args=[self.company.pk])).status_code, 404)

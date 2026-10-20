from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse

from .models import Client, StaffAccess


class SidebarNavigationTests(TestCase):
    def setUp(self):
        self.company = Client.objects.create(name='Empresa A', code='empresa-a')

    def test_operator_sees_grouped_menu_without_global_administration(self):
        user = get_user_model().objects.create_user('operator')
        access = StaffAccess.objects.create(user=user, role='operator'); access.clients.add(self.company)
        user.groups.add(Group.objects.get(name='SOC Operador'))
        self.client.force_login(user)
        response = self.client.get(reverse('operations_help'))
        self.assertContains(response, '<summary>Respuesta</summary>', html=True)
        self.assertContains(response, '<summary>Detección e investigación</summary>', html=True)
        self.assertNotContains(response, f'href="{reverse("staff")}"')
        self.assertNotContains(response, f'href="{reverse("mail_settings")}"')
        self.assertNotContains(response, 'href="/admin/"')
        self.assertNotContains(response, 'SOC general en Wazuh')
        self.assertNotContains(response, '<summary>Administración</summary>', html=True)
        self.assertContains(response, f'<a href="{reverse("operations_help")}" aria-current="page">Guía de operación</a>', html=True)

    def test_detail_page_marks_parent_entry_and_opens_its_group(self):
        admin = get_user_model().objects.create_superuser(username='nav-admin', password='test-pass-9821')
        self.client.force_login(admin)
        response = self.client.get(reverse('client_detail', args=[self.company.pk]))
        self.assertContains(response, f'<a href="{reverse("client_list")}" aria-current="page">Clientes y sedes</a>', html=True)
        self.assertContains(response, 'data-nav-group="clientes" open')
        self.assertNotContains(response, 'data-nav-group="respuesta" open')
        self.assertContains(response, 'href="/admin/"')
        self.assertContains(response, f'href="{reverse("staff")}"')

    def test_customer_only_sees_private_portal_entries(self):
        customer = get_user_model().objects.create_user('customer')
        access = StaffAccess.objects.create(user=customer, role='customer'); access.clients.add(self.company)
        self.client.force_login(customer)
        response = self.client.get(reverse('mfa_setup'))
        self.assertContains(response, f'<a href="{reverse("customer_home")}">Mi empresa</a>', html=True)
        self.assertContains(response, 'Mi autenticador')
        self.assertNotContains(response, 'Bandeja de trabajo')
        self.assertNotContains(response, 'nav-group" data-nav-group')

"""Alta guiada: cliente → sede → firewall → comprobación → servicios, sin saltos ni entradas paralelas."""
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from .models import AuditEvent, Client, Device, FirewallOnboarding, Site, StaffAccess, UserInvitation
from .testing_access import FreshMfaClient


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class GuidedOnboardingTests(TestCase):
    client_class = FreshMfaClient

    def setUp(self):
        self.manager = get_user_model().objects.create_user('gestor')
        StaffAccess.objects.create(user=self.manager, role='manager', all_clients=True)
        self.manager.user_permissions.add(*Permission.objects.filter(codename__in=(
            'add_client', 'change_client', 'add_site', 'add_device', 'change_device', 'manage_security')))
        self.client.force_login(self.manager)

    def new_client(self, **data):
        page = self.client.get(reverse('client_new'))
        return self.client.post(reverse('client_new'), {'creation_token': page.context['creation_token'], **data})

    def test_new_client_is_step_one_and_goes_straight_to_its_first_site(self):
        page = self.client.get(reverse('client_new'))
        self.assertContains(page, 'Paso 1 de 7')
        self.assertContains(page, '¿Qué cliente vas a dar de alta?')
        response = self.new_client(name='Empresa Nueva', code='nueva')
        client = Client.objects.get(code='nueva')
        self.assertTrue(client.active)
        self.assertRedirects(response, reverse('site_new') + f'?client={client.pk}', fetch_redirect_response=False)
        page = self.client.get(response['Location'])
        self.assertContains(page, 'Paso 2 de 7')
        self.assertContains(page, 'Empresa Nueva')
        self.assertContains(page, '¿Cómo se llama la sede?')

    def test_identifier_is_generated_and_a_double_submit_creates_one_client(self):
        Client.objects.create(name='Otra', code='conservas-ejemplo')
        page = self.client.get(reverse('client_new'))
        data = {'creation_token': page.context['creation_token'], 'name': 'Conservas Ejemplo'}
        first = self.client.post(reverse('client_new'), data)
        second = self.client.post(reverse('client_new'), data)
        self.assertEqual(Client.objects.filter(name='Conservas Ejemplo').get().code, 'conservas-ejemplo-2')
        self.assertEqual(first['Location'], second['Location'])

    def test_client_without_sites_points_to_the_next_step(self):
        client = Client.objects.create(name='Empresa', code='e')
        self.assertContains(self.client.get(reverse('client_detail', args=[client.pk])), 'Añadir la primera sede')
        site = Site.objects.create(client=client, name='Palma', code='palma')
        page = self.client.get(reverse('client_detail', args=[client.pk]))
        self.assertContains(page, reverse('onboarding_add_device', args=[site.pk]))

    def test_generic_device_form_is_not_a_second_entry(self):
        site = Site.objects.create(client=Client.objects.create(name='Empresa', code='e'), name='Palma', code='palma')
        self.assertRedirects(self.client.get(reverse('device_new') + f'?site={site.pk}'),
                             reverse('onboarding_add_device', args=[site.pk]), fetch_redirect_response=False)
        self.assertRedirects(self.client.get(reverse('device_new')), reverse('client_list'), fetch_redirect_response=False)

    def test_verified_firewall_leads_to_the_client_services(self):
        client = Client.objects.create(name='Empresa', code='e')
        device = Device.objects.create(site=Site.objects.create(client=client, name='Palma', code='palma'), name='FW', vendor='opnsense')
        FirewallOnboarding.objects.create(device=device, step=5, verified_at=timezone.now(), event_at=timezone.now())
        page = self.client.get(reverse('device_onboarding', args=[device.pk]))
        self.assertContains(page, 'Activar los servicios del cliente')
        self.assertContains(page, reverse('client_detail', args=[client.pk]) + '#servicios')
        self.assertContains(page, 'Paso 6 de 7')

    def test_portal_access_is_created_and_invited_from_the_client(self):
        client = Client.objects.create(name='Empresa', code='e')
        response = self.client.post(reverse('client_portal_invite', args=[client.pk]), {'email': 'Gerencia@Empresa.test'})
        self.assertEqual(response.status_code, 302)
        user = get_user_model().objects.get(email='gerencia@empresa.test')
        access = StaffAccess.objects.get(user=user)
        self.assertEqual((access.role, access.all_clients, list(access.clients.all())), ('customer', False, [client]))
        self.assertFalse(user.has_usable_password())
        self.assertEqual(UserInvitation.objects.get(user=user).status, 'queued')
        self.assertTrue(AuditEvent.objects.filter(action='staff.access').exists())
        self.assertContains(self.client.get(reverse('client_detail', args=[client.pk])), 'gerencia@empresa.test (invitación pendiente)')
        self.client.post(reverse('client_portal_invite', args=[client.pk]), {'email': 'gerencia@empresa.test'})
        self.assertEqual(get_user_model().objects.filter(email='gerencia@empresa.test').count(), 1)

    def test_portal_invite_needs_security_permission_and_global_access(self):
        client = Client.objects.create(name='Empresa', code='e')
        self.manager.user_permissions.remove(Permission.objects.get(codename='manage_security'))
        self.assertEqual(self.client.post(reverse('client_portal_invite', args=[client.pk]), {'email': 'a@e.test'}).status_code, 403)
        self.assertNotContains(self.client.get(reverse('client_detail', args=[client.pk])), 'Dar acceso al portal')
        self.manager.user_permissions.add(Permission.objects.get(codename='manage_security'))
        StaffAccess.objects.filter(user=self.manager).update(all_clients=False)
        StaffAccess.objects.get(user=self.manager).clients.add(client)
        self.assertEqual(self.client.post(reverse('client_portal_invite', args=[client.pk]), {'email': 'a@e.test'}).status_code, 403)
        self.assertFalse(get_user_model().objects.filter(email='a@e.test').exists())

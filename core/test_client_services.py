"""Servicios del cliente en un solo sitio: ficha del cliente y de cada sede."""
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from .models import (AuditEvent, BlocklistFeed, ChangePlan, Client, Device, DeviceHealth, Site, StaffAccess,
                     UnifiBlocklistBinding)


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class ClientServicesTests(TestCase):
    def setUp(self):
        self.company = Client.objects.create(name='Empresa A', code='a', contact_email='it@a.test')
        self.other = Client.objects.create(name='Empresa B', code='b')
        self.palma = Site.objects.create(client=self.company, name='Palma', code='palma')
        self.inca = Site.objects.create(client=self.company, name='Inca', code='inca')
        self.opnsense = Device.objects.create(site=self.palma, name='FW-Palma', vendor='opnsense', zenarmor_enabled=True)
        self.unifi = Device.objects.create(site=self.inca, name='UDM-Inca', vendor='unifi')
        DeviceHealth.objects.create(device=self.opnsense, last_log_at=timezone.now())
        ChangePlan.objects.create(device=self.opnsense, template='crowdsec', title='Bloqueo', status='active')
        UnifiBlocklistBinding.objects.create(device=self.unifi, site_id='s', list_id='lista', list_name='SOC Bloqueo entrada', item_format='ip')
        BlocklistFeed.objects.create(client=self.company, enabled=True, entries=['198.51.100.7'])
        self.manager = get_user_model().objects.create_user('gestor')
        self.access = StaffAccess.objects.create(user=self.manager, role='manager')
        self.access.clients.add(self.company)
        self.manager.user_permissions.add(Permission.objects.get(codename='change_client'))
        self.client.force_login(self.manager)

    def save(self, **data):
        return self.client.post(reverse('client_services', args=[self.company.pk]), data)

    def test_client_page_shows_every_service_and_each_firewall(self):
        page = self.client.get(reverse('client_detail', args=[self.company.pk]))
        for text in ('Servicios del cliente', 'Informe semanal por correo', 'Avisos de actuaciones', 'Informe mensual por correo',
                     'Publicada · 1 IP', 'Desactivados en todo el SOC', 'Ninguno publicado', 'Sedes y firewalls',
                     'FW-Palma', 'Recibiendo', 'Regla activa', 'UDM-Inca', 'Lista escrita, política sin activar', 'Envío sin configurar'):
            self.assertContains(page, text)

    def test_saving_services_updates_the_client_and_audits_it(self):
        response = self.save(weekly_reports_enabled='on', report_email='informes@a.test', customer_portal_detail_enabled='on')
        self.assertRedirects(response, reverse('client_detail', args=[self.company.pk]) + '#servicios', fetch_redirect_response=False)
        self.company.refresh_from_db()
        self.assertTrue(self.company.weekly_reports_enabled and self.company.customer_portal_detail_enabled)
        self.assertEqual(self.company.report_email, 'informes@a.test')
        event = AuditEvent.objects.get(action='client.services')
        self.assertIn('weekly_reports_enabled', event.details['fields'])

    def test_invalid_combination_is_rejected_with_its_reason(self):
        response = self.save(weekly_reports_enabled='on')
        self.company.refresh_from_db()
        self.assertFalse(self.company.weekly_reports_enabled)
        page = self.client.get(response['Location'])
        self.assertContains(page, 'Indica el correo que recibirá el informe')

    def test_site_page_shows_its_firewalls_and_saves_back_to_the_site(self):
        page = self.client.get(reverse('site_detail', args=[self.palma.pk]))
        self.assertContains(page, 'Firewalls de esta sede')
        self.assertContains(page, 'FW-Palma')
        self.assertNotContains(page, 'UDM-Inca')
        self.assertContains(page, 'Afectan a todas las sedes de Empresa A')
        response = self.save(task_notices_enabled='on', site=str(self.palma.pk))
        self.assertTrue(response['Location'].startswith(reverse('site_detail', args=[self.palma.pk])))
        self.company.refresh_from_db()
        self.assertTrue(self.company.task_notices_enabled)

    def test_requires_permission_and_scope(self):
        self.manager.user_permissions.clear()
        self.assertEqual(self.save(weekly_reports_enabled='on', report_email='x@a.test').status_code, 403)
        self.manager.user_permissions.add(Permission.objects.get(codename='change_client'))
        response = self.client.post(reverse('client_services', args=[self.other.pk]), {'customer_live_map_enabled': 'on'})
        self.assertEqual(response.status_code, 404)
        self.other.refresh_from_db()
        self.assertFalse(self.other.customer_live_map_enabled)

    def test_edit_form_keeps_only_the_basic_data(self):
        self.client.post(reverse('client_edit', args=[self.company.pk]),
                         {'name': 'Empresa A', 'code': 'a', 'active': 'on', 'weekly_reports_enabled': 'on', 'report_email': 'x@a.test'})
        self.company.refresh_from_db()
        self.assertFalse(self.company.weekly_reports_enabled)
        self.assertNotContains(self.client.get(reverse('client_edit', args=[self.company.pk])), 'Enviar avisos urgentes automáticamente')

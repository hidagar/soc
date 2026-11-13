"""Contadores del menú lateral y buscador global."""
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from .models import (Client, CustomerRequest, Device, DeviceExposure, Incident, PolicyProposal, Site, StaffAccess,
                     VulnerabilityRecord)


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class MenuSearchTests(TestCase):
    def setUp(self):
        self.company = Client.objects.create(name='Talleres Ejemplo', code='te')
        self.other = Client.objects.create(name='Talleres Ajenos', code='ta')
        self.site = Site.objects.create(client=self.company, name='Palma', code='palma')
        self.fw = Device.objects.create(site=self.site, name='FW-Palma', vendor='opnsense', serial_number='SN-12345', software_version='25.1')
        other_site = Site.objects.create(client=self.other, name='Inca', code='inca')
        self.other_fw = Device.objects.create(site=other_site, name='FW-Inca', vendor='opnsense', serial_number='SN-12399')
        self.user = get_user_model().objects.create_user('operador')
        StaffAccess.objects.create(user=self.user, role='operator').clients.add(self.company)
        self.client.force_login(self.user)

    def get(self, q):
        return self.client.get(reverse('search'), {'q': q})

    def test_badges_count_pending_work_within_scope(self):
        page = self.client.get(reverse('dashboard'))
        self.assertNotContains(page, 'nav-badge')
        CustomerRequest.objects.create(client=self.company, kind='question', subject='Duda', urgent=True)
        CustomerRequest.objects.create(client=self.company, kind='question', subject='Cerrada', status='resolved')
        CustomerRequest.objects.create(client=self.other, kind='question', subject='Ajena')
        PolicyProposal.objects.create(client=self.company, kind='ips_block', key='k', title='IPS', change='c', risk='r', status='approved')
        record = VulnerabilityRecord.objects.create(cve_id='CVE-2026-44194', product='a:opnsense:opnsense', severity='CRITICAL')
        DeviceExposure.objects.create(client=self.company, device=self.fw, record=record, version='25.1')
        page = self.client.get(reverse('dashboard')).content.decode()
        self.assertEqual(page.count('class="nav-badge urgent">1<'), 2)  # solicitudes y políticas (aprobada)
        self.assertEqual(page.count('class="nav-badge">1<'), 1)  # vulnerabilidades
        self.assertIn('name="q"', page)

    def test_search_finds_across_areas_and_respects_scope(self):
        Incident.objects.create(client=self.company, title='Acceso RDP sospechoso en talleres', description='d')
        page = self.get('talleres')
        self.assertContains(page, 'Talleres Ejemplo')
        self.assertContains(page, 'Acceso RDP sospechoso')
        self.assertNotContains(page, 'Talleres Ajenos')
        # El número de serie parcial coincide con dos firewalls, pero solo uno es de sus clientes.
        self.assertRedirects(self.get('SN-123'), reverse('device_detail', args=[self.fw.pk]), fetch_redirect_response=False)
        Device.objects.create(site=self.site, name='FW-Palma-2', vendor='opnsense', serial_number='SN-12377')
        page = self.get('SN-123')
        self.assertContains(page, 'FW-Palma-2')
        self.assertNotContains(page, 'FW-Inca')
        self.assertContains(self.get('zzz-nada'), 'Sin resultados')
        self.assertContains(self.get('a'), 'al menos dos caracteres')

    def test_single_result_reference_and_ip_go_straight_to_the_page(self):
        self.assertRedirects(self.get('SN-12345'), reverse('device_detail', args=[self.fw.pk]), fetch_redirect_response=False)
        req = CustomerRequest.objects.create(client=self.company, kind='question', subject='Duda')
        self.assertRedirects(self.get(f'sol-{req.pk}'), reverse('request_detail', args=[req.pk]), fetch_redirect_response=False)
        foreign = CustomerRequest.objects.create(client=self.other, kind='question', subject='Ajena')
        self.assertEqual(self.get(foreign.reference).status_code, 200)  # fuera de su ámbito: no redirige ni la muestra
        self.assertRedirects(self.get('203.0.113.9'), reverse('ip_investigation') + '?ip=203.0.113.9', fetch_redirect_response=False)
        record = VulnerabilityRecord.objects.create(cve_id='CVE-2026-44194', product='a:opnsense:opnsense', severity='CRITICAL')
        DeviceExposure.objects.create(client=self.company, device=self.fw, record=record, version='25.1', resolved_at=timezone.now())
        page = self.get('CVE-2026-44194')
        self.assertContains(page, 'FW-Palma')
        self.assertContains(page, 'resuelta')

    def test_customers_have_no_search(self):
        customer = get_user_model().objects.create_user('cliente')
        StaffAccess.objects.create(user=customer, role='customer').clients.add(self.company)
        self.client.force_login(customer)
        self.assertEqual(self.get('talleres').status_code, 403)
        self.assertNotContains(self.client.get(reverse('customer_home')), 'nav-search')

    def test_intelligence_pages_share_one_menu_entry_and_tabs(self):
        from django.contrib.auth.models import Permission
        page = self.client.get(reverse('crowdsec_overview')).content.decode()
        self.assertIn('Inteligencia y bloqueo</a>', page)
        self.assertNotIn('>Listas de CrowdSec</a>', page)  # sin permiso de operaciones: solo su pestaña
        self.assertIn('aria-label="Inteligencia y bloqueo"', page)
        self.user.user_permissions.add(Permission.objects.get(codename='manage_operations'))
        page = self.client.get(reverse('blocklists')).content.decode()
        for label in ('Reputación CrowdSec', 'Listas de CrowdSec', 'Listas de bloqueo', 'Q-Feeds', 'Reputación propia'):
            self.assertIn(f'>{label}</a>', page)
        self.assertIn(f'<a href="{reverse("blocklists")}" aria-current="page">Listas de bloqueo</a>', page)
        self.assertIn(f'<a href="{reverse("crowdsec_overview")}" aria-current="page">Inteligencia y bloqueo', page)
        self.assertNotIn('page-tabs', self.client.get(reverse('dashboard')).content.decode())

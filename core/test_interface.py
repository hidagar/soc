"""Revisión de la interfaz: el resumen prioriza lo pendiente y las fichas resumen el estado sin datos de otros clientes."""
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from .models import Client, CustomerTask, Device, DeviceHealth, Incident, SecurityEvidence, Site, StaffAccess


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class InterfaceTests(TestCase):
    def setUp(self):
        self.company = Client.objects.create(name='Conservas Roselló', code='rosello')
        self.other = Client.objects.create(name='Otra empresa', code='otra')
        self.device = Device.objects.create(site=Site.objects.create(client=self.company, name='Fábrica', code='f'),
                                            name='FW-Rosello', vendor='opnsense')
        other_device = Device.objects.create(site=Site.objects.create(client=self.other, name='Sede', code='o'),
                                             name='FW-Otra', vendor='opnsense')
        now = timezone.now()
        for n, (device, action) in enumerate([(self.device, 'allowed'), (self.device, 'blocked'), (other_device, 'allowed')]):
            SecurityEvidence.objects.create(uid=f'{n:064x}', device=device, observed_at=now - timedelta(hours=1), engine='suricata',
                                            signature='ET SCAN Escaneo', source_ip='45.155.205.233', destination_ip='10.0.0.5',
                                            action=action, level=5, client_scope_id=device.site.client_id)
        DeviceHealth.objects.create(device=self.device, last_log_at=now - timedelta(hours=5))
        incident = Incident.objects.create(client=self.company, title='Escaneo', severity='critical', status='open', observed_at=now)
        Incident.objects.create(client=self.other, title='Ajena', severity='critical', status='open', observed_at=now)
        CustomerTask.objects.create(incident=incident, title='Revisar RDP', visible=True, status='submitted')
        self.admin = get_user_model().objects.create_superuser('admin', 'admin@example.test', 'x')

    def test_dashboard_lists_what_needs_attention(self):
        self.client.force_login(self.admin)
        page = self.client.get(reverse('dashboard'))
        attention = {item['title']: item['count'] for item in page.context['attention']}
        self.assertEqual(attention['Incidencias de prioridad alta o crítica'], 2)
        self.assertEqual(attention['Detecciones permitidas en las últimas 24 h'], 2)
        self.assertEqual(attention['Respuestas de clientes por revisar'], 1)
        self.assertEqual(attention['Equipos sin registros desde hace más de 2 h'], 1)
        self.assertNotIn('Avisos urgentes sin revisar', attention)  # sin avisos no aparece la fila
        self.assertContains(page, 'Revisar →')

    def test_scoped_operator_only_counts_assigned_clients(self):
        operator = get_user_model().objects.create_user('operador', 'op@example.test', 'x')
        StaffAccess.objects.create(user=operator, role='operator').clients.add(self.company)
        self.client.force_login(operator)
        attention = {item['title']: item['count'] for item in self.client.get(reverse('dashboard')).context['attention']}
        self.assertEqual(attention['Incidencias de prioridad alta o crítica'], 1)
        self.assertEqual(attention['Detecciones permitidas en las últimas 24 h'], 1)

    def test_client_detail_summarises_without_twelve_buttons(self):
        self.client.force_login(self.admin)
        page = self.client.get(reverse('client_detail', args=[self.company.pk]))
        self.assertEqual(page.context['evidence'], {'total': 2, 'allowed': 1})
        self.assertEqual((page.context['open_tasks'], page.context['replies']), (1, 1))
        self.assertContains(page, 'Más acciones')
        self.assertContains(page, '1 respuesta por revisar')

    def test_device_detail_header_comes_first(self):
        self.client.force_login(self.admin)
        page = self.client.get(reverse('device_detail', args=[self.device.pk])).content.decode()
        content = page[page.index('<main'):]
        self.assertLess(content.index('class="breadcrumbs"'), content.index('Validar detección y recepción'))
        self.assertIn('Detecciones · 7 días', content)

    def test_intelligence_is_paginated_and_in_spanish(self):
        self.client.force_login(self.admin)
        page = self.client.get(reverse('intelligence'))
        self.assertEqual(page.context['total'], 3)
        self.assertContains(page, 'Permitida')
        self.assertNotContains(page, 'Acción: allowed')

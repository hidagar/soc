"""«Ver como cliente»: el SOC ve el portal de un cliente igual que él, en solo lectura, dentro de su ámbito."""
from datetime import date, timedelta

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from .models import (AuditEvent, Client, CustomerPublication, CustomerTask, Device, Incident, SecurityEvidence, Site,
                     StaffAccess, WeeklyReport)


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class CustomerPreviewTests(TestCase):
    def setUp(self):
        self.company = Client.objects.create(name='Conservas Roselló', code='rosello', notes='NOTA INTERNA',
                                             customer_portal_detail_enabled=True, customer_live_map_enabled=True)
        self.other = Client.objects.create(name='Otra empresa', code='otra')
        device = Device.objects.create(site=Site.objects.create(client=self.company, name='Fábrica', code='f'),
                                       name='FW-Rosello', vendor='opnsense')
        SecurityEvidence.objects.create(uid='a' * 64, device=device, observed_at=timezone.now() - timedelta(hours=1),
                                        engine='suricata', signature='ET SCAN Escaneo', source_ip='45.155.205.233',
                                        destination_ip='10.0.0.5', action='blocked', level=5,
                                        client_scope_id=self.company.pk, recommendation='RECOMENDACION INTERNA')
        incident = Incident.objects.create(client=self.company, title='INCIDENCIA INTERNA', severity='high', status='open',
                                           observed_at=timezone.now())
        self.task = CustomerTask.objects.create(incident=incident, title='Revisar acceso RDP', instructions='Confirmad el acceso.',
                                                visible=True)
        self.report = WeeklyReport.objects.create(client=self.company, week_start=date(2026, 9, 21), sources=['192.0.2.1'],
                                                  security_count=1, blocked_count=1)
        CustomerPublication.objects.create(client=self.company, title='Aviso publicado', summary='Texto publicado',
                                           visible=True, weekly_report=self.report)
        self.customer = get_user_model().objects.create_user('cliente')
        StaffAccess.objects.create(user=self.customer, role='customer').clients.add(self.company)
        self.admin = get_user_model().objects.create_superuser('admin', 'admin@example.test', 'x')

    def staff(self, name, *clients):
        user = get_user_model().objects.create_user(name)
        access = StaffAccess.objects.create(user=user, role='operator')
        access.clients.add(*clients)
        user.groups.add(Group.objects.get(name='SOC Operador'))
        return user

    def test_soc_sees_exactly_what_the_customer_sees_in_read_only(self):
        self.client.force_login(self.customer)
        own = self.client.get(reverse('customer_detections'))
        self.client.force_login(self.admin)
        page = self.client.get(reverse('customer_preview', args=[self.company.pk]))
        for text in ('Vista previa como Conservas Roselló', 'Aviso publicado', 'Revisar acceso RDP', 'FW-Rosello'):
            self.assertContains(page, text)
        for text in ('NOTA INTERNA', 'INCIDENCIA INTERNA', reverse('customer_task_reply', args=[self.task.pk]),
                     reverse('logout')):
            self.assertNotContains(page, text)
        self.assertContains(page, reverse('customer_preview_report', args=[self.company.pk, self.report.pk]))
        self.assertContains(self.client.get(reverse('customer_preview_tasks', args=[self.company.pk])),
                            'Respuesta del cliente desactivada')
        for name, text in (('customer_preview_reports', 'Semana del 21/09/2026'), ('customer_preview_tasks', 'Revisar acceso RDP')):
            listing = self.client.get(reverse(name, args=[self.company.pk]))
            self.assertContains(listing, text)
            self.assertContains(listing, 'aria-current="page"')
            self.assertNotContains(listing, reverse('customer_task_reply', args=[self.task.pk]))
        preview = self.client.get(reverse('customer_preview_detections', args=[self.company.pk]))
        self.assertEqual(preview.context['summary']['totals'], own.context['summary']['totals'])
        self.assertEqual(list(preview.context['page'].object_list), list(own.context['page'].object_list))
        self.assertNotContains(preview, 'RECOMENDACION INTERNA')
        self.assertContains(preview, reverse('customer_preview_firewalls', args=[self.company.pk]))
        self.assertEqual(self.client.get(reverse('customer_preview_firewalls', args=[self.company.pk])).status_code, 200)
        self.assertEqual(self.client.get(reverse('customer_preview_map', args=[self.company.pk])).status_code, 200)
        data = self.client.get(reverse('customer_preview_map_data', args=[self.company.pk])).json()
        self.assertEqual((data['total'], data['recent']), (1, []))
        report = self.client.get(reverse('customer_preview_report', args=[self.company.pk, self.report.pk]))
        self.assertEqual(report.status_code, 200)
        self.assertEqual(self.client.get(reverse('customer_preview_report_pdf', args=[self.company.pk, self.report.pk]))['Content-Type'],
                         'application/pdf')
        self.assertEqual(self.client.post(reverse('customer_preview', args=[self.company.pk])).status_code, 405)
        sections = set(AuditEvent.objects.filter(action='customer.preview').values_list('details__status', flat=True))
        self.assertEqual(sections, {'inicio', 'informes', 'actuaciones', 'detecciones', 'firewalls', 'mapa', 'informe'})
        self.assertContains(self.client.get(reverse('client_detail', args=[self.company.pk])), 'Ver como cliente')

    def test_preview_respects_the_company_options(self):
        Client.objects.filter(pk=self.company.pk).update(customer_portal_detail_enabled=False, customer_live_map_enabled=False)
        self.client.force_login(self.admin)
        for name in ('customer_preview_firewalls', 'customer_preview_detections', 'customer_preview_map',
                     'customer_preview_map_data'):
            self.assertEqual(self.client.get(reverse(name, args=[self.company.pk])).status_code, 404, name)
        home = self.client.get(reverse('customer_preview', args=[self.company.pk]))
        self.assertNotContains(home, reverse('customer_preview_firewalls', args=[self.company.pk]))

    def test_only_staff_within_scope_can_preview(self):
        self.client.force_login(self.staff('limitado', self.other))
        for name in ('customer_preview', 'customer_preview_detections'):
            self.assertEqual(self.client.get(reverse(name, args=[self.company.pk])).status_code, 404)
        self.client.force_login(self.staff('asignado', self.company))
        self.assertEqual(self.client.get(reverse('customer_preview', args=[self.company.pk])).status_code, 200)
        self.client.force_login(self.customer)
        self.assertEqual(self.client.get(reverse('customer_preview', args=[self.company.pk])).status_code, 403)
        self.assertEqual(self.client.get(reverse('customer_preview', args=[self.other.pk])).status_code, 403)
        self.client.logout()
        self.assertEqual(self.client.get(reverse('customer_preview', args=[self.company.pk])).status_code, 302)

    def test_customer_portal_keeps_its_own_links(self):
        self.client.force_login(self.customer)
        page = self.client.get(reverse('customer_home'))
        self.assertContains(page, reverse('customer_task_reply', args=[self.task.pk]))
        self.assertContains(page, reverse('customer_weekly', args=[self.report.pk]))
        self.assertContains(page, reverse('logout'))
        self.assertNotContains(page, 'Vista previa')
        for name in ('customer_reports', 'customer_tasks'):
            self.assertContains(page, reverse(name))
        self.assertContains(self.client.get(reverse('customer_reports')), reverse('customer_weekly', args=[self.report.pk]))
        self.assertContains(self.client.get(reverse('customer_tasks')), reverse('customer_task_reply', args=[self.task.pk]))

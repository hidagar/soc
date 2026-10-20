"""Bloque 6: el informe publicado no cambia; una rectificación conserva ambas versiones."""
from datetime import date

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import TestCase, override_settings
from django.urls import reverse

from .models import Client, CustomerPublication, MailSettings, ReportVersion, Site, StaffAccess, WeeklyReport
from .report_sharing import create_report_link
from .report_versions import PDF_PLACEHOLDER, published_version


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class ReportVersionTests(TestCase):
    def setUp(self):
        self.company = Client.objects.create(name='Empresa A', code='a', report_email='a@example.test',
                                             weekly_reports_enabled=True)
        Site.objects.create(client=self.company, name='Sede original', code='s1')
        self.report = WeeklyReport.objects.create(client=self.company, week_start=date(2026, 9, 21),
                                                  sources=['192.0.2.1'], security_count=4, blocked_count=4)
        CustomerPublication.objects.create(client=self.company, title='Publicación', summary='x', visible=True,
                                           weekly_report=self.report)
        MailSettings.objects.create(pk=1, from_email='soc@example.test', enabled=True, last_test_ok=True,
                                    encrypted_api_key='opaque', public_reports_url='https://reports.example.test',
                                    public_reports_verified=True)
        User = get_user_model()
        self.customer = User.objects.create_user('cliente-a')
        StaffAccess.objects.create(user=self.customer, role='customer').clients.add(self.company)
        self.manager = User.objects.create_user('gestor')
        StaffAccess.objects.create(user=self.manager, role='manager', all_clients=True)
        self.manager.user_permissions.add(Permission.objects.get(codename='manage_connections'))

    def change_panel_data(self):
        for index in range(3):
            Site.objects.create(client=self.company, name=f'Sede nueva {index}', code=f'n{index}')
        self.report.blocked_count = 99
        self.report.save()

    def portal(self, **params):
        self.client.force_login(self.customer)
        return self.client.get(reverse('customer_weekly', args=[self.report.pk]), params)

    def test_published_report_reproduces_the_original_months_later(self):
        first = self.portal().content.decode()
        self.change_panel_data()
        later = self.portal().content.decode()
        self.assertEqual(ReportVersion.objects.count(), 1)
        self.assertIn('4 detecciones bloqueadas', first)
        self.assertIn('4 detecciones bloqueadas', later)
        self.assertNotIn('99', later.split('<footer')[0].split('Informe semanal', 1)[1])
        self.assertNotIn(PDF_PLACEHOLDER, later)
        pdf = self.client.get(reverse('customer_weekly_pdf', args=[self.report.pk]))
        self.assertEqual(bytes(pdf.content), bytes(ReportVersion.objects.get().pdf))

    def test_signed_link_serves_the_same_frozen_version(self):
        path = create_report_link(self.report).removeprefix('https://reports.example.test')
        self.client.get(path)
        self.change_panel_data()
        self.client.logout()
        response = self.client.get(path)
        self.assertContains(response, '4 detecciones bloqueadas')
        self.assertEqual(ReportVersion.objects.count(), 1)

    def test_rectification_keeps_both_versions_and_explains_the_change(self):
        self.portal()
        self.change_panel_data()
        self.client.force_login(self.manager)
        response = self.client.post(reverse('rectify_report', args=[self.report.pk]),
                                    {'reason': 'Recuento de bloqueos corregido tras revisar el firewall'})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(list(ReportVersion.objects.values_list('number', flat=True)), [1, 2])
        latest = self.portal().content.decode()
        self.assertIn('Versión rectificada 2', latest)
        self.assertIn('Recuento de bloqueos corregido', latest)
        self.assertIn('99 detecciones bloqueadas', latest)
        original = self.portal(version='1').content.decode()
        self.assertIn('4 detecciones bloqueadas', original)
        self.assertNotIn('Versión rectificada', original)
        self.assertEqual(self.portal(version='7').status_code, 404)

    def test_rectification_requires_reason_permission_and_a_published_version(self):
        self.client.force_login(self.manager)
        url = reverse('rectify_report', args=[self.report.pk])
        self.client.post(url, {'reason': 'Sin publicar todavía'})
        self.assertFalse(ReportVersion.objects.exists())
        published_version(self.report)
        self.client.post(url, {'reason': '  '})
        self.assertEqual(ReportVersion.objects.count(), 1)
        operator = get_user_model().objects.create_user('operador')
        StaffAccess.objects.create(user=operator, role='operator', all_clients=True)
        self.client.force_login(operator)
        self.assertEqual(self.client.post(url, {'reason': 'Intento'}).status_code, 403)
        self.assertEqual(ReportVersion.objects.count(), 1)

    def test_versions_of_another_company_are_never_served(self):
        other = Client.objects.create(name='Empresa B', code='b')
        foreign = WeeklyReport.objects.create(client=other, week_start=date(2026, 9, 21))
        CustomerPublication.objects.create(client=other, title='x', summary='x', visible=True, weekly_report=foreign)
        published_version(foreign)
        self.client.force_login(self.customer)
        self.assertEqual(self.client.get(reverse('customer_weekly', args=[foreign.pk])).status_code, 404)
        self.assertEqual(self.client.get(reverse('customer_weekly_pdf', args=[foreign.pk])).status_code, 404)

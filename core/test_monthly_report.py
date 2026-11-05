"""Bloque 6: informe mensual para dirección, publicado con versión inmutable y correo opcional."""
from datetime import date, datetime, timedelta
from unittest import mock

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from . import monthly_report
from .forms import ClientForm
from .mail_delivery import MailDeliveryError
from .models import (Client, CustomerPublication, CustomerTask, Incident, MailSettings, MonthlyReport, MonthlyReportShare,
                     MonthlyReportVersion, OperationalIssue, StaffAccess, WeeklyReport)
from .testing_access import collected_report

OCTOBER = date(2026, 10, 1)
OCT_WEEKS = (date(2026, 10, 5), date(2026, 10, 12), date(2026, 10, 19), date(2026, 10, 26))
SEP_WEEKS = (date(2026, 9, 7), date(2026, 9, 14), date(2026, 9, 21), date(2026, 9, 28))
SEND = 'core.mail_delivery.send_customer_email'
ADVICE = 'Cerrar el puerto publicado del servidor de correo.'


def aware(*args):
    return timezone.make_aware(datetime(*args))


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False, SOC_PUBLIC_ORIGIN='https://soc.example.test')
class MonthlyReportTests(TestCase):
    def setUp(self):
        self.company = Client.objects.create(name='Empresa A', code='a', report_email='it@a.test',
                                             monthly_reports_enabled=True, monthly_email='direccion@a.test')
        self.other = Client.objects.create(name='Empresa B', code='b')
        for index, monday in enumerate(OCT_WEEKS):
            findings = [{'asset_name': 'Correo', 'recommendations': [ADVICE]}] if index < 2 else []
            self.week(monday, security=10, blocked=8, allowed=1, findings=findings)
        for monday in SEP_WEEKS:
            self.week(monday, security=5, blocked=5, allowed=0)
        published = Incident.objects.create(client=self.company, title='Caso interno secreto', description='Detalle interno',
                                            observed_at=aware(2026, 10, 10, 12))
        CustomerPublication.objects.create(client=self.company, title='Comunicado visible', summary='x', visible=True,
                                           status='resolved', incident=published)
        CustomerTask.objects.create(incident=published, title='Actualizar el firmware', instructions='Pasos', visible=True,
                                    status='accepted', response='Hecho', reviewed_at=aware(2026, 10, 15, 9))
        CustomerTask.objects.create(incident=published, title='Revisar la VPN', instructions='Pasos', visible=True)
        CustomerTask.objects.create(incident=published, title='Borrador interno', instructions='Pasos', visible=False)
        MailSettings.objects.create(pk=1, from_email='soc@example.test', enabled=True, last_test_ok=True, encrypted_api_key='opaque',
                                    public_reports_url='https://reports.example.test', public_reports_verified=True)
        User = get_user_model()
        self.operator = User.objects.create_user('operador')
        StaffAccess.objects.create(user=self.operator, role='operator', all_clients=True)
        self.operator.user_permissions.add(Permission.objects.get(codename='change_incident'))
        self.manager = User.objects.create_user('gestor')
        StaffAccess.objects.create(user=self.manager, role='manager', all_clients=True)
        self.manager.user_permissions.add(Permission.objects.get(codename='manage_connections'))
        self.customer = User.objects.create_user('cliente-a')
        StaffAccess.objects.create(user=self.customer, role='customer').clients.add(self.company)
        self.stranger = User.objects.create_user('cliente-b')
        StaffAccess.objects.create(user=self.stranger, role='customer').clients.add(self.other)

    def week(self, monday, security, blocked, allowed, findings=()):
        report = WeeklyReport.objects.create(client=self.company, week_start=monday, sources=['192.0.2.1'], security_count=security,
                                             blocked_count=blocked, allowed_count=allowed, findings=list(findings))
        collected_report(report)
        return report

    def publish(self, **data):
        self.client.force_login(self.operator)
        return self.client.post(reverse('monthly_publish', args=[self.company.pk]),
                                {'month': '2026-10', 'soc_summary': 'Mes tranquilo; seguimos con la VPN.', 'send': '1', **data})

    def report(self):
        return MonthlyReport.objects.get(client=self.company, month=OCTOBER)

    def test_month_needs_all_its_weeks_finished_and_ready(self):
        self.assertEqual(monthly_report.release_problem(self.company, OCTOBER, now=aware(2026, 11, 3, 9)), '')
        self.assertIn('terminan el 01/11/2026', monthly_report.release_problem(self.company, OCTOBER, now=aware(2026, 11, 1, 9)))
        WeeklyReport.objects.filter(client=self.company, week_start=OCT_WEEKS[2]).delete()
        self.assertIn('semana del 19/10', monthly_report.release_problem(self.company, OCTOBER, now=aware(2026, 11, 3, 9)))

    def test_context_sums_the_weeks_and_projects_only_published_data(self):
        context = monthly_report.customer_context(self.company, OCTOBER)
        self.assertEqual((context['totals']['security'], context['totals']['blocked'], context['totals']['allowed'],
                          context['totals']['unknown']), (40, 32, 4, 4))
        self.assertEqual(context['previous']['security'], 20)
        self.assertIn('aumentaron un 100 %', context['summary_text'])
        self.assertEqual(context['recommendations'][0]['weeks'], 2)
        self.assertEqual([p['title'] for p in context['publications']], ['Comunicado visible'])
        self.assertEqual([t['title'] for t in context['validated_tasks']], ['Actualizar el firmware'])
        self.assertEqual([t['title'] for t in context['pending_tasks']], ['Revisar la VPN'])

    def test_publishing_freezes_version_one_and_queues_the_email(self):
        self.assertEqual(self.publish().status_code, 302)
        report = self.report()
        self.assertIsNotNone(report.published_at)
        self.assertEqual((report.send_status, report.sent_to), ('queued', 'direccion@a.test'))
        self.assertEqual(MonthlyReportVersion.objects.count(), 1)
        self.publish()
        self.assertEqual(MonthlyReportVersion.objects.count(), 1)

    def test_customer_sees_the_frozen_report_and_never_internal_data(self):
        self.publish(send='')
        self.assertEqual(self.report().send_status, '')
        WeeklyReport.objects.filter(client=self.company, week_start=OCT_WEEKS[0]).update(security_count=999)
        self.client.force_login(self.customer)
        listing = self.client.get(reverse('customer_reports'))
        self.assertContains(listing, 'Octubre de 2026')
        page = self.client.get(reverse('customer_monthly', args=[self.report().pk]))
        for text in ('Informe mensual', 'Mes tranquilo; seguimos con la VPN.', 'Comunicado visible', 'Actualizar el firmware',
                     'Revisar la VPN', ADVICE, '>40<'):
            self.assertContains(page, text)
        for text in ('Caso interno secreto', 'Detalle interno', 'Borrador interno', '999', monthly_report.PDF_PLACEHOLDER):
            self.assertNotContains(page, text)
        pdf = self.client.get(reverse('customer_monthly_pdf', args=[self.report().pk]))
        self.assertEqual(bytes(pdf.content), bytes(MonthlyReportVersion.objects.get().pdf))
        self.client.force_login(self.stranger)
        self.assertEqual(self.client.get(reverse('customer_monthly', args=[self.report().pk])).status_code, 404)

    def test_unpublished_month_is_invisible_to_the_customer(self):
        report = MonthlyReport.objects.create(client=self.company, month=OCTOBER)
        self.client.force_login(self.customer)
        self.assertEqual(self.client.get(reverse('customer_monthly', args=[report.pk])).status_code, 404)
        self.assertNotContains(self.client.get(reverse('customer_reports')), 'Octubre de 2026')

    def test_rectification_keeps_both_versions(self):
        self.publish(send='')
        self.client.force_login(self.manager)
        self.client.post(reverse('monthly_rectify', args=[self.report().pk]),
                         {'reason': 'Valoración ampliada', 'soc_summary': 'Valoración nueva del mes.'})
        self.assertEqual(list(MonthlyReportVersion.objects.values_list('number', flat=True)), [1, 2])
        self.client.force_login(self.customer)
        latest = self.client.get(reverse('customer_monthly', args=[self.report().pk]))
        self.assertContains(latest, 'Versión rectificada 2')
        self.assertContains(latest, 'Valoración nueva del mes.')
        first = self.client.get(reverse('customer_monthly', args=[self.report().pk]), {'version': '1'})
        self.assertContains(first, 'Mes tranquilo; seguimos con la VPN.')

    def test_queued_email_is_sent_once_with_only_the_signed_link(self):
        self.publish()
        with mock.patch(SEND, return_value='sg-1') as send:
            self.assertEqual(monthly_report.send_pending(), 1)
        recipient, subject, plain, html = send.call_args.args
        self.assertEqual(recipient, 'direccion@a.test')
        self.assertIn('Informe mensual', subject)
        self.assertEqual(send.call_args.kwargs['delivery_context'], {'client': self.company, 'kind': 'monthly'})
        self.assertTrue(send.call_args.kwargs['report_copy'])
        self.assertIn('https://reports.example.test/reports/mensual-', plain)
        for body in (plain, html):
            for secret in ('Mes tranquilo', 'Comunicado visible', ADVICE):
                self.assertNotIn(secret, body)
        report = self.report()
        self.assertEqual((report.send_status, report.provider_id), ('accepted', 'sg-1'))
        path = plain.split('https://reports.example.test', 1)[1].split()[0]
        self.client.logout()
        self.assertContains(self.client.get(path), 'Mes tranquilo; seguimos con la VPN.')
        self.assertEqual(self.client.get(path + 'pdf/')['Content-Type'], 'application/pdf')
        MonthlyReportShare.objects.update(revoked=True)
        self.assertEqual(self.client.get(path).status_code, 404)
        with mock.patch(SEND) as again:
            monthly_report.send_pending()
        again.assert_not_called()

    def test_uncertain_send_needs_an_explicit_confirmation(self):
        self.publish()
        with mock.patch(SEND, side_effect=MailDeliveryError('red')):
            monthly_report.send_pending()
        report = self.report()
        self.assertEqual(report.send_status, 'uncertain')
        with mock.patch(SEND) as send:
            monthly_report.send_pending()
        send.assert_not_called()
        self.client.force_login(self.operator)
        self.client.post(reverse('monthly_send', args=[report.pk]))
        self.assertEqual(self.report().send_status, 'uncertain')
        self.client.post(reverse('monthly_send', args=[report.pk]), {'confirm': '1'})
        self.assertEqual(self.report().send_status, 'queued')

    def test_send_is_dropped_if_the_client_disables_it_first(self):
        self.publish()
        Client.objects.filter(pk=self.company.pk).update(monthly_reports_enabled=False)
        with mock.patch(SEND) as send:
            monthly_report.send_pending()
        send.assert_not_called()
        self.assertEqual(self.report().send_status, 'failed')

    def test_pending_month_is_reminded_in_soc_health_until_published(self):
        now = aware(2026, 11, 6, 9)
        self.assertEqual(monthly_report.check_pending(now), 1)
        issue = OperationalIssue.objects.get(key=f'report:monthly:{self.company.pk}', active=True)
        self.assertIn('octubre de 2026', issue.details)
        self.publish(send='')
        monthly_report.check_pending(now)
        self.assertFalse(OperationalIssue.objects.filter(key=issue.key, active=True).exists())
        self.assertEqual(monthly_report.check_pending(aware(2026, 11, 3, 9)), 0)

    def test_staff_page_preview_and_permissions(self):
        self.client.force_login(self.operator)
        page = self.client.get(reverse('monthly_summary', args=[self.company.pk]), {'month': '2026-10'})
        self.assertContains(page, 'Publicar el informe del mes')
        self.assertContains(page, 'Enviar también por correo a direccion@a.test')
        preview = self.client.get(reverse('monthly_preview', args=[self.company.pk]), {'month': '2026-10'})
        self.assertContains(preview, 'Vista previa con los datos de hoy')
        self.assertFalse(MonthlyReportVersion.objects.exists())
        viewer = get_user_model().objects.create_user('lector')
        StaffAccess.objects.create(user=viewer, role='operator', all_clients=True)
        self.client.force_login(viewer)
        self.assertEqual(self.client.post(reverse('monthly_publish', args=[self.company.pk]), {'month': '2026-10'}).status_code, 403)
        self.assertFalse(MonthlyReport.objects.filter(published_at__isnull=False).exists())

    def test_client_form_requires_a_recipient_when_enabled(self):
        form = ClientForm({'name': 'Empresa C', 'code': 'c', 'monthly_reports_enabled': 'on', 'active': 'on'})
        self.assertIn('monthly_email', form.errors)
        self.assertTrue(ClientForm({'name': 'Empresa C', 'code': 'c', 'monthly_reports_enabled': 'on', 'active': 'on',
                                    'report_email': 'it@c.test'}).is_valid())

    def test_monthly_link_is_hidden_in_logs(self):
        from socportal.log_redaction import redact
        token = 'eyJyZXBvcnQiOjF9:1abc:' + 'x' * 30
        self.assertEqual(redact(f'GET /reports/mensual-{token}/pdf/ 200'), 'GET /reports/[oculto]/pdf/ 200')

    def test_previous_month_without_all_weeks_has_no_comparison(self):
        WeeklyReport.objects.filter(client=self.company, week_start=SEP_WEEKS[0]).delete()
        self.assertIsNone(monthly_report.customer_context(self.company, OCTOBER)['previous'])
        self.assertEqual(timedelta(days=0), monthly_report.available_from(OCTOBER) - date(2026, 11, 2))

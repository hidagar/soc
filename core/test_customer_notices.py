"""Hoja de ruta 6: avisos por correo al cliente cuando el SOC asigna, devuelve o valida una actuación."""
from datetime import timedelta
from unittest import mock

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from . import customer_notices
from .forms import ClientForm
from .mail_delivery import MailDeliveryError
from .models import Client, CustomerNotice, CustomerTask, Incident, StaffAccess

SEND = 'core.mail_delivery.send_customer_email'


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False, SOC_PUBLIC_ORIGIN='https://soc.example.test')
class CustomerNoticeTests(TestCase):
    def setUp(self):
        self.company = Client.objects.create(name='Empresa A', code='a', contact_email='it@empresa-a.test',
                                             task_notices_enabled=True)
        self.case = Incident.objects.create(client=self.company, title='Caso interno', description='Detalle interno')
        self.analyst = get_user_model().objects.create_user('analista')
        StaffAccess.objects.create(user=self.analyst, role='operator', all_clients=True)
        self.analyst.user_permissions.add(Permission.objects.get(codename='change_incident'))

    def save_task(self, task=None, **values):
        self.client.force_login(self.analyst)
        data = {'title': 'Actualizar el firmware', 'instructions': 'Pasos internos con la IP 10.0.0.1',
                'status': 'pending', 'review_note': ''}
        data.update(values)
        url = (reverse('customer_task_edit', args=[task.pk]) if task
               else reverse('customer_task_new', args=[self.case.pk]))
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, 302, getattr(response, 'context', None) and response.context['form'].errors)
        return task or CustomerTask.objects.get(incident=self.case)

    def test_change_kind_follows_the_customer_visible_status(self):
        task = CustomerTask(visible=True, status='pending')
        self.assertEqual(customer_notices.change_kind((None, False), task), 'assigned')
        self.assertEqual(customer_notices.change_kind(('pending', False), task), 'assigned')
        self.assertIsNone(customer_notices.change_kind(('pending', True), task))
        self.assertEqual(customer_notices.change_kind(('rework', True), task), 'assigned')
        task.status = 'rework'
        self.assertEqual(customer_notices.change_kind(('submitted', True), task), 'rework')
        self.assertIsNone(customer_notices.change_kind(('rework', True), task))
        task.status = 'accepted'
        self.assertEqual(customer_notices.change_kind(('submitted', True), task), 'accepted')
        task.status = 'submitted'
        self.assertIsNone(customer_notices.change_kind(('pending', True), task))
        task.status, task.visible = 'pending', False
        self.assertIsNone(customer_notices.change_kind((None, False), task))

    def test_publishing_a_task_queues_one_notice_and_drafts_do_not(self):
        task = self.save_task()
        self.assertFalse(CustomerNotice.objects.exists())
        self.save_task(task, visible='on')
        self.save_task(task, visible='on', title='Actualizar el firmware hoy')
        notice = CustomerNotice.objects.get()
        self.assertEqual((notice.kind, notice.recipient, notice.status), ('assigned', 'it@empresa-a.test', 'queued'))

    def test_nothing_is_queued_when_the_client_has_not_enabled_notices(self):
        Client.objects.filter(pk=self.company.pk).update(task_notices_enabled=False)
        self.save_task(visible='on')
        self.assertFalse(CustomerNotice.objects.exists())

    def test_task_email_takes_precedence_over_contact_email(self):
        Client.objects.filter(pk=self.company.pk).update(task_email='tareas@empresa-a.test')
        self.save_task(visible='on')
        self.assertEqual(CustomerNotice.objects.get().recipient, 'tareas@empresa-a.test')

    def test_review_queues_rework_and_accepted_notices(self):
        task = self.save_task(visible='on')
        CustomerTask.objects.filter(pk=task.pk).update(status='submitted', response='Hecho')
        task.refresh_from_db()
        self.save_task(task, visible='on', status='rework', review_note='Falta la versión instalada')
        CustomerTask.objects.filter(pk=task.pk).update(status='submitted')
        task.refresh_from_db()
        self.save_task(task, visible='on', status='accepted', review_note='Comprobado')
        self.assertEqual(list(CustomerNotice.objects.order_by('pk').values_list('kind', flat=True)),
                         ['assigned', 'rework', 'accepted'])

    def test_send_pending_sends_only_title_date_and_portal_link(self):
        task = self.save_task(visible='on', status='pending')
        CustomerTask.objects.filter(pk=task.pk).update(review_note='Nota interna del analista')
        with mock.patch(SEND, return_value='sg-123') as send:
            self.assertEqual(customer_notices.send_pending(), 1)
        recipient, subject, plain, html = send.call_args.args
        self.assertEqual(recipient, 'it@empresa-a.test')
        self.assertIn('Nueva actuación', subject)
        self.assertEqual(send.call_args.kwargs['delivery_context'], {'client': self.company, 'kind': 'task'})
        url = 'https://soc.example.test' + reverse('customer_task_reply', args=[task.pk])
        for body in (plain, html):
            self.assertIn('Actualizar el firmware', body)
            self.assertIn(url, body)
            for secret in ('Pasos internos', '10.0.0.1', 'Nota interna', 'Caso interno', 'Detalle interno'):
                self.assertNotIn(secret, body)
        notice = CustomerNotice.objects.get()
        self.assertEqual((notice.status, notice.provider_id), ('accepted', 'sg-123'))
        self.assertIsNotNone(notice.sent_at)
        with mock.patch(SEND) as send:
            self.assertEqual(customer_notices.send_pending(), 0)
        send.assert_not_called()

    def test_uncertain_result_is_not_retried(self):
        self.save_task(visible='on')
        with mock.patch(SEND, side_effect=MailDeliveryError('red')):
            customer_notices.send_pending()
        self.assertEqual(CustomerNotice.objects.get().status, 'uncertain')
        with mock.patch(SEND) as send:
            customer_notices.send_pending()
        send.assert_not_called()

    def test_notice_is_skipped_when_the_task_changed_before_sending(self):
        task = self.save_task(visible='on')
        CustomerTask.objects.filter(pk=task.pk).update(visible=False)
        with mock.patch(SEND) as send:
            customer_notices.send_pending()
        send.assert_not_called()
        self.assertEqual(CustomerNotice.objects.get().status, 'skipped')

    def test_notice_is_skipped_when_the_client_disables_notices(self):
        self.save_task(visible='on')
        Client.objects.filter(pk=self.company.pk).update(task_notices_enabled=False)
        with mock.patch(SEND) as send:
            customer_notices.send_pending()
        send.assert_not_called()
        self.assertEqual(CustomerNotice.objects.get().status, 'skipped')

    def test_interrupted_send_becomes_uncertain_instead_of_repeating(self):
        self.save_task(visible='on')
        CustomerNotice.objects.update(status='sending', attempted_at=timezone.now() - timedelta(minutes=11))
        with mock.patch(SEND) as send:
            customer_notices.send_pending()
        send.assert_not_called()
        self.assertEqual(CustomerNotice.objects.get().status, 'uncertain')

    def test_incident_detail_shows_the_notice_status(self):
        self.save_task(visible='on')
        page = self.client.get(reverse('incident_detail', args=[self.case.pk]))
        self.assertContains(page, 'aviso «Nueva actuación»: en cola')

    def test_client_form_requires_a_recipient_when_enabled(self):
        data = {'name': 'Empresa C', 'code': 'c', 'task_notices_enabled': 'on', 'active': 'on'}
        form = ClientForm(data)
        self.assertFalse(form.is_valid())
        self.assertIn('task_email', form.errors)
        form = ClientForm({**data, 'contact_email': 'it@empresa-c.test'})
        self.assertTrue(form.is_valid(), form.errors)

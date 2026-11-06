"""Solicitudes al SOC desde el portal del cliente."""
from datetime import timedelta
from unittest import mock

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from . import customer_requests
from .models import (AuditEvent, Client, CustomerRequest, CustomerRequestEntry, Incident, RecoverySettings, Site, StaffAccess)


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class CustomerRequestTests(TestCase):
    def setUp(self):
        self.company = Client.objects.create(name='Empresa A', code='a')
        self.other = Client.objects.create(name='Empresa B', code='b')
        self.palma = Site.objects.create(client=self.company, name='Palma', code='palma')
        Site.objects.create(client=self.company, name='Inca', code='inca')
        self.other_site = Site.objects.create(client=self.other, name='Sóller', code='soller')
        User = get_user_model()
        self.customer = User.objects.create_user('ana', email='ana@a.test')
        StaffAccess.objects.create(user=self.customer, role='customer').clients.add(self.company)
        self.intruder = User.objects.create_user('beto', email='beto@b.test')
        StaffAccess.objects.create(user=self.intruder, role='customer').clients.add(self.other)
        self.operator = User.objects.create_user('operador')
        access = StaffAccess.objects.create(user=self.operator, role='operator')
        access.clients.add(self.company)
        self.operator.user_permissions.add(*Permission.objects.filter(codename__in=['change_incident', 'add_incident']))

    def create(self, **extra):
        data = {'kind': 'unblock', 'subject': 'No abre la web de un proveedor', 'site': self.palma.pk,
                'text': 'Desde el equipo de contabilidad, a las 9:00.', **extra}
        self.client.force_login(self.customer)
        return self.client.post(reverse('customer_requests'), data)

    def test_customer_opens_a_request_and_the_soc_is_told_once(self):
        response = self.create(urgent='on')
        req = CustomerRequest.objects.get()
        self.assertRedirects(response, reverse('customer_request_detail', args=[req.pk]) + '?enviada=1')
        self.assertEqual((req.client, req.site, req.contact_email, req.status, req.urgent), (self.company, self.palma, 'ana@a.test', 'new', True))
        self.assertEqual(req.entries.get().kind, 'customer')
        self.assertTrue(AuditEvent.objects.filter(action='customer.request').exists())
        RecoverySettings.objects.update_or_create(pk=1, defaults={'notify_enabled': True, 'operational_email': 'noc@ibred.test'})
        with mock.patch('core.mail_delivery.send_customer_email', return_value='x') as send:
            self.assertEqual(customer_requests.notify_soc(), 1)
            self.assertEqual(customer_requests.notify_soc(), 0)
        self.assertEqual(send.call_count, 1)
        self.assertIn('URGENTE', send.call_args.args[1])
        self.assertIn(req.reference, send.call_args.args[2])

    def test_site_of_another_client_is_rejected(self):
        self.create(site=self.other_site.pk)
        self.assertFalse(CustomerRequest.objects.exists())

    def test_other_customers_cannot_see_or_reply(self):
        self.create()
        req = CustomerRequest.objects.get()
        self.client.force_login(self.intruder)
        self.assertEqual(self.client.get(reverse('customer_request_detail', args=[req.pk])).status_code, 404)
        self.assertEqual(self.client.post(reverse('customer_request_detail', args=[req.pk]), {'text': 'hola'}).status_code, 404)
        self.assertNotContains(self.client.get(reverse('customer_requests')), 'No abre la web')
        # Un cliente no puede abrir la página del SOC.
        self.assertEqual(self.client.get(reverse('requests')).status_code, 403)

    def test_soc_reply_internal_note_and_customer_view(self):
        self.create()
        req = CustomerRequest.objects.get()
        self.client.force_login(self.operator)
        self.client.post(reverse('request_detail', args=[req.pk]), {'action': 'note', 'text': 'Revisar categoría de Zenarmor, SECRETO-INTERNO'})
        self.client.post(reverse('request_detail', args=[req.pk]), {'action': 'reply', 'status': 'waiting',
                                                                   'text': '¿Qué dirección web es exactamente?'})
        req.refresh_from_db()
        self.assertEqual((req.status, req.owner, req.first_response_at is not None), ('waiting', self.operator, True))
        reply = req.entries.get(kind='soc')
        self.assertEqual(reply.notice_status, 'queued')
        with mock.patch('core.mail_delivery.send_customer_email', return_value='msg') as send:
            self.assertEqual(customer_requests.send_pending(), 1)
            self.assertEqual(customer_requests.send_pending(), 0)
        self.assertEqual(send.call_args.args[0], 'ana@a.test')
        self.assertIn('necesita información', send.call_args.args[1])
        self.assertNotIn('dirección web', send.call_args.args[2])  # el correo no lleva el texto
        self.assertEqual(send.call_args.kwargs['delivery_context'], {'client': self.company, 'kind': 'request'})
        self.client.force_login(self.customer)
        page = self.client.get(reverse('customer_request_detail', args=[req.pk]))
        self.assertContains(page, '¿Qué dirección web es exactamente?')
        self.assertNotContains(page, 'SECRETO-INTERNO')
        self.assertContains(self.client.get(reverse('customer_home')), 'esperando vuestra respuesta')
        self.client.post(reverse('customer_request_detail', args=[req.pk]), {'text': 'proveedor.example'})
        req.refresh_from_db()
        self.assertEqual(req.status, 'in_progress')
        self.assertIsNone(req.soc_notified_at)  # el SOC vuelve a recibir el aviso interno

    def test_resolve_close_and_reopen_window(self):
        self.create()
        req = CustomerRequest.objects.get()
        self.client.force_login(self.operator)
        self.client.post(reverse('request_detail', args=[req.pk]), {'action': 'reply', 'status': 'resolved', 'text': 'Desbloqueada.'})
        req.refresh_from_db()
        self.assertEqual(req.status, 'resolved')
        self.client.force_login(self.customer)
        self.client.post(reverse('customer_request_detail', args=[req.pk]), {'text': 'Sigue sin abrir.'})
        req.refresh_from_db()
        self.assertEqual(req.status, 'in_progress')
        self.client.post(reverse('customer_request_detail', args=[req.pk]), {'action': 'close'})
        req.refresh_from_db()
        self.assertEqual(req.status, 'resolved')
        CustomerRequest.objects.filter(pk=req.pk).update(resolved_at=timezone.now() - timedelta(days=20))
        response = self.client.post(reverse('customer_request_detail', args=[req.pk]), {'text': 'Otra vez'})
        self.assertContains(response, 'Abre una nueva')
        self.assertEqual(CustomerRequest.objects.get().status, 'resolved')

    def test_limits(self):
        for n in range(customer_requests.MAX_PER_DAY):
            CustomerRequest.objects.create(client=self.company, kind='question', subject=f'S{n}', status='resolved')
        response = self.create()
        self.assertContains(response, 'máximo de solicitudes nuevas por día')
        self.assertEqual(CustomerRequest.objects.count(), customer_requests.MAX_PER_DAY)

    def test_soc_permissions_scope_and_incident(self):
        self.create(kind='incident')
        req = CustomerRequest.objects.get()
        other_req = CustomerRequest.objects.create(client=self.other, kind='question', subject='Ajena')
        self.client.force_login(self.operator)
        listing = self.client.get(reverse('requests'))
        self.assertContains(listing, 'No abre la web')
        self.assertNotContains(listing, 'Ajena')
        self.assertEqual(self.client.get(reverse('request_detail', args=[other_req.pk])).status_code, 404)
        self.assertContains(self.client.get(reverse('work_queue')), 'Solicitudes de clientes')
        response = self.client.post(reverse('request_detail', args=[req.pk]), {'action': 'incident'})
        incident = Incident.objects.get()
        self.assertRedirects(response, reverse('incident_detail', args=[incident.pk]), fetch_redirect_response=False)
        self.assertEqual((incident.client, incident.severity), (self.company, 'high'))
        self.assertEqual(CustomerRequest.objects.get(pk=req.pk).incident, incident)
        reader = get_user_model().objects.create_user('lector')
        StaffAccess.objects.create(user=reader, role='reader').clients.add(self.company)
        self.client.force_login(reader)
        self.assertEqual(self.client.post(reverse('request_detail', args=[req.pk]), {'action': 'reply', 'status': 'resolved',
                                                                                      'text': 'x'}).status_code, 403)
        self.assertEqual(CustomerRequestEntry.objects.filter(kind='soc').count(), 0)

    def test_preview_is_read_only(self):
        self.create()
        self.client.force_login(self.operator)
        page = self.client.get(reverse('customer_preview_requests', args=[self.company.pk]))
        self.assertContains(page, 'No abre la web')
        self.assertNotContains(page, 'Enviar al SOC')

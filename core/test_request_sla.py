"""Plazos de respuesta de las solicitudes de clientes."""
from datetime import timedelta
from unittest import mock

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from . import request_sla
from .models import Client, CustomerRequest, CustomerRequestEntry, OperationalIssue, SlaSettings, StaffAccess


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class RequestSlaTests(TestCase):
    def setUp(self):
        self.now = timezone.now()
        self.company = Client.objects.create(name='Empresa A', code='a')
        self.config = SlaSettings.objects.create(pk=1, requests_enabled=True, requests_enabled_at=self.now - timedelta(days=30))
        self.operator = get_user_model().objects.create_user('operador')
        StaffAccess.objects.create(user=self.operator, role='manager', all_clients=True)
        self.operator.user_permissions.add(*Permission.objects.filter(codename__in=['change_incident', 'manage_operations']))
        self.customer = get_user_model().objects.create_user('ana', email='ana@a.test')
        StaffAccess.objects.create(user=self.customer, role='customer').clients.add(self.company)

    def request(self, hours_ago, **extra):
        values = {'kind': 'question', 'subject': 'Duda', 'created_by': self.customer, 'contact_email': 'ana@a.test', **extra}
        return CustomerRequest.objects.create(client=self.company, created_at=self.now - timedelta(hours=hours_ago), **values)

    def states(self, req):
        return {row['key']: row['state'] for row in request_sla.evaluate(req, self.now)}

    def test_targets_depend_on_urgency_and_only_new_requests_count(self):
        self.assertEqual(self.states(self.request(1)), {'response': 'running', 'resolve': 'running'})
        self.assertEqual(self.states(self.request(7)), {'response': 'soon', 'resolve': 'running'})
        self.assertEqual(self.states(self.request(9)), {'response': 'breached', 'resolve': 'running'})
        self.assertEqual(self.states(self.request(2, urgent=True))['response'], 'breached')  # 1 h para las urgentes
        self.assertEqual(self.states(self.request(2, kind='incident'))['response'], 'breached')
        answered = self.request(9, first_response_at=self.now - timedelta(hours=8))
        self.assertEqual(self.states(answered)['response'], 'met')
        late = self.request(12, first_response_at=self.now - timedelta(hours=1))
        self.assertEqual(self.states(late)['response'], 'late')
        self.assertEqual(request_sla.evaluate(self.request(24 * 40), self.now), [])  # anterior a la activación
        SlaSettings.objects.update(requests_enabled=False)
        self.assertEqual(request_sla.evaluate(self.request(9), self.now), [])

    def test_time_waiting_for_the_customer_does_not_count(self):
        six_days = 6 * 24
        req = self.request(six_days, first_response_at=self.now - timedelta(days=5, hours=20), status='in_progress')
        self.assertEqual(self.states(req)['resolve'], 'breached')
        waiting = self.request(six_days, first_response_at=self.now - timedelta(days=5, hours=20), status='waiting',
                               waiting_since=self.now - timedelta(days=3))
        self.assertEqual(self.states(waiting)['resolve'], 'paused')
        fields = request_sla.transition_fields(waiting, 'in_progress', self.now)
        self.assertEqual(fields['waiting_since'], None)
        self.assertEqual(fields['waited_seconds'], 3 * 86400)
        CustomerRequest.objects.filter(pk=waiting.pk).update(status='in_progress', **fields)
        waiting.refresh_from_db()
        self.assertEqual(self.states(waiting)['resolve'], 'running')  # 6 días menos 3 de espera: dentro de los 5

    def test_views_record_waiting_time(self):
        req = self.request(1)
        self.client.force_login(self.operator)
        self.client.post(reverse('request_detail', args=[req.pk]), {'action': 'reply', 'status': 'waiting', 'text': '¿Qué web?'})
        req.refresh_from_db()
        self.assertIsNotNone(req.waiting_since)
        CustomerRequest.objects.filter(pk=req.pk).update(waiting_since=timezone.now() - timedelta(hours=5))
        self.client.force_login(self.customer)
        self.client.post(reverse('customer_request_detail', args=[req.pk]), {'text': 'proveedor.example'})
        req.refresh_from_db()
        self.assertIsNone(req.waiting_since)
        self.assertGreaterEqual(req.waited_seconds, 5 * 3600 - 5)

    def test_breach_is_recorded_once_and_cleared_when_met(self):
        req = self.request(9, urgent=True)
        with mock.patch('core.security.audit'):
            self.assertEqual(request_sla.check(self.now), 1)
            self.assertEqual(request_sla.check(self.now), 1)
        issue = OperationalIssue.objects.get(key=f'request-sla:{req.pk}:response')
        self.assertEqual((issue.active, issue.severity), (True, 'critical'))
        self.assertEqual(CustomerRequestEntry.objects.filter(request=req, kind='internal').count(), 1)
        self.client.force_login(self.operator)
        dashboard = self.client.get(reverse('dashboard'))
        self.assertContains(dashboard, '1 plazo vencido')
        self.assertNotContains(dashboard, 'Fallos de la plataforma')
        self.assertContains(self.client.get(reverse('requests')), 'vencido')
        self.assertContains(self.client.get(reverse('request_detail', args=[req.pk])), 'Primera respuesta')
        self.client.post(reverse('request_detail', args=[req.pk]), {'action': 'reply', 'status': 'in_progress', 'text': 'Lo miramos'})
        request_sla.check(timezone.now())
        self.assertFalse(OperationalIssue.objects.get(pk=issue.pk).active)
        # El cliente no ve la nota interna del plazo vencido.
        self.client.force_login(self.customer)
        self.assertNotContains(self.client.get(reverse('customer_request_detail', args=[req.pk])), 'Plazo de primera respuesta vencido')

    def test_customer_sees_the_commitment_only_if_enabled(self):
        req = self.request(1)
        self.client.force_login(self.customer)
        url = reverse('customer_request_detail', args=[req.pk])
        self.assertNotContains(self.client.get(url), 'Os responderemos antes del')
        SlaSettings.objects.update(requests_visible=True)
        self.assertContains(self.client.get(url), 'Os responderemos antes del')
        CustomerRequest.objects.filter(pk=req.pk).update(first_response_at=self.now)
        self.assertNotContains(self.client.get(url), 'Os responderemos antes del')

    def test_settings_page_saves_and_validates(self):
        SlaSettings.objects.update(requests_enabled=False, requests_enabled_at=None)
        self.client.force_login(self.operator)
        data = {'action': 'requests', 'request_response_minutes': '4 h', 'request_resolve_minutes': '3 d',
                'request_urgent_response_minutes': '30 min', 'request_urgent_resolve_minutes': '8 h', 'requests_enabled': 'on', 'requests_visible': 'on'}
        self.assertContains(self.client.get(reverse('sla_settings')), 'Plazos de las solicitudes de clientes')
        self.client.post(reverse('sla_settings'), data)
        config = SlaSettings.objects.get(pk=1)
        self.assertEqual((config.request_response_minutes, config.request_resolve_minutes, config.request_urgent_response_minutes,
                          config.requests_enabled, config.requests_visible), (240, 4320, 30, True, True))
        self.assertIsNotNone(config.requests_enabled_at)
        response = self.client.post(reverse('sla_settings'), {**data, 'request_response_minutes': '9 d'})
        self.assertContains(response, 'no puede tener más plazo')
        self.assertEqual(SlaSettings.objects.get(pk=1).request_response_minutes, 240)

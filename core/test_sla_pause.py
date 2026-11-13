"""Pausa del plazo de resolución de una incidencia mientras se espera al cliente, y bandeja de solicitudes."""
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from . import sla
from .models import Client, CustomerRequest, CustomerTask, Incident, OperationalIssue, SlaSettings


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class IncidentPauseTests(TestCase):
    def setUp(self):
        self.now = timezone.now()
        self.company = Client.objects.create(name='Empresa A', code='a')
        self.config = SlaSettings.objects.create(pk=1, enabled=True, enabled_at=self.now - timedelta(days=60), pause_incidents_waiting=True)
        self.resolve_minutes = sla.DEFAULTS['critical'][2]

    def incident(self, minutes_ago):
        incident = Incident.objects.create(client=self.company, title='Caso', description='d', severity='critical')
        Incident.objects.filter(pk=incident.pk).update(created_at=self.now - timedelta(minutes=minutes_ago))
        incident.refresh_from_db()
        return incident

    def resolve_row(self, incident, now=None):
        incident.refresh_from_db()
        return sla.evaluate(incident, now or self.now)[2]

    def test_waiting_for_the_customer_pauses_only_the_resolution(self):
        incident = self.incident(self.resolve_minutes + 60)  # vencido por una hora
        self.assertEqual(self.resolve_row(incident)['state'], 'breached')
        task = CustomerTask.objects.create(incident=incident, title='Revisar el equipo', instructions='Pasos', visible=True)
        self.assertEqual(sla.sync_waiting(self.now - timedelta(hours=3)), 1)
        rows = sla.evaluate(Incident.objects.get(pk=incident.pk), self.now)
        self.assertEqual((rows[0]['state'], rows[2]['state'], rows[2]['state_label']),
                         ('breached', 'paused', 'En pausa: esperando al cliente'))  # el acuse no se pausa
        # El cliente responde: la espera se suma y el plazo se alarga esas tres horas.
        CustomerTask.objects.filter(pk=task.pk).update(status='submitted')
        self.assertEqual(sla.sync_waiting(self.now), 1)
        incident.refresh_from_db()
        self.assertEqual((incident.sla_waiting_since, incident.sla_waited_seconds), (None, 3 * 3600))
        row = self.resolve_row(incident)
        self.assertEqual(row['state'], 'pending' if row['deadline'] - self.now > timedelta(minutes=self.resolve_minutes) * sla.DUE_SOON else 'due_soon')
        self.assertEqual(row['deadline'], incident.created_at + timedelta(minutes=self.resolve_minutes) + timedelta(hours=3))

    def test_hidden_tasks_and_disabled_setting_do_not_pause(self):
        incident = self.incident(self.resolve_minutes + 60)
        CustomerTask.objects.create(incident=incident, title='Borrador', instructions='Pasos', visible=False)
        self.assertEqual(sla.sync_waiting(self.now), 0)
        CustomerTask.objects.update(visible=True)
        SlaSettings.objects.update(pause_incidents_waiting=False)
        self.assertEqual(sla.sync_waiting(self.now), 0)
        self.assertEqual(self.resolve_row(incident)['state'], 'breached')

    def test_check_clears_the_alert_while_paused_and_resolving_ends_the_wait(self):
        incident = self.incident(self.resolve_minutes + 60)
        sla.record(incident, 'acknowledge', 'investigate', now=incident.created_at + timedelta(minutes=1))
        sla.check(self.now)
        key = f'sla:{incident.pk}:resolve'
        self.assertTrue(OperationalIssue.objects.get(key=key).active)
        CustomerTask.objects.create(incident=incident, title='Revisar', instructions='Pasos', visible=True)
        sla.check(self.now)  # sincroniza la espera y retira el aviso
        self.assertFalse(OperationalIssue.objects.get(key=key).active)
        Incident.objects.filter(pk=incident.pk).update(status='resolved', resolved_at=self.now + timedelta(hours=2))
        sla.sync_waiting(self.now + timedelta(hours=5))
        incident.refresh_from_db()
        self.assertEqual((incident.sla_waiting_since, incident.sla_waited_seconds), (None, 2 * 3600))  # hasta la resolución, no hasta ahora


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class WorkQueueRequestsTests(TestCase):
    def test_requests_show_even_without_overdue_actions(self):
        company = Client.objects.create(name='Empresa A', code='a')
        CustomerRequest.objects.create(client=company, kind='question', subject='Duda sobre el informe')
        self.client.force_login(get_user_model().objects.create_superuser('admin', 'a@x.test', 'x'))
        page = self.client.get(reverse('work_queue'))
        self.assertContains(page, 'id="solicitudes"')
        self.assertContains(page, 'Duda sobre el informe')
        self.assertNotContains(page, 'id="acciones-vencidas"')

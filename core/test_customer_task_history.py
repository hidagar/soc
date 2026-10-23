"""Bloque 5: historial completo de tareas, reapertura de acciones y pendientes visibles."""
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from .models import Client, CustomerTask, CustomerTaskEntry, Incident, IncidentAction, IncidentUpdate, StaffAccess


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class CustomerTaskHistoryTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.company = Client.objects.create(name='Empresa A', code='a')
        self.other = Client.objects.create(name='Empresa B', code='b')
        self.case = Incident.objects.create(client=self.company, title='Caso', description='Detalle')
        self.analyst = User.objects.create_user('analista')
        StaffAccess.objects.create(user=self.analyst, role='operator', all_clients=True)
        self.analyst.user_permissions.add(Permission.objects.get(codename='change_incident'))
        self.customer = User.objects.create_user('cliente-a')
        StaffAccess.objects.create(user=self.customer, role='customer').clients.add(self.company)
        self.action = IncidentAction.objects.create(incident=self.case, title='Actualizar el equipo',
                                                    responsible_party='client', status='awaiting_client')
        self.task = CustomerTask.objects.create(incident=self.case, action=self.action, title='Actualizar',
                                                instructions='Pasos', visible=True)

    def reply(self, text):
        self.client.force_login(self.customer)
        return self.client.post(reverse('customer_task_reply', args=[self.task.pk]), {'response': text})

    def review(self, status, note):
        self.client.force_login(self.analyst)
        data = {'title': self.task.title, 'instructions': self.task.instructions, 'status': status,
                'review_note': note, 'action': self.action.pk, 'visible': 'on'}
        return self.client.post(reverse('customer_task_edit', args=[self.task.pk]), data)

    def test_history_keeps_every_response_and_review_in_order(self):
        self.assertEqual(self.reply('Primer intento').status_code, 302)
        self.assertEqual(self.review('rework', 'Falta el resultado del análisis').status_code, 302)
        self.assertEqual(self.reply('Análisis completo sin hallazgos').status_code, 302)
        self.assertEqual(self.review('accepted', 'Comprobado en el firewall').status_code, 302)
        history = list(self.task.entries.values_list('kind', 'status', 'text'))
        self.assertEqual(history, [
            ('response', 'submitted', 'Primer intento'),
            ('review', 'rework', 'Falta el resultado del análisis'),
            ('response', 'submitted', 'Análisis completo sin hallazgos'),
            ('review', 'accepted', 'Comprobado en el firewall'),
        ])
        self.client.force_login(self.customer)
        page = self.client.get(reverse('customer_task_reply', args=[self.task.pk]))
        for text in ('Primer intento', 'Falta el resultado del análisis', 'Comprobado en el firewall'):
            self.assertContains(page, text)

    def test_saving_without_changes_does_not_duplicate_reviews(self):
        self.reply('Hecho')
        self.review('accepted', 'Comprobado')
        self.review('accepted', 'Comprobado')
        self.assertEqual(self.task.entries.filter(kind='review').count(), 1)

    def test_reopening_a_task_reopens_its_completed_action(self):
        self.reply('Hecho')
        self.review('accepted', 'Comprobado')
        self.action.refresh_from_db()
        self.assertEqual(self.action.status, 'done')
        self.review('rework', 'El equipo vuelve a generar alertas')
        self.action.refresh_from_db()
        self.assertEqual((self.action.status, self.action.completed_at), ('awaiting_client', None))
        self.assertTrue(IncidentUpdate.objects.filter(incident=self.case, text__contains='Acción reabierta').exists())

    def test_cancelled_action_is_not_reopened(self):
        self.action.status = 'cancelled'
        self.action.save()
        self.review('rework', 'Más información')
        self.action.refresh_from_db()
        self.assertEqual(self.action.status, 'cancelled')

    def test_pending_tasks_are_never_displaced_by_closed_ones(self):
        now = timezone.now()
        CustomerTask.objects.bulk_create([
            CustomerTask(incident=self.case, title=f'Cerrada {i}', instructions='x', visible=True, status='accepted',
                         reviewed_at=now - timedelta(minutes=i), due_at=now - timedelta(days=400 - i))
            for i in range(150)])
        undated = CustomerTask.objects.create(incident=self.case, title='Pendiente sin fecha', instructions='x', visible=True)
        late = CustomerTask.objects.create(incident=self.case, title='Pendiente lejana', instructions='x', visible=True,
                                           due_at=now + timedelta(days=30))
        self.client.force_login(self.customer)
        home = self.client.get(reverse('customer_home'))
        page = self.client.get(reverse('customer_tasks'))
        for pending in (undated, late):
            self.assertContains(home, reverse('customer_task_reply', args=[pending.pk]))
            self.assertContains(page, reverse('customer_task_reply', args=[pending.pk]))
        self.assertContains(page, 'Actuaciones cerradas')
        self.assertEqual(page.content.decode().count('Cerrada '), 20)

    def test_history_of_another_company_is_never_visible(self):
        foreign_case = Incident.objects.create(client=self.other, title='Ajeno', description='x')
        foreign = CustomerTask.objects.create(incident=foreign_case, title='Ajena', instructions='x', visible=True)
        CustomerTaskEntry.objects.create(task=foreign, kind='review', status='rework', text='Nota de otra empresa')
        self.client.force_login(self.customer)
        self.assertEqual(self.client.get(reverse('customer_task_reply', args=[foreign.pk])).status_code, 404)
        self.assertNotContains(self.client.get(reverse('customer_home')), 'Nota de otra empresa')
        self.assertNotContains(self.client.get(reverse('customer_tasks')), 'Ajena')


class HistorySeedMigrationTests(TestCase):
    def test_existing_response_and_review_become_history(self):
        from importlib import import_module
        from django.apps import apps
        from django.db import connection
        seed = import_module('core.migrations.0048_customer_task_history').seed_history
        company = Client.objects.create(name='A', code='a')
        case = Incident.objects.create(client=company, title='Caso', description='x')
        submitted = timezone.now() - timedelta(days=3)
        task = CustomerTask.objects.create(incident=case, title='T', instructions='x', response='Respuesta antigua',
                                           submitted_at=submitted, review_note='Revisión antigua', status='accepted',
                                           reviewed_at=submitted + timedelta(hours=2))
        CustomerTask.objects.create(incident=case, title='Sin respuesta', instructions='x')

        class Editor:
            pass
        editor = Editor()
        editor.connection = connection
        seed(apps, editor)
        self.assertEqual(list(task.entries.values_list('kind', 'text', 'created_at')), [
            ('response', 'Respuesta antigua', submitted),
            ('review', 'Revisión antigua', submitted + timedelta(hours=2)),
        ])
        self.assertEqual(CustomerTaskEntry.objects.count(), 2)

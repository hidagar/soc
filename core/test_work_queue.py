from datetime import timedelta
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase, override_settings, Client as Browser
from django.urls import reverse
from django.utils import timezone
from .models import Client, Site, Device, Incident, IncidentAction, IncidentUpdate, OperationalIssue, StaffAccess, AuditEvent


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class WorkQueueTests(TestCase):
    def setUp(self):
        self.company = Client.objects.create(name='Visible', code='visible')
        self.other = Client.objects.create(name='Otro cliente', code='other')
        self.site = Site.objects.create(client=self.company, name='Oficina', code='office')
        self.device = Device.objects.create(site=self.site, name='Firewall', vendor='opnsense')
        self.other_site = Site.objects.create(client=self.other, name='Otra sede', code='other')
        self.other_device = Device.objects.create(site=self.other_site, name='Otro firewall', vendor='opnsense')
        self.case = Incident.objects.create(client=self.company, device=self.device, title='Caso urgente', severity='critical')
        self.secret = Incident.objects.create(client=self.other, title='Caso privado', severity='critical')
        self.operator = get_user_model().objects.create_user('operator')
        access = StaffAccess.objects.create(user=self.operator, role='operator')
        access.clients.add(self.company)
        self.operator.groups.add(Group.objects.get(name='SOC Operador'))
        self.client.force_login(self.operator)

    def test_scope_applies_to_counts_cases_actions_issues_and_forged_client(self):
        IncidentAction.objects.create(incident=self.secret, title='Tarea privada', due_at=timezone.now()-timedelta(days=1))
        OperationalIssue.objects.create(device=self.other_device, key='other', title='Aviso privado')
        response = self.client.get(reverse('work_queue'), {'queue': 'all'})
        self.assertContains(response, 'Caso urgente')
        for title in ('Caso privado', 'Tarea privada', 'Aviso privado'):
            self.assertNotContains(response, title)
        self.assertEqual(response.context['counts']['unassigned'], 1)
        self.assertEqual(response.context['counts']['overdue'], 0)
        self.assertEqual(self.client.get(reverse('work_queue'), {'client': self.other.pk}).status_code, 404)
        self.assertEqual(self.client.post(reverse('claim_incident', args=[self.secret.pk])).status_code, 404)

    def test_claim_is_idempotent_and_records_one_timeline_and_audit(self):
        url = reverse('claim_incident', args=[self.case.pk])
        self.assertEqual(self.client.get(url).status_code, 405)
        self.assertEqual(self.client.post(url).status_code, 302)
        self.client.post(url)
        self.case.refresh_from_db()
        self.assertEqual(self.case.owner, self.operator)
        self.assertEqual(self.case.status, 'investigating')
        self.assertEqual(self.case.timeline.count(), 1)
        self.assertEqual(AuditEvent.objects.filter(action='incident.claimed').count(), 1)

    def test_cannot_take_existing_owner_or_resolved_case(self):
        owner = get_user_model().objects.create_user('assigned')
        self.case.owner = owner
        self.case.save()
        self.client.post(reverse('claim_incident', args=[self.case.pk]))
        self.case.refresh_from_db()
        self.assertEqual(self.case.owner, owner)
        self.case.owner = None
        self.case.status = 'resolved'
        self.case.save()
        self.client.post(reverse('claim_incident', args=[self.case.pk]))
        self.case.refresh_from_db()
        self.assertIsNone(self.case.owner)
        self.assertEqual(self.case.status, 'resolved')
        self.assertFalse(self.case.timeline.exists())

    def test_note_activity_prevents_false_stale_and_resolved_not_counted(self):
        Incident.objects.filter(pk=self.case.pk).update(updated_at=timezone.now()-timedelta(days=2))
        response = self.client.get(reverse('work_queue'), {'queue': 'stale'})
        self.assertEqual(response.context['counts']['stale'], 1)
        IncidentUpdate.objects.create(incident=self.case, author=self.operator, text='Seguimiento reciente')
        response = self.client.get(reverse('work_queue'), {'queue': 'stale'})
        self.assertEqual(response.context['counts']['stale'], 0)
        self.assertNotContains(response, 'Caso urgente')
        self.case.status = 'resolved'
        self.case.save()
        response = self.client.get(reverse('work_queue'))
        self.assertEqual(response.context['counts']['priority'], 0)

    def test_readers_and_customers_cannot_claim(self):
        access = self.operator.soc_access
        access.role = 'reader'
        access.save()
        self.operator.groups.clear()
        self.operator.groups.add(Group.objects.get(name='SOC Consulta'))
        self.assertEqual(self.client.get(reverse('work_queue')).status_code, 200)
        self.assertEqual(self.client.post(reverse('claim_incident', args=[self.case.pk])).status_code, 403)
        access.role = 'customer'
        access.save()
        self.operator.groups.add(Group.objects.get(name='SOC Administrador'))
        self.assertEqual(self.client.get(reverse('work_queue')).status_code, 403)
        self.assertEqual(self.client.post(reverse('claim_incident', args=[self.case.pk])).status_code, 403)

    def test_claim_requires_csrf(self):
        browser = Browser(enforce_csrf_checks=True)
        browser.force_login(self.operator)
        self.assertEqual(browser.post(reverse('claim_incident', args=[self.case.pk])).status_code, 403)
        self.case.refresh_from_db()
        self.assertIsNone(self.case.owner)

    def test_ordering_and_overdue_exclude_closed_actions(self):
        older = Incident.objects.create(client=self.company, title='Alta antigua', severity='high', observed_at=timezone.now()-timedelta(days=3))
        IncidentAction.objects.create(incident=self.case, title='Vencida', due_at=timezone.now()-timedelta(days=1))
        IncidentAction.objects.create(incident=self.case, title='Completada', status='done', due_at=timezone.now()-timedelta(days=1))
        response = self.client.get(reverse('work_queue'), {'queue': 'priority'})
        self.assertEqual([i.pk for i in response.context['incidents']], [self.case.pk, older.pk])
        self.assertEqual(response.context['counts']['overdue'], 1)
        self.assertEqual(len(response.context['overdue_actions']), 1)

    def test_global_selected_client_filters_health_issues_and_work_queue(self):
        access = self.operator.soc_access
        access.all_clients = True
        access.save()
        OperationalIssue.objects.create(device=self.device, key='visible', title='Aviso visible')
        OperationalIssue.objects.create(device=self.other_device, key='other', title='Aviso privado')
        for route in ('work_queue', 'health_list'):
            response = self.client.get(reverse(route), {'client': self.company.pk})
            self.assertContains(response, 'Aviso visible')
            self.assertNotContains(response, 'Aviso privado')
        response = self.client.get(reverse('work_queue'), {'client': self.company.pk})
        self.assertEqual(response.context['counts']['priority'], 1)

"""Plazos de atención (hoja de ruta 5): cálculo, hitos, escalado e interfaz."""
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from . import sla
from .background_jobs import execute
from .models import (AuditEvent, Client, Device, DeviceHealth, Incident, IncidentUpdate, OperationalIssue, Site,
                     SlaPolicy, SlaSettings, StaffAccess)
from .testing_access import FreshMfaClient


class DurationTests(SimpleTestCase):
    def test_round_trip_and_errors(self):
        for text, minutes in (('30 min', 30), ('4 h', 240), ('3 d', 4320), ('1 d 6 h', 1800), ('45', 45), ('2H', 120)):
            self.assertEqual(sla.parse_duration(text), minutes)
            self.assertEqual(sla.parse_duration(sla.duration(minutes)), minutes)
        for text in ('', 'pronto', '4 semanas', '0', '91 d', '4 h y algo'):
            with self.assertRaises(ValueError):
                sla.parse_duration(text)


class SlaCase(TestCase):
    def setUp(self):
        self.company = Client.objects.create(name='Conservas Norte', code='norte')
        self.device = Device.objects.create(site=Site.objects.create(client=self.company, name='Sede', code='s'),
                                            name='FW', vendor='opnsense')
        self.now = timezone.now()
        SlaSettings.objects.create(pk=1, enabled=True, enabled_at=self.now - timedelta(days=30))

    def incident(self, severity='critical', minutes_ago=0, **extra):
        incident = Incident.objects.create(client=self.company, device=self.device, title='Escaneo contra RDP',
                                           description='x', severity=severity, observed_at=self.now, **extra)
        Incident.objects.filter(pk=incident.pk).update(created_at=self.now - timedelta(minutes=minutes_ago))
        incident.refresh_from_db()
        return incident

    def states(self, incident, now=None):
        return {row['key']: row['state'] for row in sla.evaluate(incident, now or self.now)}


class EvaluateTests(SlaCase):
    def test_states_follow_the_targets_of_the_severity(self):
        # Crítica: acuse 15 min, diagnóstico 1 h, resolución 1 d.
        self.assertEqual(self.states(self.incident(minutes_ago=5)),
                         {'acknowledge': 'pending', 'investigate': 'pending', 'resolve': 'pending'})
        self.assertEqual(self.states(self.incident(minutes_ago=12))['acknowledge'], 'due_soon')
        self.assertEqual(self.states(self.incident(minutes_ago=20))['acknowledge'], 'breached')
        late = self.incident(minutes_ago=90)
        Incident.objects.filter(pk=late.pk).update(acknowledged_at=self.now - timedelta(minutes=85),
                                                   investigated_at=self.now - timedelta(minutes=10))
        late.refresh_from_db()
        self.assertEqual(self.states(late), {'acknowledge': 'met', 'investigate': 'late', 'resolve': 'pending'})

    def test_only_cases_created_after_activation_count(self):
        SlaSettings.objects.filter(pk=1).update(enabled_at=self.now - timedelta(minutes=10))
        self.assertEqual(sla.evaluate(self.incident(minutes_ago=60), self.now), [])
        SlaSettings.objects.filter(pk=1).update(enabled=False)
        self.assertEqual(sla.evaluate(self.incident(minutes_ago=5), self.now), [])

    def test_client_policy_overrides_the_global_one(self):
        SlaPolicy.objects.create(client=None, severity='medium', acknowledge_minutes=60, investigate_minutes=120,
                                 resolve_minutes=600)
        incident = self.incident('medium', minutes_ago=90)
        self.assertEqual(self.states(incident)['acknowledge'], 'breached')
        SlaPolicy.objects.create(client=self.company, severity='medium', acknowledge_minutes=180,
                                 investigate_minutes=240, resolve_minutes=600)
        self.assertEqual(self.states(incident)['acknowledge'], 'pending')

    def test_a_resolved_case_has_been_acknowledged_and_investigated(self):
        incident = self.incident(minutes_ago=600, status='resolved', resolved_at=self.now - timedelta(minutes=30))
        self.assertEqual(self.states(incident), {'acknowledge': 'late', 'investigate': 'late', 'resolve': 'met'})


@override_settings(SECURE_SSL_REDIRECT=False)
class MilestoneTests(SlaCase):
    client_class = FreshMfaClient

    def setUp(self):
        super().setUp()
        self.admin = get_user_model().objects.create_superuser('admin', 'admin@example.test', 'x')
        self.client.force_login(self.admin)

    def test_claiming_acknowledges_and_a_note_documents_the_diagnosis(self):
        incident = self.incident(minutes_ago=5)
        self.client.post(reverse('claim_incident', args=[incident.pk]))
        incident.refresh_from_db()
        self.assertIsNotNone(incident.acknowledged_at)
        self.assertIsNone(incident.investigated_at)
        first = incident.acknowledged_at
        self.client.post(reverse('incident_note', args=[incident.pk]), {'text': 'Origen identificado: escaneo masivo.'})
        incident.refresh_from_db()
        self.assertIsNotNone(incident.investigated_at)
        self.assertEqual(incident.acknowledged_at, first)  # la primera vez no se pisa

    def test_a_note_alone_also_counts_as_acknowledgement(self):
        incident = self.incident(minutes_ago=5)
        self.client.post(reverse('incident_note', args=[incident.pk]), {'text': 'Revisado.'})
        incident.refresh_from_db()
        self.assertEqual(incident.acknowledged_at, incident.investigated_at)

    def test_resolving_from_the_form_closes_every_milestone(self):
        incident = self.incident(minutes_ago=5)
        data = {'client': self.company.pk, 'title': incident.title, 'description': 'x', 'severity': 'critical',
                'status': 'resolved', 'observed_at': timezone.localtime(self.now).strftime('%Y-%m-%dT%H:%M')}
        self.assertEqual(self.client.post(reverse('incident_edit', args=[incident.pk]), data).status_code, 302)
        incident.refresh_from_db()
        self.assertTrue(incident.acknowledged_at and incident.investigated_at and incident.resolved_at)


class EscalationTests(SlaCase):
    def test_a_breach_is_recorded_once_and_cleared_when_met(self):
        incident = self.incident('high', minutes_ago=45)  # alta: acuse 30 min
        self.assertEqual(sla.check(self.now), 1)
        self.assertEqual(sla.check(self.now + timedelta(minutes=1)), 1)
        incident.refresh_from_db()
        self.assertIn('acknowledge', incident.sla_breaches)
        self.assertEqual(IncidentUpdate.objects.filter(incident=incident, text__startswith='Plazo de acuse').count(), 1)
        self.assertEqual(AuditEvent.objects.filter(action='incident.sla_breached').count(), 1)
        issue = OperationalIssue.objects.get(key=f'sla:{incident.pk}:acknowledge', active=True)
        self.assertEqual((issue.severity, issue.device_id), ('critical', self.device.pk))
        sla.record(incident, 'acknowledge')
        sla.check(self.now + timedelta(minutes=2))
        self.assertFalse(OperationalIssue.objects.filter(key__startswith='sla:', active=True).exists())
        self.assertIn('acknowledge', Incident.objects.get(pk=incident.pk).sla_breaches)  # queda constancia

    def test_low_severity_is_a_warning_and_disabling_clears_the_alerts(self):
        incident = self.incident('low', minutes_ago=25 * 60)  # baja: acuse 1 d
        sla.check(self.now)
        self.assertEqual(OperationalIssue.objects.get(key=f'sla:{incident.pk}:acknowledge').severity, 'warning')
        SlaSettings.objects.filter(pk=1).update(enabled=False)
        sla.check(self.now)
        self.assertFalse(OperationalIssue.objects.filter(key__startswith='sla:', active=True).exists())

    def test_the_notifications_job_escalates(self):
        self.incident('critical', minutes_ago=20)
        execute('notifications')
        self.assertTrue(OperationalIssue.objects.filter(key__startswith='sla:', active=True).exists())


@override_settings(SECURE_SSL_REDIRECT=False)
class InterfaceTests(SlaCase):
    client_class = FreshMfaClient

    def setUp(self):
        super().setUp()
        self.admin = get_user_model().objects.create_superuser('admin', 'admin@example.test', 'x')
        self.client.force_login(self.admin)

    def test_queue_dashboard_and_detail_show_the_deadlines(self):
        late = self.incident(minutes_ago=30)
        self.incident('low', minutes_ago=5)
        page = self.client.get(reverse('work_queue') + '?queue=sla')
        self.assertEqual([i.pk for i in page.context['incidents']], [late.pk])
        self.assertContains(page, 'Acuse: vencido hace')
        rows = {row['title']: row['count'] for row in self.client.get(reverse('dashboard')).context['attention']}
        self.assertEqual(rows['Incidencias con plazo de atención vencido'], 1)
        sla.check(self.now)
        rows = {row['title']: row['count'] for row in self.client.get(reverse('dashboard')).context['attention']}
        self.assertNotIn('Fallos de la plataforma del SOC', rows)  # el aviso de plazo no cuenta dos veces
        self.assertContains(self.client.get(reverse('incident_detail', args=[late.pk])), 'Plazos de atención')

    def test_without_activation_nothing_appears(self):
        SlaSettings.objects.filter(pk=1).update(enabled=False)
        self.incident(minutes_ago=30)
        page = self.client.get(reverse('work_queue'))
        self.assertNotContains(page, 'Plazo vencido o próximo')
        self.assertEqual(self.client.get(reverse('work_queue') + '?queue=sla').context['queue'], 'unassigned')


@override_settings(SECURE_SSL_REDIRECT=False)
class SettingsViewTests(TestCase):
    client_class = FreshMfaClient

    def setUp(self):
        self.company = Client.objects.create(name='Conservas Norte', code='norte')
        self.admin = get_user_model().objects.create_superuser('admin', 'admin@example.test', 'x')
        self.url = reverse('sla_settings')

    def table(self, ack='15 min', inv='1 h', res='1 d'):
        return {f'{s}_{k}': v for s in ('critical', 'high', 'medium', 'low')
                for k, v in (('acknowledge', ack), ('investigate', inv), ('resolve', res))}

    def test_scoped_staff_cannot_change_the_deadlines(self):
        operator = get_user_model().objects.create_user('op', 'op@example.test', 'x')
        StaffAccess.objects.create(user=operator, role='operator').clients.add(self.company)
        operator.user_permissions.add(Permission.objects.get(codename='manage_operations'))
        self.client.force_login(operator)
        self.assertEqual(self.client.get(self.url).status_code, 403)

    def test_enabling_starts_counting_now_and_bad_values_are_refused(self):
        self.client.force_login(self.admin)
        self.assertContains(self.client.post(self.url, {'action': 'global', **self.table(ack='2 h', inv='1 h')}),
                            'el acuse no puede ser posterior')
        self.assertFalse(SlaPolicy.objects.exists())
        self.client.post(self.url, {'action': 'global', 'enabled': 'on', **self.table()})
        config = SlaSettings.objects.get(pk=1)
        self.assertTrue(config.enabled)
        self.assertLess(timezone.now() - config.enabled_at, timedelta(minutes=1))
        self.assertEqual(SlaPolicy.objects.filter(client=None).count(), 4)
        started = config.enabled_at
        self.client.post(self.url, {'action': 'global', 'enabled': 'on', **self.table()})
        self.assertEqual(SlaSettings.objects.get(pk=1).enabled_at, started)  # guardar otra vez no reinicia

    def test_client_overrides_and_blank_rows_fall_back(self):
        self.client.force_login(self.admin)
        data = {'action': 'client', 'client': self.company.pk, **{k: '' for k in self.table()},
                'critical_acknowledge': '5 min', 'critical_investigate': '30 min', 'critical_resolve': '8 h'}
        self.client.post(self.url, data)
        row = SlaPolicy.objects.get(client=self.company)
        self.assertEqual((row.severity, row.acknowledge_minutes, row.resolve_minutes), ('critical', 5, 480))
        data['critical_resolve'] = ''
        self.assertContains(self.client.post(self.url, data), 'indica los tres plazos')
        self.client.post(self.url, {'action': 'client', 'client': self.company.pk, **{k: '' for k in self.table()}})
        self.assertFalse(SlaPolicy.objects.filter(client=self.company).exists())


@override_settings(SECURE_SSL_REDIRECT=False)
class MaintenanceReasonTests(TestCase):
    client_class = FreshMfaClient

    def test_maintenance_needs_a_reason_and_a_limit(self):
        company = Client.objects.create(name='C', code='c')
        device = Device.objects.create(site=Site.objects.create(client=company, name='S', code='s'), name='FW',
                                       vendor='opnsense')
        self.client.force_login(get_user_model().objects.create_superuser('admin', 'admin@example.test', 'x'))
        url = reverse('health_device', args=[device.pk])
        until = timezone.localtime(timezone.now() + timedelta(days=1)).strftime('%Y-%m-%dT%H:%M')
        page = self.client.post(url, {'expected_silence_minutes': 0, 'maintenance_until': until})
        self.assertContains(page, 'Indica el motivo')
        far = timezone.localtime(timezone.now() + timedelta(days=45)).strftime('%Y-%m-%dT%H:%M')
        self.assertContains(self.client.post(url, {'expected_silence_minutes': 0, 'maintenance_until': far,
                                                   'maintenance_reason': 'Cambio de línea'}), 'como máximo 30 días')
        self.client.post(url, {'expected_silence_minutes': 0, 'maintenance_until': until,
                               'maintenance_reason': 'Cambio de operador de fibra'})
        self.assertEqual(DeviceHealth.objects.get(device=device).maintenance_reason, 'Cambio de operador de fibra')

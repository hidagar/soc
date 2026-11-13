"""Horario laboral de los plazos: calendario, solicitudes e incidencias."""
from datetime import date, datetime, time, timedelta

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from . import business_hours, request_sla, sla
from .business_hours import Calendar
from .models import Client, CustomerRequest, Incident, SlaSettings, StaffAccess


def local(*args):
    return timezone.make_aware(datetime(*args), timezone.get_current_timezone())


class CalendarTests(TestCase):
    """2026-11-13 es viernes; jornada de 8:00 a 18:00 de lunes a viernes."""
    calendar = Calendar()

    def test_add_skips_nights_weekends_and_holidays(self):
        self.assertEqual(self.calendar.add(local(2026, 11, 13, 10, 0), 120), local(2026, 11, 13, 12, 0))
        self.assertEqual(self.calendar.add(local(2026, 11, 13, 17, 0), 8 * 60), local(2026, 11, 16, 15, 0))  # viernes 17:00 + 8 h
        self.assertEqual(self.calendar.add(local(2026, 11, 14, 11, 0), 60), local(2026, 11, 16, 9, 0))  # sábado
        self.assertEqual(self.calendar.add(local(2026, 11, 13, 22, 0), 30), local(2026, 11, 16, 8, 30))  # fuera de hora
        holiday = Calendar(holidays=frozenset({date(2026, 11, 16)}))
        self.assertEqual(holiday.add(local(2026, 11, 13, 17, 0), 8 * 60), local(2026, 11, 17, 15, 0))
        self.assertEqual(self.calendar.add(local(2026, 11, 13, 9, 0), 5 * 10 * 60), local(2026, 11, 20, 9, 0))  # 5 jornadas

    def test_between_counts_only_working_minutes(self):
        self.assertEqual(self.calendar.between(local(2026, 11, 13, 17, 0), local(2026, 11, 16, 9, 0)), 120)
        self.assertEqual(self.calendar.between(local(2026, 11, 14, 9, 0), local(2026, 11, 15, 20, 0)), 0)
        self.assertEqual(self.calendar.between(local(2026, 11, 13, 9, 0), local(2026, 11, 13, 8, 0)), 0)

    def test_parsers(self):
        self.assertEqual(business_hours.parse_holidays('25/12/2026\n01/01/2027, 25/12/2026'), [date(2026, 12, 25), date(2027, 1, 1)])
        self.assertEqual(business_hours.parse_time('08:30', 'x'), time(8, 30))
        for call in (lambda: business_hours.parse_holidays('2026-12-25'), lambda: business_hours.parse_time('8h', 'x'),
                     lambda: business_hours.parse_days([])):
            with self.assertRaises(ValueError):
                call()


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class BusinessSlaTests(TestCase):
    def setUp(self):
        self.company = Client.objects.create(name='Empresa A', code='a')
        self.config = SlaSettings.objects.create(pk=1, enabled=True, enabled_at=local(2026, 1, 1), requests_enabled=True,
                                                 requests_enabled_at=local(2026, 1, 1), business_hours_enabled=True)
        self.friday = local(2026, 11, 13, 17, 0)
        self.monday = local(2026, 11, 16, 9, 0)

    def deadlines(self, req, now):
        return {row['key']: row for row in request_sla.evaluate(req, now)}

    def test_normal_requests_follow_the_calendar_and_urgent_ones_do_not(self):
        normal = CustomerRequest.objects.create(client=self.company, kind='question', subject='Duda', created_at=self.friday)
        rows = self.deadlines(normal, self.monday)
        self.assertEqual((rows['response']['deadline'], rows['response']['state']), (local(2026, 11, 16, 15, 0), 'running'))
        urgent = CustomerRequest.objects.create(client=self.company, kind='question', subject='Urgente', urgent=True, created_at=self.friday)
        rows = self.deadlines(urgent, self.monday)
        self.assertEqual((rows['response']['deadline'], rows['response']['state']), (self.friday + timedelta(hours=1), 'breached'))
        SlaSettings.objects.update(business_urgent_requests=True)
        self.assertEqual(self.deadlines(urgent, self.monday)['response']['deadline'], local(2026, 11, 13, 18, 0))  # 17:00 + 1 h de jornada: cabe en el viernes
        SlaSettings.objects.update(business_hours_enabled=False)
        self.assertEqual(self.deadlines(normal, self.monday)['response']['state'], 'breached')  # tiempo natural: 8 h desde el viernes

    def test_waiting_is_discounted_in_working_minutes(self):
        req = CustomerRequest.objects.create(client=self.company, kind='question', subject='Duda', created_at=local(2026, 11, 9, 8, 0),
                                             first_response_at=local(2026, 11, 9, 9, 0), status='waiting', waiting_since=local(2026, 11, 10, 8, 0))
        now = local(2026, 11, 12, 8, 0)  # dos jornadas esperando al cliente
        fields = request_sla.transition_fields(req, 'in_progress', now)
        self.assertEqual(fields['waited_work_minutes'], 2 * 10 * 60)
        CustomerRequest.objects.filter(pk=req.pk).update(status='in_progress', **fields)
        req.refresh_from_db()
        # 5 días de plazo = 7200 min = 12 jornadas de 10 h; más 2 de espera = 14 jornadas desde el lunes 9.
        self.assertEqual(self.deadlines(req, now)['resolve']['deadline'], local(2026, 11, 26, 18, 0))

    def test_incidents_only_medium_and_low_and_only_if_marked(self):
        low = Incident.objects.create(client=self.company, title='Baja', description='d', severity='low')
        high = Incident.objects.create(client=self.company, title='Alta', description='d', severity='high')
        Incident.objects.update(created_at=self.friday)
        low.refresh_from_db()
        high.refresh_from_db()
        natural = sla.evaluate(low, self.monday)[0]
        self.assertFalse(natural['business'])
        SlaSettings.objects.update(business_minor_incidents=True)
        with_hours = sla.evaluate(low, self.monday)[0]
        self.assertTrue(with_hours['business'])
        self.assertEqual(with_hours['deadline'], Calendar().add(self.friday, with_hours['target']))
        self.assertGreater(with_hours['deadline'], natural['deadline'])
        self.assertFalse(sla.evaluate(high, self.monday)[0]['business'])  # las altas, siempre 24 horas

    def test_settings_page_saves_and_validates(self):
        user = get_user_model().objects.create_user('gestor')
        StaffAccess.objects.create(user=user, role='manager', all_clients=True)
        user.user_permissions.add(Permission.objects.get(codename='manage_operations'))
        self.client.force_login(user)
        self.assertContains(self.client.get(reverse('sla_settings')), 'Horario laboral')
        data = {'action': 'hours', 'business_hours_enabled': 'on', 'business_days': ['0', '1', '2', '3'], 'business_start': '09:00',
                'business_end': '14:00', 'business_holidays': '25/12/2026', 'business_minor_incidents': 'on'}
        self.client.post(reverse('sla_settings'), data)
        config = SlaSettings.objects.get(pk=1)
        self.assertEqual((config.business_days, config.business_start, config.business_end, config.business_holidays,
                          config.business_minor_incidents, config.business_urgent_requests),
                         ('0,1,2,3', time(9, 0), time(14, 0), ['2026-12-25'], True, False))
        calendar = business_hours.calendar_for(config)
        self.assertEqual(calendar.add(local(2026, 12, 24, 13, 0), 120), local(2026, 12, 28, 10, 0))  # jueves; viernes no laborable y festivo
        response = self.client.post(reverse('sla_settings'), {**data, 'business_end': '08:00'})
        self.assertContains(response, 'posterior al inicio')
        response = self.client.post(reverse('sla_settings'), {**data, 'business_holidays': 'Navidad'})
        self.assertContains(response, 'dd/mm/aaaa')
        self.assertEqual(SlaSettings.objects.get(pk=1).business_end, time(14, 0))

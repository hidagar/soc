"""Índice de seguridad del cliente: cálculo por factores, lo no comprobado, vistas e informe mensual."""
from datetime import date, timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from . import security_score
from .models import (BlocklistFeed, ChangePlan, Client, CustomerTask, Device, DeviceHealth, ExposureCheck, ExposureFinding,
                     Incident, SecurityEvidence, SecurityScore, Site, StaffAccess, WeeklyReport)


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class SecurityScoreTests(TestCase):
    def setUp(self):
        self.now = timezone.now()
        self.company = Client.objects.create(name='Empresa A', code='a')
        self.site = Site.objects.create(client=self.company, name='Palma', code='palma')
        self.device = Device.objects.create(site=self.site, name='FW-Palma', vendor='opnsense')
        self.health = DeviceHealth.objects.create(device=self.device, api_ok=True, checked_at=self.now, protection_checked_at=self.now,
                                                  last_log_at=self.now, engines={
                                                      'Suricata': {'configured': True, 'running': True, 'mode': 'ips'},
                                                      'Firmware': {'updates_available': False, 'catalogue_checked_at': self.now.isoformat()}})
        ExposureCheck.objects.create(device=self.device, last_success_at=self.now, checked_at=self.now, status='ok')
        BlocklistFeed.objects.create(client=self.company, enabled=True, entries=['198.51.100.7'])
        ChangePlan.objects.create(device=self.device, template='crowdsec', title='Bloqueo', status='active')

    def factors(self):
        result = security_score.compute(self.company, self.now)
        return result, {f['key']: f for f in result['factors']}

    def engines(self, **suricata):
        self.health.engines = {**self.health.engines, 'Suricata': {'configured': True, 'running': True, 'mode': 'ips', **suricata}}
        self.health.save()

    def test_a_well_protected_client_scores_100(self):
        result, factors = self.factors()
        self.assertEqual((result['score'], result['level'], result['level_label']), (100, 'good', 'Bien'))
        self.assertTrue(all(f['state'] == 'ok' for f in factors.values()))
        self.assertEqual(result['improvements'], [])

    def test_each_weakness_costs_its_weight_and_suggests_the_step(self):
        self.engines(mode='ids')
        self.health.engines['Firmware']['updates_available'] = True
        self.health.save()
        ExposureFinding.objects.create(device=self.device, section='nat', remote_id='1', kind='port', title='PostgreSQL',
                                       severity='high', recommendation='Cerrar', fingerprint='x')
        result, factors = self.factors()
        self.assertEqual((factors['ips']['points'], factors['firmware']['points'], factors['exposure']['points']), (0, 0, 0))
        self.assertEqual(result['score'], 55)
        self.assertEqual(result['level'], 'poor')
        self.assertEqual([i['label'] for i in result['improvements']], ['Exposición a Internet', 'Firmware al día', 'IPS en modo bloqueo'])
        self.assertEqual(factors['exposure']['detail'], 'Servicios publicados en Internet: 1 de riesgo alto.')
        self.assertEqual(factors['ips']['detail'], 'El IPS solo detecta: no bloquea.')
        self.assertNotIn('PostgreSQL', str(result))  # nunca títulos internos del control de exposición

    def test_documented_exceptions_do_not_count_as_exposure(self):
        ExposureFinding.objects.create(device=self.device, section='nat', remote_id='1', kind='port', title='VPN', severity='high',
                                       recommendation='-', fingerprint='x', review='accepted', review_until=self.now + timedelta(days=30))
        self.assertEqual(self.factors()[1]['exposure']['state'], 'ok')

    def test_what_cannot_be_checked_counts_half_and_says_so(self):
        self.health.delete()
        ExposureCheck.objects.all().delete()
        result, factors = self.factors()
        for key in ('exposure', 'engines', 'ips', 'firmware', 'attacks'):
            self.assertEqual(factors[key]['state'], 'unknown', key)
            self.assertEqual(factors[key]['points'], factors[key]['max'] / 2, key)
        self.assertEqual(factors['visibility']['points'], 0)
        self.assertIn('acceso', factors['firmware']['action'])

    def test_allowed_attacks_and_overdue_tasks_lower_the_score(self):
        for index in range(3):
            SecurityEvidence.objects.create(uid=f'{index:064x}', device=self.device, observed_at=self.now - timedelta(days=1),
                                            engine='suricata', signature='x', source_ip='45.155.205.10', destination_ip='10.0.0.5',
                                            action='allowed', client_scope_id=self.company.pk)
        incident = Incident.objects.create(client=self.company, title='Caso', description='-')
        CustomerTask.objects.create(incident=incident, title='Actualizar', instructions='-', visible=True,
                                    due_at=self.now - timedelta(days=2))
        result, factors = self.factors()
        self.assertEqual((factors['attacks']['points'], factors['tasks']['points']), (5, 0))
        self.assertEqual(result['score'], 85)

    def test_client_without_firewalls_has_no_score(self):
        Device.objects.update(active=False)
        self.assertIsNone(security_score.compute(self.company, self.now)['score'])

    def test_daily_record_and_customer_pages(self):
        self.assertEqual(security_score.record(self.now), 1)
        security_score.record(self.now)
        self.assertEqual(SecurityScore.objects.count(), 1)
        customer = get_user_model().objects.create_user('cliente-a')
        StaffAccess.objects.create(user=customer, role='customer').clients.add(self.company)
        self.client.force_login(customer)
        home = self.client.get(reverse('customer_home'))
        self.assertContains(home, 'Índice de seguridad')
        page = self.client.get(reverse('customer_index'))
        self.assertContains(page, '>100<')
        self.assertContains(page, 'Qué suma y qué resta')
        self.assertNotContains(page, 'FW-Palma')

    def test_soc_sees_it_in_the_client_page_and_the_preview(self):
        security_score.record(self.now)
        staff = get_user_model().objects.create_user('operador')
        StaffAccess.objects.create(user=staff, role='operator', all_clients=True)
        self.client.force_login(staff)
        self.assertContains(self.client.get(reverse('client_detail', args=[self.company.pk])), 'Índice de seguridad')
        self.assertContains(self.client.get(reverse('customer_preview_index', args=[self.company.pk])), 'Vista previa como Empresa A')

    def test_monthly_report_freezes_the_index_at_month_end(self):
        from .monthly_report import customer_context
        SecurityScore.objects.create(client=self.company, day=date(2026, 9, 30), score=70, level='fair', factors=[])
        SecurityScore.objects.create(client=self.company, day=date(2026, 10, 31), score=82, level='fair',
                                     factors=[{'label': 'Firmware al día', 'state': 'bad', 'detail': 'Pendiente', 'action': 'Actualizar'}])
        SecurityScore.objects.create(client=self.company, day=date(2026, 11, 3), score=95, level='good', factors=[])
        for monday in (date(2026, 10, 5), date(2026, 10, 12), date(2026, 10, 19), date(2026, 10, 26)):
            WeeklyReport.objects.create(client=self.company, week_start=monday)
        index = customer_context(self.company, date(2026, 10, 1))['index']
        self.assertEqual((index['score'], index['previous'], index['label']), (82, 70, 'Mejorable'))
        self.assertEqual(index['weak'][0]['label'], 'Firmware al día')

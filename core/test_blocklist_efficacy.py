"""Eficacia de las reglas de bloqueo del SOC: contadores del firewall, reinicios y tabla cargada."""
import time
from datetime import timedelta
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from . import blocklist_efficacy as efficacy
from .models import BlocklistFeed, ChangePlan, Client, Device, OpnsenseConnection, Site, WorkerState


class FakeFirewall:
    def __init__(self):
        self.packets, self.loaded, self.fail = 100, 1500, False

    def __call__(self, connection, path, payload=None, method=None):
        if self.fail:
            raise ValueError('HTTP 500 respuesta interna del proveedor')
        if path == '/api/firewall/filter_util/rule_stats':
            return {'status': 'ok', 'stats': {'uuid-regla': {'packets': self.packets, 'bytes': self.packets * 60},
                                              'otra': {'packets': 999999}}}
        if path == '/api/firewall/alias_util/list/SOC_CROWDSEC_1':
            return {'total': self.loaded, 'rows': []}
        raise AssertionError(path)


class EfficacyTests(TestCase):
    def setUp(self):
        self.now = timezone.now()
        self.company = Client.objects.create(name='Conservas Roselló', code='rosello')
        self.device = Device.objects.create(site=Site.objects.create(client=self.company, name='Fábrica', code='f'),
                                            name='FW-Rosello', vendor='opnsense', management_method='api')
        OpnsenseConnection.objects.create(device=self.device, api_url='https://fw.example.test', encrypted_api_key='x',
                                          encrypted_api_secret='x')
        self.plan = ChangePlan.objects.create(device=self.device, template='crowdsec', title='Bloqueo', status='active',
                                              remote_objects=[{'kind': 'alias', 'uuid': 'uuid-alias', 'rule': {'name': 'SOC_CROWDSEC_1'}},
                                                              {'kind': 'firewall', 'uuid': 'uuid-regla', 'rule': {}}])
        self.firewall = FakeFirewall()

    def run_at(self, minutes):
        with mock.patch('core.change_control.api', side_effect=self.firewall):
            return efficacy.refresh(self.now + timedelta(minutes=minutes))

    def test_counts_differences_survives_counter_resets_and_api_failures(self):
        self.assertEqual(self.run_at(0), 1)
        self.assertEqual(efficacy.summary(self.plan, self.now)['total'], 0, 'la primera lectura es el punto de partida')
        self.firewall.packets = 160
        self.run_at(60)
        self.firewall.packets = 25  # recarga de reglas o reinicio: pf vuelve a cero
        self.run_at(120)
        data = efficacy.summary(self.plan, self.now + timedelta(minutes=120))
        self.assertEqual((data['total'], data['resets'], data['loaded']), (85, 1, 1500))
        self.firewall.fail = True
        self.assertEqual(self.run_at(180), 0)
        data = efficacy.summary(self.plan, self.now + timedelta(minutes=180))
        self.assertEqual(data['total'], 85, 'un fallo no inventa ni borra bloqueos')
        self.assertEqual(data['error'], 'No se pudieron leer los contadores del firewall por API.')
        self.assertNotIn('proveedor', data['error'])

    def test_only_active_soc_rules_are_measured(self):
        ChangePlan.objects.filter(pk=self.plan.pk).update(status='rolled_back')
        self.assertEqual(self.run_at(0), 0)
        self.assertFalse(WorkerState.objects.filter(name__startswith=efficacy.PREFIX).exists())

    def test_rule_missing_from_stats_is_reported_not_counted_as_zero(self):
        self.assertIsNone(efficacy.rule_counters({'stats': {'otra': {'packets': 3}}}, ['uuid-regla']))
        with mock.patch('core.change_control.api', return_value={'stats': {}}):
            efficacy.refresh(self.now)
        self.assertIn('no informa', efficacy.summary(self.plan, self.now)['error'])

    @override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
    def test_panel_shows_blocked_packets_and_warns_when_the_table_is_empty(self):
        BlocklistFeed.objects.create(client=self.company, enabled=True, generated_at=self.now,
                                     entries=[{'ip': '45.155.205.233', 'reasons': ['x'], 'clients': 1, 'events': 1,
                                               'here': 1, 'here_allowed': 0}])
        self.run_at(-60)
        self.firewall.packets, self.firewall.loaded = 140, 0
        self.run_at(0)
        admin = get_user_model().objects.create_superuser('admin', 'a@example.test', 'x')
        self.client.force_login(admin)
        session = self.client.session
        session.update({'soc_mfa_user': admin.pk, 'soc_mfa_at': time.time()})
        session.save()
        page = self.client.get(reverse('blocklist_detail', args=[self.company.pk]))
        self.assertContains(page, 'Paquetes bloqueados hoy')
        self.assertContains(page, 'su tabla del SOC está vacía')
        self.assertContains(self.client.get(reverse('blocklists')), '40 paquetes')

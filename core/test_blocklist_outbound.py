"""Lista de salida (C2): destinos recurrentes de detecciones salientes, bloqueos manuales y plantilla de salida."""
import time
from datetime import timedelta
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import override_settings
from django.urls import reverse

from . import blocklist, change_control
from .blocklist import refresh_feeds
from .change_control import enable, rollback, stage
from .models import BlocklistFeed, ChangePlan, ManualBlock, OpnsenseConnection, SecurityEvidence
from .test_blocklist import ALLOWED_BY_CLIENT, FakeOpnsenseWithAliases, FeedTestCase

C2_TWO_DAYS, C2_ONCE, C2_TWO_CLIENTS, C2_INBOUND = '91.215.85.20', '91.215.85.21', '91.215.85.22', '91.215.85.23'


class OutboundTestCase(FeedTestCase):
    def setUp(self):
        super().setUp()
        BlocklistFeed.objects.filter(pk=self.feed.pk).update(outbound_enabled=True)
        other_device = self.other.sites.first().devices.first()
        events = [(C2_TWO_DAYS, self.device, 1), (C2_TWO_DAYS, self.device, 30), (C2_ONCE, self.device, 1),
                  (C2_TWO_CLIENTS, self.device, 1), (C2_TWO_CLIENTS, other_device, 2), (ALLOWED_BY_CLIENT, self.device, 1),
                  (ALLOWED_BY_CLIENT, self.device, 30), ('10.9.9.9', self.device, 1), ('10.9.9.9', self.device, 30)]
        for index, (destination, device, hours) in enumerate(events):
            self.c2(f'c2{index}', device, destination, hours)
        # Misma IP pero entrante, o saliente sin ser malware: no es un destino C2.
        self.c2('in1', self.device, C2_INBOUND, 1, direction='inbound')
        self.c2('in2', self.device, C2_INBOUND, 30, family='scan')

    def c2(self, uid, device, destination, hours, direction='outbound', family='malware'):
        SecurityEvidence.objects.create(uid=uid.ljust(64, '0'), device=device, observed_at=self.now - timedelta(hours=hours),
                                        engine='suricata', signature='ET MALWARE CnC Beacon', source_ip='192.168.1.20',
                                        destination_ip=destination, action='allowed', level=12,
                                        client_scope_id=device.site.client_id, geography={'direction': direction},
                                        interpretation={'event_family': family})

    def outbound(self):
        self.feed.refresh_from_db()
        return [e['ip'] for e in self.feed.outbound_entries]


class OutboundListTests(OutboundTestCase):
    def test_only_recurrent_outbound_malware_destinations_without_exceptions(self):
        refresh_feeds(self.now)
        self.assertEqual(self.outbound(), [C2_TWO_CLIENTS, C2_TWO_DAYS])
        self.assertNotIn(C2_TWO_DAYS, [e['ip'] for e in self.feed.entries], 'la lista de entrada no cambia')

    def test_manual_blocks_go_to_the_list_of_their_direction(self):
        for network, direction in (('185.191.171.1', 'in'), ('185.191.171.2', 'out'), ('185.191.171.3', 'both')):
            ManualBlock.objects.create(client=self.rosello, network=network, direction=direction, reason='Prueba',
                                       expires_at=self.now + timedelta(days=1))
        BlocklistFeed.objects.filter(pk=self.feed.pk).update(include_c2_detections=False)
        refresh_feeds(self.now)
        self.assertEqual(self.outbound(), ['185.191.171.2', '185.191.171.3'])
        inbound = [e['ip'] for e in self.feed.entries]
        self.assertIn('185.191.171.1', inbound)
        self.assertIn('185.191.171.3', inbound)
        self.assertNotIn('185.191.171.2', inbound)

    def test_outbound_url_needs_its_option_and_the_emergency_stop_empties_both(self):
        token = blocklist.rotate_token(self.feed)
        refresh_feeds(self.now)
        url = reverse('blocklist_serve_out', args=[self.rosello.pk, token])
        self.assertEqual(self.client.get(url).content.decode().split(), [C2_TWO_CLIENTS, C2_TWO_DAYS])
        self.assertEqual(self.client.get(reverse('blocklist_serve_out', args=[self.rosello.pk, 'x' * 43])).status_code, 404)
        BlocklistFeed.objects.filter(pk=self.feed.pk).update(stopped=True)
        self.assertEqual(self.client.get(url).content, b'')
        BlocklistFeed.objects.filter(pk=self.feed.pk).update(stopped=False, outbound_enabled=False)
        self.assertEqual(self.client.get(url).content, b'')
        self.assertNotEqual(self.client.get(reverse('blocklist_serve', args=[self.rosello.pk, token])).content, b'')


@override_settings(SOC_PUBLIC_ORIGIN='https://soc.example.test', SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class OutboundTemplateTests(OutboundTestCase):
    def setUp(self):
        super().setUp()
        OpnsenseConnection.objects.create(device=self.device, api_url='https://fw.example.test',
                                          encrypted_api_key='x', encrypted_api_secret='x')
        self.token = blocklist.rotate_token(self.feed)
        self.firewall = FakeOpnsenseWithAliases({'existing': {'description': 'Regla del cliente', 'enabled': '1'}})
        patcher = mock.patch.object(change_control, 'api', side_effect=self.firewall)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_page_prepares_an_outbound_rule_that_blocks_destinations(self):
        admin = get_user_model().objects.create_superuser('admin', 'a@example.test', 'x')
        self.client.force_login(admin)
        session = self.client.session
        session.update({'soc_mfa_user': admin.pk, 'soc_mfa_at': time.time()})
        session.save()
        url = reverse('blocklist_detail', args=[self.rosello.pk])
        self.assertContains(self.client.get(url), 'Preparar bloqueo de salida (C2)')
        self.client.post(url, {'action': 'plan_out', 'device': self.device.pk})
        plan = ChangePlan.objects.get(template=blocklist.TEMPLATE_OUT)
        stage(plan)
        self.assertEqual(plan.status, 'staged')
        [alias] = self.firewall.aliases.values()
        self.assertEqual(alias['name'], f'SOC_C2_{plan.pk}')
        self.assertTrue(alias['content'].endswith(f'/{self.token}/salida/'))
        [rule] = self.firewall.owned(plan).values()
        self.assertEqual((rule['enabled'], rule['action'], rule['direction'], rule['destination_net'], rule['source_net']),
                         ('0', 'block', 'out', alias['name'], 'any'))
        enable(plan)
        rollback(plan, delete=True)
        self.assertEqual((self.firewall.owned(plan), self.firewall.aliases), ({}, {}))
        # Sin la lista de salida activada no se prepara ni se crea nada en el firewall.
        BlocklistFeed.objects.filter(pk=self.feed.pk).update(outbound_enabled=False)
        self.client.post(url, {'action': 'plan_out', 'device': self.device.pk})
        self.assertEqual(ChangePlan.objects.filter(template=blocklist.TEMPLATE_OUT).count(), 1)

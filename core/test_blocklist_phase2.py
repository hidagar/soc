"""Listas de bloqueo, fase 2: bloqueos manuales del analista y atacantes detectados por el propio SOC."""
import json
import time
from datetime import timedelta
from unittest import mock

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase, override_settings
from django.urls import reverse

from . import blocklist
from .blocklist import parse_manual, refresh_feeds, servable
from .models import AuditEvent, BlocklistFeed, ManualBlock, StaffAccess, WorkerState
from .test_blocklist import ALLOWED_BY_CLIENT, HERE, OTHER, PARTNER_PUBLIC, FeedTestCase

MANUAL, RANGE, SOC_SCAN = '185.191.171.45', '185.191.170.0/28', '45.95.147.10'


def lapi(decisions):
    """Respuesta simulada del motor CrowdSec del SOC (GET /v1/decisions?origins=crowdsec)."""
    response = mock.MagicMock()
    response.__enter__.return_value.read.return_value = json.dumps(decisions).encode()
    return response


class ManualBlockTests(FeedTestCase):
    def block(self, network=MANUAL, client=None, days=7, **extra):
        values = dict(network=network, reason='Fuerza bruta RDP (caso 128)', expires_at=self.now + timedelta(days=days))
        values.update(extra)
        return ManualBlock.objects.create(client=client, **values)

    def test_manual_blocks_come_first_without_counting_against_the_maximum_and_expire(self):
        self.block(client=self.rosello)
        self.block(RANGE)  # todos los clientes
        self.block('185.191.172.200', client=self.other)  # de otro cliente: no aparece aquí
        self.block('185.191.172.201', client=self.rosello, revoked_at=self.now)
        self.block('185.191.172.202', client=self.rosello, days=-1)
        BlocklistFeed.objects.filter(pk=self.feed.pk).update(max_entries=1)
        refresh_feeds(self.now)
        self.assertEqual(self.ips(), [MANUAL, RANGE, HERE])
        self.assertEqual((self.feed.entries[0]['scope'], self.feed.entries[1]['scope']), ('cliente', 'todos'))
        # Caduca entre recálculos: deja de servirse al pasar su fecha.
        later = self.now + timedelta(days=8)
        BlocklistFeed.objects.filter(pk=self.feed.pk).update(generated_at=later - timedelta(minutes=5))
        self.feed.refresh_from_db()
        self.assertNotIn(MANUAL, servable(self.feed, later))

    def test_exceptions_and_protected_addresses_still_win(self):
        self.block(ALLOWED_BY_CLIENT, client=self.rosello)
        self.block(PARTNER_PUBLIC)  # IP pública de otro cliente del SOC
        self.block(PARTNER_PUBLIC.rsplit('.', 1)[0] + '.0/24')  # red que la contiene
        refresh_feeds(self.now)
        self.assertEqual(self.ips(), [HERE, OTHER, '89.248.165.2'])

    def test_validation(self):
        for value in ('10.0.0.1', 'no-es-ip', '185.0.0.0/16', '2001:db8::/32', '127.0.0.1'):
            with self.assertRaises(ValueError, msg=value):
                parse_manual(value)
        self.assertEqual(str(parse_manual(' 185.191.171.0/24 ')), '185.191.171.0/24')
        self.assertEqual(blocklist._label(parse_manual(MANUAL)), MANUAL)


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class ManualBlockPageTests(FeedTestCase):
    def login(self, user, fresh=True):
        self.client.force_login(user)
        if fresh:
            session = self.client.session
            session.update({'soc_mfa_user': user.pk, 'soc_mfa_at': time.time()})
            session.save()

    def manager(self, name, all_clients):
        user = get_user_model().objects.create_user(name)
        access = StaffAccess.objects.create(user=user, role='manager', all_clients=all_clients)
        if not all_clients:
            access.clients.add(self.rosello)
        user.groups.add(Group.objects.get(name='SOC Administrador'))
        return user

    def test_add_and_revoke_with_mfa_scope_and_audit(self):
        url = reverse('blocklist_detail', args=[self.rosello.pk])
        data = {'action': 'manual_add', 'network': MANUAL, 'reason': 'Fuerza bruta RDP', 'days': '7', 'scope': 'client'}
        admin = get_user_model().objects.create_superuser('admin', 'a@example.test', 'x')
        self.login(admin, fresh=False)
        self.assertRedirects(self.client.post(url, data), reverse('mfa_challenge'), fetch_redirect_response=False)
        self.assertFalse(ManualBlock.objects.exists())
        self.login(admin)
        self.assertRedirects(self.client.post(url, data), url, fetch_redirect_response=False)
        block = ManualBlock.objects.get()
        self.assertEqual((block.client, block.network, block.created_by), (self.rosello, MANUAL, admin))
        self.assertIn(MANUAL, [e['ip'] for e in BlocklistFeed.objects.get(pk=self.feed.pk).entries], 'recalculada al momento')
        self.assertTrue(AuditEvent.objects.filter(action='blocklist.manual_add').exists())
        for bad, text in (({'network': '10.0.0.0/8'}, 'direcciones públicas'), ({'reason': ''}, 'motivo'),
                          ({'days': '365'}, 'caducidad'), ({'network': ALLOWED_BY_CLIENT}, 'excepción del cliente')):
            self.assertContains(self.client.post(url, {**data, **bad}), text)
        self.assertEqual(ManualBlock.objects.count(), 1)
        # Retirar no espera al MFA, como el freno de emergencia.
        self.login(admin, fresh=False)
        self.client.post(url, {'action': 'manual_revoke', 'block': block.pk})
        block.refresh_from_db()
        self.assertIsNotNone(block.revoked_at)
        self.assertNotIn(MANUAL, [e['ip'] for e in BlocklistFeed.objects.get(pk=self.feed.pk).entries])

    def test_blocks_for_all_clients_require_global_access(self):
        url = reverse('blocklist_detail', args=[self.rosello.pk])
        limited = self.manager('limitado', all_clients=False)
        self.login(limited)
        page = self.client.post(url, {'action': 'manual_add', 'network': MANUAL, 'reason': 'Escaneo', 'days': '7', 'scope': 'all'})
        self.assertContains(page, 'requiere acceso global')
        self.assertFalse(ManualBlock.objects.exists())
        shared = ManualBlock.objects.create(network=RANGE, reason='Común', expires_at=self.now + timedelta(days=1))
        self.assertEqual(self.client.post(url, {'action': 'manual_revoke', 'block': shared.pk}).status_code, 403)
        self.assertIsNone(ManualBlock.objects.get(pk=shared.pk).revoked_at)
        self.login(self.manager('global', all_clients=True))
        self.client.post(url, {'action': 'manual_add', 'network': MANUAL, 'reason': 'Escaneo', 'days': '7', 'scope': 'all'})
        self.assertIsNone(ManualBlock.objects.get(network=MANUAL).client)
        self.assertContains(self.client.get(reverse('blocklists')), 'Común')


class SocDetectionTests(FeedTestCase):
    def setUp(self):
        super().setUp()
        BlocklistFeed.objects.filter(pk=self.feed.pk).update(include_soc_detections=True)

    def run_with(self, decisions, now=None, key='clave-bouncer'):
        side = decisions if isinstance(decisions, Exception) else None
        with mock.patch.dict('os.environ', {'SOC_PORTAL_CROWDSEC_LAPI_KEY': key}), \
                mock.patch('urllib.request.OpenerDirector.open', side_effect=side,
                           return_value=None if side else lapi(decisions)):
            refresh_feeds(now or self.now)

    def test_engine_detections_enter_before_the_automatic_list_and_respect_exceptions(self):
        self.run_with([{'value': SOC_SCAN, 'scope': 'Ip', 'type': 'ban', 'scenario': 'crowdsecurity/http-probing'},
                       {'value': ALLOWED_BY_CLIENT, 'scope': 'Ip', 'type': 'ban', 'scenario': 'x'},
                       {'value': '10.0.0.9', 'scope': 'Ip', 'type': 'ban', 'scenario': 'x'},
                       {'value': '185.0.0.0/16', 'scope': 'Range', 'type': 'ban', 'scenario': 'x'},
                       {'value': '185.191.173.7', 'scope': 'Ip', 'type': 'captcha', 'scenario': 'x'}])
        self.assertEqual(self.ips()[0], SOC_SCAN)
        self.assertEqual(self.feed.entries[0]['reasons'], ['Detectado por el SOC: crowdsecurity/http-probing'])
        self.assertNotIn(ALLOWED_BY_CLIENT, self.ips())
        self.assertEqual(len([e for e in self.feed.entries if e.get('soc')]), 1)
        # Sin la opción, el mismo cliente no las recibe.
        BlocklistFeed.objects.filter(pk=self.feed.pk).update(include_soc_detections=False)
        self.run_with([{'value': SOC_SCAN, 'scope': 'Ip', 'type': 'ban', 'scenario': 'x'}])
        self.assertNotIn(SOC_SCAN, self.ips())

    def test_engine_outage_uses_the_last_reading_for_one_hour_then_stops_blocking(self):
        self.run_with([{'value': SOC_SCAN, 'scope': 'Ip', 'type': 'ban', 'scenario': 'x'}])
        self.run_with(ConnectionRefusedError(), self.now + timedelta(minutes=30))
        self.assertIn(SOC_SCAN, self.ips())
        self.assertIn('no responde', WorkerState.objects.get(name=blocklist.SOC_STATE).details['error'])
        self.run_with(ConnectionRefusedError(), self.now + timedelta(hours=2))
        self.assertNotIn(SOC_SCAN, self.ips())

"""Listas de bloqueo del SOC (7A/C2, fase 1): criterios, observación, descarga, freno y plantilla."""
import json
import time
from datetime import timedelta
from unittest import mock

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from . import blocklist, change_control
from .blocklist import parse_allowlist, refresh_feeds
from .change_control import enable, rollback, stage
from .models import (BlocklistFeed, ChangePlan, Client, Device, ExportConfiguration, IpReputation, OpnsenseConnection,
                     SecurityEvidence, Site, StaffAccess)
from .test_change_control_lifecycle import FakeOpnsense

HERE, OTHER, NOISE, STALE, ALLOWED_BY_CLIENT, QUIET, SUSPICIOUS, CTI_ONLY = (
    '45.155.205.233', '185.220.101.4', '167.94.138.24', '218.92.0.35', '91.92.5.6', '193.32.162.31',
    '80.82.77.139', '89.248.165.2')
PARTNER_PUBLIC = '81.47.12.10'


def listed(ip, now, **extra):
    values = dict(listed=True, list_origins=['Lista comunitaria'], list_scenarios=['ssh:bruteforce'],
                  lists_checked_at=now - timedelta(hours=1), lists_expires_at=now + timedelta(hours=5))
    values.update(extra)
    return IpReputation.objects.create(ip=ip, **values)


class FeedTestCase(TestCase):
    def setUp(self):
        self.now = timezone.now()
        self.rosello = Client.objects.create(name='Conservas Roselló', code='rosello')
        self.other = Client.objects.create(name='Otra', code='otra')
        self.device = Device.objects.create(site=Site.objects.create(client=self.rosello, name='Fábrica', code='f'),
                                            name='FW-Rosello', vendor='opnsense', management_method='api')
        other_device = Device.objects.create(site=Site.objects.create(client=self.other, name='S', code='s'),
                                             name='FW-Otra', vendor='opnsense')
        ExportConfiguration.objects.create(device=other_device, source_ip=PARTNER_PUBLIC)
        attacks = [(HERE, self.device, 'allowed'), (HERE, self.device, 'blocked'), (OTHER, other_device, 'blocked'),
                   (NOISE, self.device, 'blocked'), (STALE, self.device, 'blocked'), (ALLOWED_BY_CLIENT, self.device, 'blocked'),
                   (SUSPICIOUS, self.device, 'blocked'), (CTI_ONLY, other_device, 'blocked'), (PARTNER_PUBLIC, self.device, 'blocked')]
        for index, (ip, device, action) in enumerate(attacks):
            SecurityEvidence.objects.create(uid=f'{index:064x}', device=device, observed_at=self.now - timedelta(hours=2),
                                            engine='suricata', signature='Firma', source_ip=ip, destination_ip='10.0.0.5',
                                            action=action, level=8, client_scope_id=device.site.client_id)
        for ip in (HERE, OTHER, ALLOWED_BY_CLIENT, QUIET, PARTNER_PUBLIC):
            listed(ip, self.now)
        listed(STALE, self.now, lists_checked_at=self.now - timedelta(days=2))
        listed(NOISE, self.now, cti_found=True, reputation='malicious', background_noise='high',
               cti_checked_at=self.now - timedelta(hours=1))
        IpReputation.objects.create(ip=SUSPICIOUS, cti_found=True, reputation='suspicious', cti_checked_at=self.now)
        IpReputation.objects.create(ip=CTI_ONLY, cti_found=True, reputation='malicious', cti_checked_at=self.now,
                                    behaviors=['http:exploit'])
        self.feed = BlocklistFeed.objects.create(client=self.rosello, enabled=True, allowlist=f'{ALLOWED_BY_CLIENT}  # proveedor')

    def ips(self):
        self.feed.refresh_from_db()
        return [e['ip'] for e in self.feed.entries]


class BuildTests(FeedTestCase):
    def test_only_fresh_listed_or_malicious_attackers_without_noise_or_exceptions(self):
        self.assertEqual(refresh_feeds(self.now), 1)
        # Primero quien atacó a este cliente; después protección preventiva por ataques a otros.
        self.assertEqual(self.ips(), [HERE, OTHER, CTI_ONLY])
        entry = self.feed.entries[0]
        self.assertEqual((entry['here'], entry['here_allowed'], entry['reasons']), (2, 1, ['Lista comunitaria']))
        self.assertEqual(self.feed.entries[2]['reasons'], ['CTI: maliciosa'])
        self.assertEqual(self.feed.observation | {'at': ''},
                         {'at': '', 'ips': 1, 'events': 2, 'allowed': 1, 'protective': 2})

    def test_sources_can_be_limited_and_entries_capped(self):
        self.feed.include_cti = False
        self.feed.save()
        refresh_feeds(self.now)
        self.assertEqual(self.ips(), [HERE, OTHER])
        self.feed.include_cti, self.feed.include_lists, self.feed.max_entries = True, False, 1
        self.feed.save()
        refresh_feeds(self.now)
        self.assertEqual(self.ips(), [CTI_ONLY])

    def test_each_source_counts_only_with_fresh_data(self):
        IpReputation.objects.filter(ip=HERE).update(cti_found=True, reputation='malicious',
                                                    cti_checked_at=self.now - timedelta(days=10))
        IpReputation.objects.filter(ip=CTI_ONLY).update(listed=True, lists_checked_at=self.now - timedelta(days=3))
        self.feed.include_lists = False
        self.feed.save()
        refresh_feeds(self.now)
        self.assertEqual(self.ips(), [CTI_ONLY], 'HERE solo tiene CTI caducada')
        self.assertEqual(self.feed.entries[0]['reasons'], ['CTI: maliciosa'])

    def test_recalculation_never_overwrites_newer_settings(self):
        refresh_feeds(self.now)
        before = self.ips()
        real_build = blocklist.build

        def operator_saves_meanwhile(feed, *args):
            entries = real_build(feed, *args)
            # El operador guarda una excepción mientras el trabajo calcula.
            changed = BlocklistFeed.objects.get(pk=feed.pk)
            changed.allowlist = f'{HERE}/32'
            changed.save(update_fields=['allowlist', 'updated_at'])
            return entries[:1]
        with mock.patch.object(blocklist, 'build', side_effect=operator_saves_meanwhile):
            refresh_feeds(self.now + timedelta(minutes=15))
        self.assertEqual(self.ips(), before, 'no escribe una lista calculada con la configuración anterior')
        refresh_feeds(self.now + timedelta(minutes=30))
        self.assertNotIn(HERE, self.ips(), 'la siguiente pasada aplica la excepción')

    def test_allowlist_validation(self):
        self.assertEqual(len(parse_allowlist('10.0.0.0/8\n2001:db8::/32 # sede\n\n# solo comentario')), 2)
        for bad in ('no-es-ip', '300.1.1.1', '\n'.join(f'10.0.{i}.0/24' for i in range(201))):
            with self.subTest(bad[:20]), self.assertRaises(ValueError):
                parse_allowlist(bad)

    def test_invalid_allowlist_keeps_last_good_list(self):
        refresh_feeds(self.now)
        BlocklistFeed.objects.filter(pk=self.feed.pk).update(allowlist='no-es-ip')
        refresh_feeds(self.now)
        self.assertEqual(self.ips(), [HERE, OTHER, CTI_ONLY])


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=True)
class ServeTests(FeedTestCase):
    def test_firewall_downloads_with_token_only_and_emergency_stop_empties_it(self):
        refresh_feeds(self.now)
        token = blocklist.rotate_token(self.feed)
        url = reverse('blocklist_serve', args=[self.rosello.pk, token])
        response = self.client.get(url)  # sin sesión ni MFA: es el firewall
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/plain; charset=utf-8')
        self.assertEqual(response.content.decode().split(), [HERE, OTHER, CTI_ONLY])
        self.feed.refresh_from_db()
        self.assertIsNotNone(self.feed.last_fetch_at)
        for bad in (reverse('blocklist_serve', args=[self.rosello.pk, 'x' * 43]),
                    reverse('blocklist_serve', args=[self.other.pk, token])):
            self.assertEqual(self.client.get(bad).status_code, 404)
        # Excepción añadida después del cálculo: se aplica ya en la siguiente descarga.
        BlocklistFeed.objects.filter(pk=self.feed.pk).update(allowlist=f'{OTHER}/32')
        self.assertEqual(self.client.get(url).content.decode().split(), [HERE, CTI_ONLY])
        BlocklistFeed.objects.filter(pk=self.feed.pk).update(allowlist='')
        # Tras rotar el token, la URL anterior recibe una lista vacía (el freno la sigue alcanzando).
        self.feed.refresh_from_db()
        new_token = blocklist.rotate_token(self.feed)
        self.assertEqual(self.client.get(url).content, b'')
        self.feed.refresh_from_db()
        self.assertIsNotNone(self.feed.previous_token_fetch_at)
        url = reverse('blocklist_serve', args=[self.rosello.pk, new_token])
        self.assertEqual(len(self.client.get(url).content.decode().split()), 3)
        # Sin recalcular más de 24 h: vacía.
        BlocklistFeed.objects.filter(pk=self.feed.pk).update(generated_at=self.now - timedelta(hours=25))
        self.assertEqual(self.client.get(url).content, b'')
        BlocklistFeed.objects.filter(pk=self.feed.pk).update(generated_at=timezone.now())
        BlocklistFeed.objects.filter(pk=self.feed.pk).update(stopped=True)
        self.assertEqual(self.client.get(url).content, b'')
        BlocklistFeed.objects.filter(pk=self.feed.pk).update(stopped=False, enabled=False)
        self.assertEqual(self.client.get(url).content, b'')
        self.assertEqual(self.client.post(url).status_code, 405)


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False, SOC_PUBLIC_ORIGIN='https://soc.example.test')
class PageTests(FeedTestCase):
    def login(self, user, fresh=True):
        self.client.force_login(user)
        if fresh:
            session = self.client.session
            session.update({'soc_mfa_user': user.pk, 'soc_mfa_at': time.time()})
            session.save()

    def user(self, name, role, group):
        user = get_user_model().objects.create_user(name)
        StaffAccess.objects.create(user=user, role=role, all_clients=True)
        user.groups.add(Group.objects.get(name=group))
        return user

    def test_operators_manage_and_only_connection_managers_see_url_or_prepare_rules(self):
        url = reverse('blocklist_detail', args=[self.rosello.pk])
        self.client.force_login(self.user('lector', 'reader', 'SOC Consulta'))
        self.assertEqual(self.client.get(url).status_code, 403)
        operator = self.user('operador', 'operator', 'SOC Operador')
        self.login(operator)
        if not operator.has_perm('core.manage_operations'):
            self.skipTest('El perfil operador no gestiona operaciones en esta configuración.')
        token = blocklist.rotate_token(self.feed)
        page = self.client.get(url)
        self.assertContains(page, 'Freno de emergencia')
        self.assertNotContains(page, token)
        self.assertEqual(self.client.post(url, {'action': 'plan', 'device': self.device.pk}).status_code, 403)
        self.client.post(url, {'action': 'stop'})
        self.assertTrue(BlocklistFeed.objects.get(pk=self.feed.pk).stopped)

    def test_settings_validation_plan_creation_and_customer_denied(self):
        admin = get_user_model().objects.create_superuser('admin', 'a@example.test', 'x')
        self.login(admin, fresh=False)
        stale = self.client.post(reverse('blocklist_detail', args=[self.rosello.pk]), {'action': 'resume'})
        self.assertRedirects(stale, reverse('mfa_challenge'), fetch_redirect_response=False)
        self.client.post(reverse('blocklist_detail', args=[self.rosello.pk]), {'action': 'stop'})
        self.assertTrue(BlocklistFeed.objects.get(pk=self.feed.pk).stopped, 'el freno no exige MFA reciente')
        self.login(admin)
        url = reverse('blocklist_detail', args=[self.rosello.pk])
        bad = self.client.post(url, {'action': 'settings', 'enabled': 'on', 'allowlist': 'no-es-ip', 'max_entries': '10'})
        self.assertContains(bad, 'Excepción no válida')
        self.assertEqual(BlocklistFeed.objects.get(pk=self.feed.pk).max_entries, 2000)
        self.client.post(url, {'action': 'settings', 'enabled': 'on', 'include_lists': 'on', 'include_cti': 'on',
                               'allowlist': '', 'max_entries': '50'})
        self.feed.refresh_from_db()
        self.assertEqual((self.feed.max_entries, bool(self.feed.token_hash)), (50, True))
        page = self.client.get(url)
        self.assertContains(page, 'https://soc.example.test/feeds/bloqueo/')
        self.assertContains(page, 'Preparar bloqueo en FW-Rosello')
        foreign = Device.objects.create(site=Site.objects.create(client=self.other, name='X', code='x'), name='Ajeno',
                                        vendor='opnsense', management_method='api')
        self.assertEqual(self.client.post(url, {'action': 'plan', 'device': foreign.pk}).status_code, 404)
        response = self.client.post(url, {'action': 'plan', 'device': self.device.pk})
        plan = ChangePlan.objects.get()
        self.assertRedirects(response, reverse('change_detail', args=[plan.pk]), fetch_redirect_response=False)
        self.assertEqual((plan.template, plan.status, plan.preview['rules'][0]['enabled']), ('crowdsec', 'draft', '0'))
        self.assertNotIn(blocklist.decrypt(self.feed.encrypted_token), json.dumps(plan.preview))
        self.assertContains(self.client.get(reverse('change_detail', args=[plan.pk])), 'regla de bloqueo de entrada')
        customer = get_user_model().objects.create_user('cliente')
        StaffAccess.objects.create(user=customer, role='customer').clients.add(self.rosello)
        self.client.force_login(customer)
        self.assertEqual(self.client.get(url).status_code, 403)


class FakeOpnsenseWithAliases(FakeOpnsense):
    def __init__(self, rules=None):
        super().__init__(rules)
        self.aliases = {}
        self.alias_ids = iter(range(1, 100))

    def __call__(self, connection, path, payload=None, method=None):
        if path.startswith('/api/firewall/alias/'):
            self.calls.append(path)
            if path.startswith('/api/firewall/alias/search_item'):
                return {'rows': [{'uuid': uid, **alias} for uid, alias in self.aliases.items()]}
            if path == '/api/firewall/alias/add_item':
                uid = f'alias-{next(self.alias_ids)}'
                self.aliases[uid] = dict(payload['alias'])
                return {'result': 'saved', 'uuid': uid}
            if path.startswith('/api/firewall/alias/get_item/'):
                return {'alias': dict(self.aliases.get(path.rsplit('/', 1)[1], {}))}
            if path.startswith('/api/firewall/alias/del_item/'):
                uid = path.rsplit('/', 1)[1]
                if any(self.aliases[uid]['name'] in (rule.get('source_net'), rule.get('destination_net')) for rule in self.rules.values()):
                    raise ValueError('Alias en uso')
                self.aliases.pop(uid)
                return {'result': 'deleted'}
            if path == '/api/firewall/alias/reconfigure':
                return {'status': 'ok'}
        return super().__call__(connection, path, payload, method)


@override_settings(SOC_PUBLIC_ORIGIN='https://soc.example.test')
class TemplateTests(FeedTestCase):
    def setUp(self):
        super().setUp()
        OpnsenseConnection.objects.create(device=self.device, api_url='https://fw.example.test',
                                          encrypted_api_key='x', encrypted_api_secret='x')
        self.token = blocklist.rotate_token(self.feed)
        self.plan = ChangePlan.objects.create(device=self.device, template='crowdsec', title=blocklist.TITLE,
                                              parameters={'client': self.rosello.pk},
                                              preview=blocklist.plan_preview(self.device))
        self.firewall = FakeOpnsenseWithAliases({'existing': {'description': 'Regla del cliente', 'enabled': '1'}})
        patcher = mock.patch.object(change_control, 'api', side_effect=self.firewall)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_stage_creates_url_table_and_disabled_block_rule_then_rollback_removes_both(self):
        stage(self.plan)
        self.assertEqual(self.plan.status, 'staged')
        [alias] = self.firewall.aliases.values()
        self.assertEqual((alias['type'], alias['name']), ('urltable', f'SOC_CROWDSEC_{self.plan.pk}'))
        self.assertIn(self.token, alias['content'])
        self.assertTrue(alias['content'].startswith('https://soc.example.test/feeds/bloqueo/'))
        [rule] = self.firewall.owned(self.plan).values()
        self.assertEqual((rule['enabled'], rule['action'], rule['interface'], rule['direction'], rule['source_net']),
                         ('0', 'block', 'wan', 'in', alias['name']))
        self.assertNotIn(self.token, json.dumps(self.plan.remote_objects) + json.dumps(self.plan.preview))
        self.assertFalse(any('/api/ids/' in call or 'zenarmor' in call for call in self.firewall.calls))
        enable(self.plan)
        self.assertEqual(self.plan.status, 'awaiting_confirmation')
        self.assertEqual([r['enabled'] for r in self.firewall.owned(self.plan).values()], ['1'])
        rollback(self.plan, delete=True)
        self.assertEqual((self.firewall.owned(self.plan), self.firewall.aliases), ({}, {}))
        self.assertEqual(self.firewall.rules['existing'], {'description': 'Regla del cliente', 'enabled': '1'})

    def test_stage_refuses_without_active_feed_and_leaves_nothing_behind(self):
        BlocklistFeed.objects.filter(pk=self.feed.pk).update(enabled=False)
        stage(self.plan)
        self.assertEqual(self.plan.status, 'failed')
        self.assertEqual((self.firewall.aliases, self.firewall.owned(self.plan)), ({}, {}))

    def test_alias_name_owned_by_someone_else_is_never_reused(self):
        self.firewall.aliases['ajeno'] = {'name': f'SOC_CROWDSEC_{self.plan.pk}', 'description': 'Del cliente'}
        stage(self.plan)
        self.assertEqual(self.plan.status, 'failed')
        self.assertIn('ajeno', self.firewall.aliases)

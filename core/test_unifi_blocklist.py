"""Listas de bloqueo del SOC en UniFi: solo listas «SOC…», formato aprendido, verificación y freno."""
import time
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from datetime import timedelta

from django.utils import timezone

from . import unifi_blocklist
from .models import BlocklistFeed, Client, Device, Site, UnifiBlocklistBinding, UnifiCloudConnection
from .unifi_blocklist import PLACEHOLDER

ZONES = {'External': '88888888-8888-8888-8888-888888888881', 'Internal': '88888888-8888-8888-8888-888888888882',
         'Gateway': '88888888-8888-8888-8888-888888888883'}
SITE, SOC_LIST, CLIENT_LIST = '11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222', '33333333-3333-3333-3333-333333333333'


class FakeConsole:
    """Consola UniFi simulada (API oficial de Network por el conector)."""
    def __init__(self, typed=True):
        item = {'type': 'IP_ADDRESS', 'value': '185.191.171.99'} if typed else '185.191.171.99'
        self.lists = {SOC_LIST: {'id': SOC_LIST, 'name': 'SOC Bloqueo', 'type': 'IPV4_ADDRESSES', 'items': [item]},
                      CLIENT_LIST: {'id': CLIENT_LIST, 'name': 'Proveedores', 'type': 'IPV4_ADDRESSES', 'items': [item]}}
        self.writes, self.drop_on_write, self.posts = [], False, []
        self.zones = [{'id': ZONES[n], 'name': n} for n in ZONES]
        self.policies = {'66666666-6666-6666-6666-666666666666': {
            'id': '66666666-6666-6666-6666-666666666666', 'name': 'Permitir VPN', 'enabled': True, 'index': 10000,
            'metadata': {'origin': 'USER_DEFINED'}, 'ipProtocolScope': {'ipVersion': 'IPV4_AND_IPV6'}}}
        self.policy_posts, self.order_puts = [], []

    def pair_ids(self, query):
        pair = (query['sourceFirewallZoneId'], query['destinationFirewallZoneId'])
        rows = [p for p in self.policies.values() if ((p.get('source') or {}).get('zoneId'), (p.get('destination') or {}).get('zoneId')) == pair]
        return [p['id'] for p in sorted(rows, key=lambda p: p['index'])]

    def __call__(self, api_key, host_id, path, method='GET', payload=None, query=None):
        if path.endswith('/firewall/policies/ordering'):
            ids = self.pair_ids(query)
            if method == 'PUT':
                self.order_puts.append(payload)
                new = payload['orderedFirewallPolicyIds']['beforeSystemDefined'] + payload['orderedFirewallPolicyIds']['afterSystemDefined']
                if sorted(new) != sorted(ids):  # como UniFi: hay que enviar todas las políticas del cruce
                    raise unifi_blocklist.UnifiCloudError('UniFi respondió HTTP 400 (api.firewall.policy.ordering.not-all-firewall-policies-specified).')
                for position, uid in enumerate(new):
                    self.policies[uid]['index'] = 10000 + position
                return {}
            return {'orderedFirewallPolicyIds': {'beforeSystemDefined': ids, 'afterSystemDefined': []}}
        if path.endswith('/firewall/zones'):
            return {'data': self.zones}
        if path.endswith('/firewall/policies'):
            if method == 'POST':
                uid = f'77777777-7777-7777-7777-77777777777{len(self.policy_posts)}'
                self.policy_posts.append(payload)
                self.policies[uid] = {'id': uid, 'index': 20000 + len(self.policy_posts), 'metadata': {'origin': 'USER_DEFINED'}, **payload}
                return {}
            return {'data': list(self.policies.values())}
        if '/firewall/policies/' in path:
            uid = path.rsplit('/', 1)[1]
            if method == 'DELETE':
                self.policies.pop(uid)
                return {}
            if method == 'PUT':
                self.policies[uid] = {**self.policies[uid], **payload}
                return {}
            return dict(self.policies[uid])
        if path == '/v1/sites':
            return {'data': [{'id': SITE, 'internalReference': 'default'}]}
        if method == 'POST':
            uid = '55555555-5555-5555-5555-55555555555' + str(len(self.lists))
            self.posts.append(payload)
            self.lists[uid] = {'id': uid, **payload}
            return {'data': self.lists[uid]}
        if path.endswith('/traffic-matching-lists'):
            return {'data': list(self.lists.values()) + [{'id': '44444444-4444-4444-4444-444444444444', 'name': 'SOC Puertos',
                                                           'type': 'PORTS', 'items': []}]}
        uid = path.rsplit('/', 1)[1]
        if method == 'PUT':
            self.writes.append((uid, payload))
            if not self.drop_on_write:
                self.lists[uid] = {**self.lists[uid], **payload}
            return {}
        return dict(self.lists[uid])


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class UnifiTestCase(TestCase):
    def setUp(self):
        self.now = timezone.now()
        self.company = Client.objects.create(name='BCM', code='bcm')
        self.device = Device.objects.create(site=Site.objects.create(client=self.company, name='Sede', code='s'),
                                            name='UDM-BCM', vendor='unifi')
        with mock.patch.dict('os.environ', {'SOC_PORTAL_UNIFI_KEY': 'MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY='}):
            from .unifi_cloud import encrypt_api_key
            key = encrypt_api_key('clave-unifi')
        UnifiCloudConnection.objects.create(device=self.device, encrypted_api_key=key, remote_host_id='host-1')
        self.feed = BlocklistFeed.objects.create(
            client=self.company, enabled=True, generated_at=self.now, outbound_enabled=True,
            entries=[{'ip': '45.155.205.233'}, {'ip': '185.220.101.0/28'}, {'ip': '2a0f:4ac0::1'}],
            outbound_entries=[{'ip': '91.215.85.20'}])
        self.console = FakeConsole()
        for patcher in (mock.patch.dict('os.environ', {'SOC_PORTAL_UNIFI_KEY': 'MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY='}),
                        mock.patch.object(unifi_blocklist, 'call', side_effect=self.console)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def login(self):
        admin = get_user_model().objects.create_superuser('admin', 'a@example.test', 'x')
        self.client.force_login(admin)
        session = self.client.session
        session.update({'soc_mfa_user': admin.pk, 'soc_mfa_at': time.time()})
        session.save()
        return reverse('blocklist_detail', args=[self.company.pk])



@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class UnifiBlocklistTests(UnifiTestCase):
    def test_only_soc_ipv4_lists_are_offered_and_the_bound_list_gets_the_feed(self):
        url = self.login()
        page = self.client.post(url, {'action': 'unifi_lists', 'device': self.device.pk})
        self.assertContains(page, 'SOC Bloqueo')
        self.assertNotContains(page, 'Proveedores')
        self.assertNotContains(page, 'SOC Puertos')
        self.assertNotContains(page, '185.191.171.99', msg_prefix='nunca se muestran las IPs de la consola')
        # Una lista del cliente no se puede vincular aunque se fuerce su identificador.
        self.assertEqual(self.client.post(url, {'action': 'unifi_bind', 'device': self.device.pk, 'list_id': CLIENT_LIST,
                                                'direction': 'in'}).status_code, 404)
        self.client.post(url, {'action': 'unifi_bind', 'device': self.device.pk, 'list_id': SOC_LIST, 'direction': 'in'})
        binding = UnifiBlocklistBinding.objects.get()
        self.assertEqual((binding.item_format, binding.pushed_count, binding.error), ('typed', 2, ''))
        [(uid, body)] = self.console.writes
        self.assertEqual((uid, body['name'], body['type']), (SOC_LIST, 'SOC Bloqueo', 'IPV4_ADDRESSES'))
        self.assertEqual(body['items'], [{'type': 'SUBNET', 'value': '185.220.101.0/28'},
                                         {'type': 'IP_ADDRESS', 'value': '45.155.205.233'}], 'IPv6 no cabe en una lista IPv4')
        self.assertEqual(self.console.lists[CLIENT_LIST]['items'][0]['value'], '185.191.171.99', 'la lista del cliente no se toca')
        # Sin cambios no se vuelve a escribir.
        unifi_blocklist.sync_all(self.now)
        self.assertEqual(len(self.console.writes), 1)

    def test_soc_creates_its_own_list_once_and_manages_it(self):
        url = self.login()
        self.client.post(url, {'action': 'unifi_create', 'device': self.device.pk, 'direction': 'in'})
        self.assertEqual(self.console.posts, [{'type': 'IPV4_ADDRESSES', 'name': 'SOC Bloqueo entrada',
                                               'items': [{'type': 'IP_ADDRESS', 'value': PLACEHOLDER}]}])
        binding = UnifiBlocklistBinding.objects.get()
        self.assertEqual((binding.list_name, binding.pushed_count, binding.error), ('SOC Bloqueo entrada', 2, ''))
        self.assertEqual(self.console.lists[binding.list_id]['items'][1], {'type': 'IP_ADDRESS', 'value': '45.155.205.233'})
        # Repetir no crea otra lista ni otras políticas: reutiliza las existentes.
        self.client.post(url, {'action': 'unifi_create', 'device': self.device.pk, 'direction': 'in'})
        self.assertEqual((len(self.console.posts), len(self.console.policy_posts)), (1, 2))
        # Solo se pueden crear listas «SOC…» de IPv4.
        from .unifi_cloud import UnifiCloudError
        mock.patch.stopall()
        for body in ({'type': 'IPV4_ADDRESSES', 'name': 'Proveedores'}, {'type': 'PORTS', 'name': 'SOC puertos'}):
            with self.assertRaises(UnifiCloudError):
                unifi_blocklist.call('k', 'host-1', f'/v1/sites/{SITE}/traffic-matching-lists', 'POST', body)

    def test_emergency_stop_and_unbind_leave_only_the_documentation_address(self):
        url = self.login()
        self.client.post(url, {'action': 'unifi_bind', 'device': self.device.pk, 'list_id': SOC_LIST, 'direction': 'out'})
        self.assertEqual(self.console.lists[SOC_LIST]['items'], [{'type': 'IP_ADDRESS', 'value': '91.215.85.20'}])
        self.client.post(url, {'action': 'stop'})
        self.assertEqual(self.console.lists[SOC_LIST]['items'], [{'type': 'IP_ADDRESS', 'value': PLACEHOLDER}])
        binding = UnifiBlocklistBinding.objects.get()
        self.client.post(url, {'action': 'unifi_unbind', 'binding': binding.pk})
        self.assertFalse(UnifiBlocklistBinding.objects.exists())
        self.assertEqual(self.console.lists[SOC_LIST]['items'], [{'type': 'IP_ADDRESS', 'value': PLACEHOLDER}])

    def test_write_not_confirmed_or_list_renamed_is_an_error_and_nothing_else_is_touched(self):
        binding = UnifiBlocklistBinding.objects.create(device=self.device, direction='in', site_id=SITE, list_id=SOC_LIST,
                                                       list_name='SOC Bloqueo', item_format='plain')
        self.console.drop_on_write = True
        self.assertFalse(unifi_blocklist.sync(binding, self.now))
        binding.refresh_from_db()
        self.assertIn('no confirmó', binding.error)
        self.console.drop_on_write = False
        self.console.lists[SOC_LIST]['name'] = 'Lista del cliente'
        writes = len(self.console.writes)
        self.assertFalse(unifi_blocklist.sync(binding, self.now))
        self.assertEqual(len(self.console.writes), writes)
        binding.refresh_from_db()
        self.assertIn('ya no es una lista', binding.error)

    def test_format_is_learned_from_the_list(self):
        self.assertEqual(unifi_blocklist.item_format(['1.2.3.4']), 'plain')
        self.assertEqual(unifi_blocklist.item_format([{'type': 'IP_ADDRESS', 'value': '1.2.3.4'}]), 'typed')
        self.assertEqual(unifi_blocklist.item_format([]), '')
        self.assertEqual(unifi_blocklist.item_format([{'ip': '1.2.3.4'}]), '')
        self.assertEqual(unifi_blocklist.encode(['45.155.205.233'], 'plain'), ['45.155.205.233'])

    def test_api_allowlist_rejects_policies_and_other_writes(self):
        from .unifi_cloud import UnifiCloudError
        mock.patch.stopall()  # la llamada real: la lista cerrada se comprueba antes de salir a la red
        for path, method in ((f'/v1/sites/{SITE}/firewall/policies', 'GET'), (f'/v1/sites/{SITE}/traffic-matching-lists', 'POST'),
                             (f'/v1/sites/{SITE}/traffic-matching-lists/{SOC_LIST}', 'DELETE'), ('/v1/sites/../x', 'GET')):
            with self.assertRaises(UnifiCloudError, msg=(path, method)):
                unifi_blocklist.call('k', 'host-1', path, method)


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class UnifiSectionVisibilityTests(TestCase):
    def test_section_is_shown_with_the_list_disabled_and_explains_missing_console_links(self):
        company = Client.objects.create(name='BCM', code='bcm')
        site = Site.objects.create(client=company, name='Sede', code='s')
        Device.objects.create(site=site, name='UDM-sin-consola', vendor='unifi')
        admin = get_user_model().objects.create_superuser('admin', 'a@example.test', 'x')
        self.client.force_login(admin)
        page = self.client.get(reverse('blocklist_detail', args=[company.pk]))
        self.assertContains(page, 'Bloqueo en UniFi')
        self.assertContains(page, 'Equipos UniFi sin la consola vinculada: UDM-sin-consola')


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class UnifiPolicyTests(UnifiTestCase):
    def test_list_and_disabled_block_policies_are_created_then_activated_with_mfa(self):
        url = self.login()
        self.client.post(url, {'action': 'unifi_create', 'device': self.device.pk, 'direction': 'in'})
        binding = UnifiBlocklistBinding.objects.get()
        self.assertEqual(len(binding.policies), 2)
        [first, second] = self.console.policy_posts
        self.assertEqual((first['enabled'], first['action'], first['ipProtocolScope']),
                         (False, {'type': 'BLOCK'}, {'ipVersion': 'IPV4_AND_IPV6'}), 'IP de la política del operador')
        self.assertEqual((first['source']['zoneId'], first['destination']['zoneId'], second['destination']['zoneId']),
                         (ZONES['External'], ZONES['Internal'], ZONES['Gateway']))
        self.assertEqual(first['source']['trafficFilter']['ipAddressFilter']['trafficMatchingListId'], binding.list_id)
        self.assertNotIn('trafficFilter', first['destination'])
        self.assertTrue(all(p['name'].startswith('SOC Bloqueo entrada') for p in self.console.policy_posts))
        # Activar exige MFA reciente; desactivar no (deja de bloquear).
        session = self.client.session
        session['soc_mfa_at'] = 0
        session.save()
        stale = self.client.post(url, {'action': 'unifi_policy_enable', 'binding': binding.pk})
        self.assertRedirects(stale, reverse('mfa_challenge'), fetch_redirect_response=False)
        session = self.client.session
        session['soc_mfa_at'] = time.time()
        session.save()
        self.client.post(url, {'action': 'unifi_policy_enable', 'binding': binding.pk})
        self.assertTrue(all(self.console.policies[p['id']]['enabled'] for p in binding.policies))
        self.assertTrue(UnifiBlocklistBinding.objects.get().policies_enabled)
        session = self.client.session
        session['soc_mfa_at'] = 0
        session.save()
        self.client.post(url, {'action': 'unifi_policy_disable', 'binding': binding.pk})
        self.assertFalse(any(self.console.policies[p['id']]['enabled'] for p in binding.policies))
        # Retirar: borra solo las políticas del SOC y deja la lista con la dirección de documentación.
        self.client.post(url, {'action': 'unifi_unbind', 'binding': binding.pk})
        self.assertEqual(list(self.console.policies), ['66666666-6666-6666-6666-666666666666'])
        self.assertEqual(self.console.lists[binding.list_id]['items'], [{'type': 'IP_ADDRESS', 'value': PLACEHOLDER}])

    def test_outbound_policy_matches_destinations_and_renamed_policies_are_not_touched(self):
        url = self.login()
        self.client.post(url, {'action': 'unifi_create', 'device': self.device.pk, 'direction': 'out'})
        binding = UnifiBlocklistBinding.objects.get()
        [policy] = self.console.policy_posts
        self.assertEqual((policy['source']['zoneId'], policy['destination']['zoneId']), (ZONES['Internal'], ZONES['External']))
        self.assertIn('trafficFilter', policy['destination'])
        self.console.policies[binding.policies[0]['id']]['name'] = 'Política del cliente'
        page = self.client.post(url, {'action': 'unifi_policy_enable', 'binding': binding.pk}, follow=True)
        self.assertContains(page, 'ha cambiado en UniFi')
        self.assertFalse(self.console.policies[binding.policies[0]['id']]['enabled'])

    def test_a_console_failing_for_an_hour_raises_an_issue(self):
        from .models import OperationalIssue
        binding = UnifiBlocklistBinding.objects.create(device=self.device, direction='in', site_id=SITE, list_id=SOC_LIST,
                                                       list_name='SOC Bloqueo', item_format='typed', synced_at=self.now)
        self.console.drop_on_write = True
        unifi_blocklist.sync_all(self.now)
        self.assertFalse(OperationalIssue.objects.filter(key=f'platform:unifi-blocklist:{binding.pk}').exists())
        unifi_blocklist.sync_all(self.now + timedelta(minutes=75))
        self.assertTrue(OperationalIssue.objects.filter(key=f'platform:unifi-blocklist:{binding.pk}', active=True).exists())
        self.console.drop_on_write = False
        unifi_blocklist.sync_all(self.now + timedelta(minutes=90))
        self.assertFalse(OperationalIssue.objects.filter(key=f'platform:unifi-blocklist:{binding.pk}', active=True).exists())

    def test_only_disabled_soc_block_policies_can_be_created(self):
        from .unifi_cloud import UnifiCloudError
        mock.patch.stopall()
        path = f'/v1/sites/{SITE}/firewall/policies'
        for body in ({'name': 'SOC x', 'enabled': True, 'action': {'type': 'BLOCK'}},
                     {'name': 'Cliente', 'enabled': False, 'action': {'type': 'BLOCK'}},
                     {'name': 'SOC x', 'enabled': False, 'action': {'type': 'ALLOW'}}):
            with self.assertRaises(UnifiCloudError):
                unifi_blocklist.call('k', 'host-1', path, 'POST', body)


class CheckCommandTests(UnifiTestCase):
    """`manage.py unifi_bloqueo_comprobar`: solo lectura y sin IPs en la salida."""

    def run_check(self):
        from io import StringIO
        from django.core.management import call_command
        out = StringIO()
        call_command('unifi_bloqueo_comprobar', '--equipo', 'udm-bcm', stdout=out)
        return out.getvalue()

    def test_reports_lists_policies_and_order_without_writing(self):
        url = self.login()
        self.client.post(url, {'action': 'unifi_create', 'device': self.device.pk, 'direction': 'in'})
        # Una política del operador que permite el mismo flujo y se evalúa antes que las del SOC.
        self.console.policies['88888888-8888-8888-8888-888888888888'] = {
            'id': '88888888-8888-8888-8888-888888888888', 'name': 'Permitir web', 'enabled': True, 'index': 5,
            'action': {'type': 'ALLOW'}, 'source': {'zoneId': ZONES['External']}, 'destination': {'zoneId': ZONES['Internal']}}
        writes = (len(self.console.writes), len(self.console.posts), len(self.console.policy_posts))
        output = self.run_check()
        self.assertEqual(writes, (len(self.console.writes), len(self.console.posts), len(self.console.policy_posts)))
        self.assertIn('Zonas: 3 · necesarias para el bloqueo: todas presentes', output)
        self.assertIn('«SOC Bloqueo entrada External→Internal»: desactivada · acción BLOCK · External → Internal', output)
        self.assertIn('creada por el panel', output)
        self.assertIn('1 política(s) ALLOW del mismo flujo se evalúan antes: «Permitir web» (orden 5)', output)
        for ip in ('45.155.205.233', '185.191.171.99', '192.0.2.1', 'clave-unifi'):
            self.assertNotIn(ip, output)

    def test_unlinked_console_is_reported(self):
        self.device.unifi_cloud.delete()
        self.assertIn('Consola UniFi: NO vinculada', self.run_check())


class PolicyOrderTests(UnifiTestCase):
    """«Poner las del SOC las primeras»: solo mueve las del SOC, con la lista completa y MFA."""

    def setUp(self):
        super().setUp()
        self.url = self.login()
        self.client.post(self.url, {'action': 'unifi_create', 'device': self.device.pk, 'direction': 'in'})
        self.binding = UnifiBlocklistBinding.objects.get(device=self.device)
        ext, internal = ZONES['External'], ZONES['Internal']
        for n, name in enumerate(('Reenvío web', 'Reenvío cámaras')):
            uid = f'99999999-9999-9999-9999-99999999999{n}'
            self.console.policies[uid] = {'id': uid, 'name': name, 'enabled': True, 'index': 5 + n, 'action': {'type': 'ALLOW'},
                                          'source': {'zoneId': ext}, 'destination': {'zoneId': internal}}

    def soc_internal(self):
        return next(p['id'] for p in self.binding.policies if 'Internal' in p['name'])

    def test_soc_policies_move_first_keeping_the_rest_in_order(self):
        response = self.client.post(self.url, {'action': 'unifi_policy_first', 'binding': self.binding.pk}, follow=True)
        self.assertContains(response, 'ya son las primeras')
        order = self.console.pair_ids({'sourceFirewallZoneId': ZONES['External'], 'destinationFirewallZoneId': ZONES['Internal']})
        self.assertEqual(order, [self.soc_internal(), '99999999-9999-9999-9999-999999999990', '99999999-9999-9999-9999-999999999991'])
        self.assertTrue(all(len(p['orderedFirewallPolicyIds']['beforeSystemDefined']) >= 1 for p in self.console.order_puts))
        self.assertFalse(any(p['enabled'] for p in self.console.policies.values() if p['name'].startswith('SOC')))  # no activa nada
        # Repetirlo no vuelve a escribir.
        writes = len(self.console.order_puts)
        self.client.post(self.url, {'action': 'unifi_policy_first', 'binding': self.binding.pk})
        self.assertEqual(len(self.console.order_puts), writes)

    def test_renamed_policy_is_not_moved(self):
        self.console.policies[self.soc_internal()]['name'] = 'Bloqueo renombrado'
        response = self.client.post(self.url, {'action': 'unifi_policy_first', 'binding': self.binding.pk}, follow=True)
        self.assertContains(response, 'ha cambiado en UniFi')
        self.assertEqual(self.console.order_puts, [])

    def test_requires_fresh_mfa(self):
        session = self.client.session
        session['soc_mfa_at'] = 0
        session.save()
        response = self.client.post(self.url, {'action': 'unifi_policy_first', 'binding': self.binding.pk})
        self.assertRedirects(response, reverse('mfa_challenge'), fetch_redirect_response=False)
        self.assertEqual(self.console.order_puts, [])

    def test_allowlist_only_accepts_well_formed_ordering(self):
        mock.patch.stopall()
        site = f'/v1/sites/{SITE}/firewall/policies/ordering'
        query = {'sourceFirewallZoneId': ZONES['External'], 'destinationFirewallZoneId': ZONES['Internal']}
        for bad_query, body in ((None, None), ({'sourceFirewallZoneId': 'x', 'destinationFirewallZoneId': 'y'}, None),
                                (query, {'orderedFirewallPolicyIds': {'beforeSystemDefined': ['no-uuid'], 'afterSystemDefined': []}}),
                                (query, {'otra': 1})):
            with self.assertRaisesRegex(unifi_blocklist.UnifiCloudError, 'no permitida'):
                unifi_blocklist.call('k', 'host-1', site, 'PUT' if body else 'GET', body, query=bad_query)

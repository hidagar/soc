"""Listas de bloqueo del SOC en UniFi: solo listas «SOC…», formato aprendido, verificación y freno."""
import time
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from . import unifi_blocklist
from .models import BlocklistFeed, Client, Device, Site, UnifiBlocklistBinding, UnifiCloudConnection
from .unifi_blocklist import PLACEHOLDER

SITE, SOC_LIST, CLIENT_LIST = '11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222', '33333333-3333-3333-3333-333333333333'


class FakeConsole:
    """Consola UniFi simulada (API oficial de Network por el conector)."""
    def __init__(self, typed=True):
        item = {'type': 'IP_ADDRESS', 'value': '185.191.171.99'} if typed else '185.191.171.99'
        self.lists = {SOC_LIST: {'id': SOC_LIST, 'name': 'SOC Bloqueo', 'type': 'IPV4_ADDRESSES', 'items': [item]},
                      CLIENT_LIST: {'id': CLIENT_LIST, 'name': 'Proveedores', 'type': 'IPV4_ADDRESSES', 'items': [item]}}
        self.writes, self.drop_on_write = [], False

    def __call__(self, api_key, host_id, path, method='GET', payload=None):
        if path == '/v1/sites':
            return {'data': [{'id': SITE, 'internalReference': 'default'}]}
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
class UnifiBlocklistTests(TestCase):
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

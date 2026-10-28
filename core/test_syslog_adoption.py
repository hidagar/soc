"""Alta de equipos: un destino syslog hacia el SOC creado a mano se reutiliza en lugar de dar error o duplicarse."""
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse

from .models import Client, Device, ExportConfiguration, FirewallOnboarding, OpnsenseConnection, Site
from .testing_access import FreshMfaClient
from .provisioning import DESTINATION, PORT, ProvisionError, _opnsense_api, _soc_address


class FakeOpnsense:
    """Lo mínimo de la API de syslog de OPNsense: búsqueda (textos), detalle (opciones) y escritura."""

    def __init__(self, rows):
        self.rows = {row['uuid']: dict(row) for row in rows}
        self.calls = []

    def detail(self, row):
        options = lambda chosen, keys: {k: {'value': k, 'selected': int(k == chosen)} for k in keys}
        return {**row, 'transport': options(row['transport'], ('udp4', 'tcp4', 'udp6')),
                'level': options(row.get('level', ''), ('', 'info', 'warn'))}

    def __call__(self, connection, path, payload=None):
        self.calls.append((path, payload))
        if path.endswith('search_destinations'):
            # La búsqueda devuelve textos de pantalla, no claves: no sirven para decidir el transporte.
            return {'rows': [{**row, 'transport': 'UDP(4)' if row['transport'] == 'udp4' else 'TCP(4)'} for row in self.rows.values()]}
        if '/get_destination/' in path:
            return {'destination': self.detail(self.rows[path.rsplit('/', 1)[1]])}
        if path.endswith('add_destination'):
            self.rows['new-uuid'] = {**payload['destination'], 'uuid': 'new-uuid'}
            return {'result': 'saved', 'uuid': 'new-uuid'}
        if '/set_destination/' in path:
            self.rows[path.rsplit('/', 1)[1]].update(payload['destination'])
            return {'result': 'saved'}
        if path.endswith('reconfigure'):
            return {'status': 'ok'}
        raise AssertionError(path)

    def writes(self):
        return [path for path, payload in self.calls if payload is not None]


def manual(uuid='manual-uuid', **values):
    return {'uuid': uuid, 'enabled': '1', 'transport': 'udp4', 'hostname': DESTINATION, 'port': str(PORT),
            'description': 'SIEM ib-red', 'level': 'info', **values}


class SyslogAdoptionTests(SimpleTestCase):
    def run_api(self, fake):
        device = mock.Mock(pk=7)
        with mock.patch('core.provisioning._api_request', side_effect=fake):
            return _opnsense_api(device, mock.Mock(), DESTINATION, PORT)

    def test_manual_destination_is_reused_without_touching_it(self):
        fake = FakeOpnsense([manual()])
        uuid, destination, notice = self.run_api(fake)
        self.assertEqual((uuid, destination), ('manual-uuid', DESTINATION))
        self.assertIn('reutilizado', notice)
        self.assertEqual(fake.writes(), [])  # ni se crea otro ni se modifica el del técnico

    def test_disabled_manual_destination_is_enabled_keeping_its_settings(self):
        fake = FakeOpnsense([manual(enabled='0', transport='tcp4')])
        uuid, _, notice = self.run_api(fake)
        row = fake.rows['manual-uuid']
        self.assertEqual((row['enabled'], row['transport'], row['description'], row['level']), ('1', 'udp4', 'SIEM ib-red', 'info'))
        self.assertNotIn('new-uuid', fake.rows)
        self.assertIn('UDP IPv4', notice)

    def test_two_destinations_to_the_soc_stop_with_a_clear_message(self):
        fake = FakeOpnsense([manual(), manual('other-uuid', description='Copia')])
        with self.assertRaisesRegex(ProvisionError, '2 destinos syslog hacia el SOC'):
            self.run_api(fake)
        self.assertEqual(fake.writes(), [])

    def test_destination_by_hostname_is_recognised(self):
        fake = FakeOpnsense([manual(hostname='soc.example.test')])
        with mock.patch('core.provisioning.socket.getaddrinfo', return_value=[(2, 2, 17, '', (DESTINATION, 0))]):
            uuid, destination, _ = self.run_api(fake)
        self.assertEqual((uuid, destination), ('manual-uuid', DESTINATION))
        self.assertEqual(fake.writes(), [])

    def test_other_servers_and_ports_are_left_alone(self):
        fake = FakeOpnsense([manual('graylog', hostname='192.0.2.50'), manual('other-port', port='514')])
        uuid, _, notice = self.run_api(fake)
        self.assertEqual((uuid, notice), ('new-uuid', ''))
        self.assertEqual(fake.rows['graylog']['hostname'], '192.0.2.50')

    def test_panel_destination_plus_manual_copy_warns_about_duplicates(self):
        fake = FakeOpnsense([manual('panel', description='Centro SOC equipo 7'), manual()])
        uuid, _, notice = self.run_api(fake)
        self.assertEqual(uuid, 'panel')
        self.assertIn('repetidos', notice)

    def test_unknown_names_are_not_resolved_as_soc(self):
        with mock.patch('core.provisioning.socket.getaddrinfo', side_effect=OSError):
            self.assertIsNone(_soc_address('no-existe.example.test'))
        self.assertIsNone(_soc_address('192.0.2.99'))
        self.assertIsNone(_soc_address('bad host;rm'))


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class AdoptionFlowTests(TestCase):
    client_class = FreshMfaClient

    def setUp(self):
        site = Site.objects.create(client=Client.objects.create(name='Islas', code='islas'), name='Central', code='c')
        self.device = Device.objects.create(site=site, name='FW-ISLA', vendor='opnsense', management_method='api',
                                            management_address='https://10.0.0.1')
        FirewallOnboarding.objects.create(device=self.device, step=4, method='api')
        OpnsenseConnection.objects.create(device=self.device, api_url='https://10.0.0.1', encrypted_api_key='x',
                                          encrypted_api_secret='x', last_ok=True)
        self.client.force_login(get_user_model().objects.create_superuser('admin', 'admin@example.test', 'x'))

    def test_manual_destination_completes_the_wizard_step(self):
        fake = FakeOpnsense([manual()])
        with mock.patch('core.provisioning._api_request', side_effect=fake), \
                mock.patch('core.views.check_connection'), mock.patch('core.views.decrypt_credential', return_value='k'), \
                mock.patch('core.views._update_opnsense_details'):
            response = self.client.post(reverse('opnsense_api', args=[self.device.pk]), {'action': 'test'}, follow=True)
        self.assertRedirects(response, reverse('device_onboarding', args=[self.device.pk]))
        self.assertContains(response, 'reutilizado el destino syslog')
        self.assertContains(response, 'Envío configurado: confirma el origen')
        export = ExportConfiguration.objects.get(device=self.device)
        self.assertEqual((export.status, export.remote_identifier, export.last_error), ('configured', 'manual-uuid', ''))
        self.assertEqual(fake.writes(), [])

    def test_new_device_preselects_the_automatic_method(self):
        row = self.device.onboarding
        row.step = 3
        row.method = 'manual'
        row.save()
        page = self.client.get(reverse('device_onboarding', args=[self.device.pk]))
        self.assertEqual(page.context['form'].initial['method'], 'api')
        self.assertLess(page.content.decode().index('value="api"'), page.content.decode().index('value="manual"'))


class UnifiAdoptionTests(SimpleTestCase):
    def test_unifi_already_sending_to_another_soc_address_is_kept(self):
        from types import SimpleNamespace
        from .provisioning import UNIFI_CONTENTS, _unifi_api
        connection = SimpleNamespace(last_ok=True, remote_host_id='host', encrypted_api_key='x')
        row = {'_id': '0123456789abcdef01234567', 'key': 'rsyslogd', 'ip': '141.105.111.227', 'port': PORT,
               'enabled': True, 'contents': list(UNIFI_CONTENTS)}
        with mock.patch.dict('os.environ', {'SOC_PORTAL_PUBLIC_SYSLOG_IP': '141.105.111.227'}), \
                mock.patch('core.provisioning.decrypt_api_key', return_value='k'), \
                mock.patch('core.provisioning.connector_json', return_value={'data': [row]}) as connector:
            self.assertEqual(_unifi_api(connection, DESTINATION, PORT), ('0123456789abcdef01234567', '141.105.111.227'))
        connector.assert_called_once()  # solo lectura: no se cambia la ruta elegida a mano

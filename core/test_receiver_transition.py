from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase

from .provisioning import UNIFI_CONTENTS, _unifi_api, available_destinations, default_destination


class ReceiverTransitionTests(SimpleTestCase):
    def test_old_endpoint_survives_and_new_public_default_is_selected(self):
        with mock.patch.dict('os.environ', {'SOC_PORTAL_PUBLIC_SYSLOG_IP': '141.105.111.250',
                                            'SOC_PORTAL_EXTRA_SYSLOG_IPS': '141.105.111.250,141.105.111.227'}):
            self.assertEqual(available_destinations(), ['172.20.10.20', '141.105.111.227', '141.105.111.250'])
            self.assertEqual(default_destination(SimpleNamespace(vendor='unifi')), '141.105.111.250')
            self.assertEqual(default_destination(SimpleNamespace(vendor='opnsense')), '172.20.10.20')

    def test_bad_extra_addresses_cannot_be_selected(self):
        with mock.patch.dict('os.environ', {'SOC_PORTAL_PUBLIC_SYSLOG_IP': '141.105.111.227',
                                            'SOC_PORTAL_EXTRA_SYSLOG_IPS': 'bad.example,::1,172.20.10.20,141.105.111.227'}):
            self.assertEqual(available_destinations(), ['172.20.10.20', '141.105.111.227'])

    def test_unifi_managed_destination_is_updated_by_setting_key_and_read_back(self):
        identifier = '0123456789abcdef01234567'
        connection = SimpleNamespace(last_ok=True, remote_host_id='test-host', encrypted_api_key='test-key')
        row = {'_id': identifier, 'key': 'rsyslogd', 'ip': '141.105.111.227', 'port': 5514,
               'enabled': True, 'contents': list(UNIFI_CONTENTS)}
        updated = {**row, 'ip': '141.105.111.250'}
        with mock.patch('core.provisioning.decrypt_api_key', return_value='test-only-key'), \
             mock.patch('core.provisioning.connector_json', side_effect=[{'data': [row]}, {}, {'data': [updated]}]) as connector:
            self.assertEqual(_unifi_api(connection, '141.105.111.250', 5514, identifier), identifier)
        write = connector.call_args_list[1]
        self.assertEqual(write.args[2], '/network/api/s/default/rest/setting/rsyslogd')
        self.assertEqual(write.kwargs['method'], 'PUT')
        self.assertEqual(write.kwargs['payload']['ip'], '141.105.111.250')
        self.assertEqual(set(write.kwargs['payload']['contents']), set(UNIFI_CONTENTS))

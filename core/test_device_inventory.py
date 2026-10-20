import hashlib
import json
import os
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit
from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import TestCase, SimpleTestCase, override_settings
from django.urls import reverse
from . import device_inventory as inventory, gdms_api
from .models import Client, Site, Device, GdmsConnection, StaffAccess
from .forms import DeviceForm
from .testing_access import workflow_access

MAC = '00:0B:82:12:34:56'


class ProtocolTests(SimpleTestCase):
    def test_signed_read_uses_bearer_without_exposing_secret(self):
        with patch.object(gdms_api.request, 'build_opener') as builder, patch.object(gdms_api.time, 'time', return_value=1234):
            response = builder.return_value.open.return_value.__enter__.return_value
            response.read.return_value = json.dumps({'retCode': 0, 'data': []}).encode()
            self.assertEqual(gdms_api.read_inventory('eu', '123', 'SECRET', 'TOKEN', 'v1.0.0/inventory/list', {'search': MAC}), [])
            req = builder.return_value.open.call_args.args[0]
            query = parse_qs(urlsplit(req.full_url).query)
            expected = '&appID=123&secretKey=SECRET&timestamp=1234000&' + hashlib.sha256(req.data).hexdigest() + '&'
            self.assertEqual(query['signature'], [hashlib.sha256(expected.encode()).hexdigest()])
            self.assertEqual(req.get_header('Authorization'), 'Bearer TOKEN')
            self.assertNotIn('SECRET', req.full_url)
            self.assertNotIn('TOKEN', req.full_url)

    def test_ssh_profiles_read_actual_device_firmware_not_uname(self):
        device = Device(vendor='opnsense')
        with patch('core.ssh_connection.run_command', side_effect=[(0, 'OPNsense 26.1.4-amd64\nFreeBSD 14', ''), (0, 'Appliance Model', ''), (0, 'SERIAL', '')]) as call:
            result = inventory.ssh_details(device, object())
            self.assertEqual(result, {'software_version': '26.1.4-amd64', 'model': 'Appliance Model', 'serial_number': 'SERIAL'})
            self.assertFalse(any('uname' in args.args[1] for args in call.call_args_list))
        with patch('core.ssh_connection.run_command', return_value=(0, 'Linux', '')):
            self.assertEqual(inventory.ssh_details(Device(vendor='other'), object()), {})


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class InventoryTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = get_user_model().objects.create_user('inventory-api-operator')
        workflow_access(cls.user)
        cls.user.user_permissions.add(Permission.objects.get(codename='manage_connections'))
        cls.customer = Client.objects.create(name='Inventory', code='inventory')
        cls.site = Site.objects.create(client=cls.customer, name='Site', code='site')
        cls.device = Device.objects.create(site=cls.site, name='GCC', vendor='grandstream_gcc', mac_address=MAC,
            model='Old model', software_version='1.0.old', serial_number='OLD')
        cls.connection = GdmsConnection.objects.create(device=cls.device, client_scope_id=cls.customer.pk,
            region='eu', app_id='123', encrypted_secret='placeholder', last_ok=True)

    def setUp(self):
        self.client.force_login(self.user)
        env = patch.dict(os.environ, {'SOC_PORTAL_SSH_KEY': Fernet.generate_key().decode()})
        env.start(); self.addCleanup(env.stop)
        self.connection.encrypted_secret = gdms_api.encrypt('SECRET')
        self.connection.save()

    def test_gdms_exact_mac_mapping_and_detail_no_other_device_imported(self):
        with patch.object(gdms_api, 'access_token', return_value='TOKEN'), patch.object(gdms_api, 'read_inventory', side_effect=[
            [{'mac': '00:0B:82:12:34:57', 'model': 'FOREIGN'}, {'mac': MAC, 'model': 'GCC6010W', 'serialNumber': 'SERIAL'}],
            {'mac': MAC, 'apType': 'GCC6010W', 'firmwareVersion': '1.0.9'}]):
            result = inventory.refresh(self.device)
        self.assertEqual(result.model, 'GCC6010W'); self.assertEqual(result.software_version, '1.0.9')
        self.assertEqual(result.serial_number, 'SERIAL')
        self.assertEqual(result.inventory_metadata['fields']['model']['source'], 'GDMS')
        self.assertEqual(Device.objects.count(), 1)
        self.assertNotIn('TOKEN', json.dumps(result.inventory_metadata))

    def test_missing_mac_or_duplicate_match_never_chooses_first(self):
        with patch.object(gdms_api, 'access_token', return_value='TOKEN'), patch.object(gdms_api, 'read_inventory', return_value=[{'mac': MAC}, {'mac': MAC}]):
            with self.assertRaises(gdms_api.GdmsError): gdms_api.discover_device(self.connection, MAC)
        with patch.object(gdms_api, 'access_token') as auth:
            with self.assertRaises(gdms_api.GdmsError): gdms_api.discover_device(self.connection, None)
            auth.assert_not_called()

    def test_current_gdms_paginated_inventory_and_partial_rejection(self):
        page = {'result': [{'mac': MAC, 'model': 'GCC6010W', 'serialNumber': 'SERIAL'}], 'total': 1, 'totalPage': 1, 'currentPage': 1}
        with patch.object(gdms_api, 'access_token', return_value='TOKEN'), patch.object(gdms_api, 'read_inventory', side_effect=[page, {'mac': MAC, 'firmwareVersion': '1.0.9'}]):
            self.assertEqual(gdms_api.discover_device(self.connection, MAC)['software_version'], '1.0.9')
        with patch.object(gdms_api, 'access_token', return_value='TOKEN'), patch.object(gdms_api, 'read_inventory', return_value={**page, 'total': 200, 'totalPage': 2}):
            with self.assertRaises(gdms_api.GdmsError): gdms_api.discover_device(self.connection, MAC)

    def test_missing_firmware_retains_old_value_as_last_known(self):
        with patch.object(gdms_api, 'access_token', return_value='TOKEN'), patch.object(gdms_api, 'read_inventory', side_effect=[
            [{'mac': MAC, 'model': 'GCC6010W', 'serialNumber': 'SERIAL'}], {'mac': '00:0B:82:12:34:57', 'firmwareVersion': 'FOREIGN'}]):
            result = inventory.refresh(self.device)
        self.assertEqual(result.software_version, '1.0.old')
        self.assertIn('software_version', result.inventory_metadata['pending'])
        self.assertEqual(result.inventory_metadata['status'], 'partial')

    def test_failure_preserves_values_and_no_raw_remote_error(self):
        with patch.object(inventory, 'collect', side_effect=RuntimeError('TOKEN SECRET PASSWORD')):
            result = inventory.refresh(self.device)
        self.assertEqual(result.model, 'Old model')
        self.assertEqual(result.inventory_metadata['status'], 'pending')
        self.assertNotIn('TOKEN', json.dumps(result.inventory_metadata))
        with self.assertRaises(inventory.InventoryError): inventory.refresh(self.device)

    def test_moved_customer_during_query_cannot_accept_inventory(self):
        other = Client.objects.create(name='Other', code='other')
        def moved(*args):
            Site.objects.filter(pk=self.site.pk).update(client=other)
            return {'model': 'MUST NOT APPLY'}
        with patch.object(inventory, 'collect', side_effect=moved):
            with self.assertRaises(inventory.InventoryError): inventory.refresh(self.device)
        self.device.refresh_from_db(); self.assertEqual(self.device.model, 'Old model')

    def test_managed_form_does_not_accept_manual_model_or_firmware(self):
        data = {'site': self.site.pk, 'name': self.device.name, 'vendor': self.device.vendor, 'management_method': 'none',
            'log_method': 'none', 'mac_address': MAC, 'model': 'FORGED', 'software_version': 'FORGED', 'serial_number': 'FORGED'}
        form = DeviceForm(data, instance=self.device)
        self.assertTrue(form.is_valid(), form.errors)
        saved = form.save()
        self.assertEqual(saved.model, 'Old model'); self.assertEqual(saved.software_version, '1.0.old')
        self.assertTrue(form.automatic_inventory)
        response = self.client.get(reverse('device_edit', args=[self.device.pk]))
        self.assertContains(response, 'Datos técnicos automáticos')
        self.assertNotContains(response, 'name="software_version"')

    def test_requeued_query_during_collection_cannot_commit_old_result(self):
        def requeue(*args):
            inventory.queue(self.device)
            return {'model': 'OBSOLETE'}
        with patch.object(inventory, 'collect', side_effect=requeue):
            with self.assertRaises(inventory.InventoryError): inventory.refresh(self.device)
        self.device.refresh_from_db(); self.assertEqual(self.device.model, 'Old model')

    def test_refresh_endpoint_csrf_and_customer_scope(self):
        from django.test import Client as HttpClient
        url = reverse('refresh_device_inventory', args=[self.device.pk])
        strict = HttpClient(enforce_csrf_checks=True); strict.force_login(self.user)
        self.assertEqual(strict.post(url).status_code, 403)
        self.assertEqual(self.client.get(url).status_code, 405)
        with patch.object(inventory, 'collect', return_value={'model': 'GCC6010W', 'software_version': '1.0.9'}):
            self.assertEqual(self.client.post(url).status_code, 302)
        self.device.refresh_from_db(); self.assertEqual(self.device.model, 'GCC6010W')
        other = Client.objects.create(name='Other', code='other')
        access = StaffAccess.objects.get(user=self.user); access.all_clients = False; access.save(); access.clients.add(other)
        self.assertEqual(self.client.post(url).status_code, 404)

    def test_due_refresh_is_bounded_and_skips_unconfigured_or_paused(self):
        Device.objects.create(site=self.site, name='Unconfigured', vendor='other')
        Device.objects.filter(pk=self.device.pk).update(integration='paused')
        with patch.object(inventory, 'refresh') as refresh:
            self.assertEqual(inventory.refresh_due(), 0); refresh.assert_not_called()
        Device.objects.filter(pk=self.device.pk).update(integration='pending')
        with patch.object(inventory, 'refresh') as refresh:
            self.assertEqual(inventory.refresh_due(limit=1), 1); refresh.assert_called_once()

    def test_opnsense_nested_product_version_not_kernel_or_update_target(self):
        with patch('core.provisioning._api_request', return_value={'product': {'product_version': '26.1.4'}, 'latest_version': '99.0'}):
            self.assertEqual(inventory.opnsense_details(object()), {'software_version': '26.1.4'})

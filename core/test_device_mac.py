from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.test import TestCase, SimpleTestCase, override_settings
from django.urls import reverse
from .device_identity import normalize_mac
from .forms import DeviceForm
from .onboarding import EquipmentForm
from .models import Client, Site, Device, StaffAccess
from .scope import customer_scope
from .testing_access import workflow_access


class MacTests(SimpleTestCase):
    def test_normalizes_supported_formats_and_empty(self):
        for value in (' 00:0b:82:12:34:56 ', '00-0b-82-12-34-56', '000b82123456', '000b.8212.3456'):
            self.assertEqual(normalize_mac(value), '00:0B:82:12:34:56')
        for value in ('', ' ', None): self.assertIsNone(normalize_mac(value))
        self.assertEqual(normalize_mac('02:00:00:00:00:01'), '02:00:00:00:00:01')

    def test_rejects_invalid_zero_multicast_and_broadcast(self):
        for value in ('00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff', '01:00:5e:01:02:03', '00:0B:82:12:34:GG', '000b8212345', '00/0b/82/12/34/56'):
            with self.assertRaises(ValidationError): normalize_mac(value)


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class DeviceMacTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = get_user_model().objects.create_user('inventory-editor')
        workflow_access(cls.user)
        cls.customer = Client.objects.create(name='Customer A', code='customer-a')
        cls.other = Client.objects.create(name='Customer B', code='customer-b')
        cls.site = Site.objects.create(client=cls.customer, name='Site A', code='site-a')
        cls.other_site = Site.objects.create(client=cls.other, name='Site B', code='site-b')
        cls.device = Device.objects.create(site=cls.site, name='GCC A', vendor='grandstream_gcc', mac_address='00:0b:82:12:34:56')
        cls.foreign = Device.objects.create(site=cls.other_site, name='SECRET FOREIGN NAME', vendor='unifi', mac_address='00:0B:82:12:34:57')

    def setUp(self): self.client.force_login(self.user)

    def test_optional_mac_and_canonical_unique_enforced_by_database(self):
        Device.objects.create(site=self.site, name='No MAC 1', vendor='other')
        Device.objects.create(site=self.site, name='No MAC 2', vendor='other', mac_address='')
        self.device.refresh_from_db()
        self.assertEqual(self.device.mac_address, '00:0B:82:12:34:56')
        with self.assertRaises(IntegrityError), transaction.atomic():
            Device.objects.create(site=self.site, name='Duplicate', vendor='other', mac_address='000b.8212.3456')

    def test_wizard_accepts_mac_and_reports_duplicate_without_customer_details(self):
        form = EquipmentForm({'name': 'New GCC', 'vendor': 'grandstream_gcc', 'mac_address': '00-0b-82-12-34-58'})
        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.cleaned_data['mac_address'], '00:0B:82:12:34:58')
        token = customer_scope.set([self.customer.pk])
        try:
            form = EquipmentForm({'name': 'New GCC', 'vendor': 'grandstream_gcc', 'mac_address': self.foreign.mac_address})
            self.assertFalse(form.is_valid())
            self.assertIn('mac_address', form.errors)
            self.assertNotIn('SECRET FOREIGN NAME', str(form.errors))
        finally: customer_scope.reset(token)

    def test_edit_own_mac_is_valid_and_format_errors_are_field_errors(self):
        data = {'site': self.site.pk, 'name': self.device.name, 'vendor': self.device.vendor,
                'management_method': 'none', 'log_method': 'none', 'mac_address': '000b82123456'}
        form = DeviceForm(data, instance=self.device)
        self.assertTrue(form.is_valid(), form.errors)
        data['mac_address'] = 'not-a-mac'
        form = DeviceForm(data, instance=self.device)
        self.assertFalse(form.is_valid()); self.assertIn('mac_address', form.errors)

    def test_client_inventory_and_site_show_only_its_equipment(self):
        response = self.client.get(reverse('client_detail', args=[self.customer.pk]))
        self.assertContains(response, 'Equipos del cliente')
        self.assertContains(response, '00:0B:82:12:34:56')
        self.assertNotContains(response, '00:0B:82:12:34:57')
        self.assertNotContains(response, 'SECRET FOREIGN NAME')
        self.assertContains(self.client.get(reverse('site_detail', args=[self.site.pk])), '00:0B:82:12:34:56')
        self.assertContains(self.client.get(reverse('device_detail', args=[self.device.pk])), '00:0B:82:12:34:56')

    def test_authorized_edit_and_foreign_client_scope(self):
        data = {'site': self.site.pk, 'name': self.device.name, 'vendor': self.device.vendor,
                'management_method': 'none', 'log_method': 'none', 'mac_address': '00-0b-82-12-34-59'}
        self.assertEqual(self.client.post(reverse('device_edit', args=[self.device.pk]), data).status_code, 302)
        self.device.refresh_from_db(); self.assertEqual(self.device.mac_address, '00:0B:82:12:34:59')
        access = StaffAccess.objects.get(user=self.user)
        access.all_clients = False; access.save(); access.clients.add(self.customer)
        self.assertEqual(self.client.get(reverse('client_detail', args=[self.other.pk])).status_code, 404)
        self.assertEqual(self.client.get(reverse('device_edit', args=[self.foreign.pk])).status_code, 404)

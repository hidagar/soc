from .testing_access import workflow_access
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import TestCase, override_settings
from django.urls import reverse

from .models import Client, Device, ExportConfiguration, OpnsenseConnection, Site, UnifiCloudConnection


@override_settings(SECURE_SSL_REDIRECT=False)
class ConnectionGuideTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.operator = get_user_model().objects.create_user("guide-operator")
        workflow_access(cls.operator, reader=False)
        cls.customer = Client.objects.create(name="Cliente de pruebas", code="guide-test")
        cls.site = Site.objects.create(client=cls.customer, name="Oficina", code="office")
        cls.device = Device.objects.create(site=cls.site, name="Firewall oficina", vendor="opnsense")

    def setUp(self):
        self.url = reverse("connection_guide")

    def test_login_required(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)
        self.assertIn("login", response.url)

    def test_generic_guide_and_each_vendor_render(self):
        self.client.force_login(self.operator)
        for vendor in ("opnsense", "unifi", "hillstone", "other"):
            with self.subTest(vendor=vendor):
                response = self.client.get(self.url, {"vendor": vendor})
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.context["vendor"], vendor)
                self.assertContains(response, 'data-step="6"')
                self.assertContains(response, "Si algo no funciona")
        response = self.client.get(self.url, {"vendor": "invalid"})
        self.assertEqual(response.context["vendor"], "opnsense")

    def test_device_context_uses_saved_destination_without_exposing_credentials(self):
        self.client.force_login(self.operator)
        connection = OpnsenseConnection.objects.create(
            device=self.device, api_url="https://fw.example.test",
            encrypted_api_key="PRIVATE-API-KEY-SENTINEL", encrypted_api_secret="PRIVATE-SECRET-SENTINEL",
            ca_certificate="PRIVATE-CERTIFICATE-SENTINEL", last_ok=True,
        )
        export = ExportConfiguration.objects.create(
            device=self.device, destination="203.0.113.10", source_ip="198.51.100.2",
            status="configured", receiver_ready=True,
        )
        response = self.client.get(self.url, {"device": self.device.pk, "vendor": "unifi"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["vendor"], "opnsense")
        self.assertTrue(response.context["connection_ready"])
        self.assertContains(response, "203.0.113.10:5514")
        self.assertContains(response, "198.51.100.2")
        self.assertContains(response, self.customer.name)
        self.assertContains(response, "Gestionar conexiones")
        self.assertNotContains(response, "Abrir configuración API")
        for sentinel in (connection.encrypted_api_key, connection.encrypted_api_secret, connection.ca_certificate):
            self.assertNotContains(response, sentinel)
        export.refresh_from_db()
        connection.refresh_from_db()
        self.assertEqual(export.status, "configured")
        self.assertTrue(connection.last_ok)

    def test_permission_shows_configuration_link(self):
        self.operator.user_permissions.add(Permission.objects.get(codename="manage_connections"))
        self.client.force_login(self.operator)
        response = self.client.get(self.url, {"device": self.device.pk, "method": "ssh"})
        self.assertContains(response, reverse("ssh_connection", args=[self.device.pk]))
        self.assertContains(response, "Obtener huella SSH")
        self.assertNotContains(response, "un administrador debe darte")

    def test_unifi_requires_site_link_to_show_ready(self):
        device = Device.objects.create(site=self.site, name="Consola", vendor="unifi")
        connection = UnifiCloudConnection.objects.create(device=device, encrypted_api_key="CLOUD-SECRET-SENTINEL", last_ok=True)
        self.client.force_login(self.operator)
        response = self.client.get(self.url, {"device": device.pk})
        self.assertFalse(response.context["connection_ready"])
        self.assertNotContains(response, "CLOUD-SECRET-SENTINEL")
        connection.remote_site_id = "remote-site"
        connection.save(update_fields=["remote_site_id"])
        response = self.client.get(self.url, {"device": device.pk})
        self.assertTrue(response.context["connection_ready"])
        self.assertContains(response, "Security Detections")

    def test_invalid_or_missing_device_returns_404(self):
        self.client.force_login(self.operator)
        for value in ("bad", "-1", "999999999", "9" * 25):
            with self.subTest(value=value):
                self.assertEqual(self.client.get(self.url, {"device": value}).status_code, 404)

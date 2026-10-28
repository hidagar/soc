from .testing_access import FreshMfaClient, workflow_access
import json
from io import BytesIO
from datetime import timedelta
from unittest import mock

from cryptography.fernet import Fernet

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.core.exceptions import ValidationError
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from .models import Client, Device, ExportConfiguration, Incident, MailSettings, OpnsenseConnection, Site, SshConnection, UnifiCloudConnection, UrgentAlert, UrgentMonitorCursor, WeeklyReport
from .opnsense_api import _get_json, _post_json
from .unifi_cloud import UnifiCloudError, encrypt_api_key


class OpnsenseApiHeaderTests(SimpleTestCase):
    def test_content_type_is_sent_only_with_json_body(self):
        class JsonResponse(BytesIO):
            headers = {"Content-Type": "application/json"}

        opener = mock.Mock()
        opener.open.side_effect = lambda request_object, timeout: JsonResponse(b"{}")
        with mock.patch("core.opnsense_api.request.build_opener", return_value=opener):
            _get_json("https://fw.example.test", "key", "secret", "", "/api/core/system/status")
            _post_json("https://fw.example.test", "key", "secret", "", "/api/syslog/service/reconfigure", {})

        get_request = opener.open.call_args_list[0].args[0]
        post_request = opener.open.call_args_list[1].args[0]
        self.assertIsNone(get_request.get_header("Content-type"))
        self.assertEqual(post_request.get_header("Content-type"), "application/json")
        self.assertEqual(post_request.data, b"{}")

    def test_ids_apply_has_bounded_wait_without_slowing_regular_reads(self):
        class JsonResponse(BytesIO):
            headers = {"Content-Type": "application/json"}
        opener = mock.Mock()
        opener.open.side_effect = lambda request_object, timeout: JsonResponse(b"{}")
        with mock.patch("core.opnsense_api.request.build_opener", return_value=opener):
            _get_json("https://fw.example.test", "key", "secret", "", "/api/ids/settings/get")
            _post_json("https://fw.example.test", "key", "secret", "", "/api/ids/service/reconfigure", {})
            _post_json("https://fw.example.test", "key", "secret", "", "/api/syslog/service/reconfigure", {})
        self.assertEqual([c.kwargs['timeout'] for c in opener.open.call_args_list],[10,60,10])

    def test_timeout_requires_state_check_before_repeating_writes(self):
        from .opnsense_api import OpnsenseApiError
        opener=mock.Mock()
        opener.open.side_effect=TimeoutError('private upstream detail')
        with mock.patch("core.opnsense_api.request.build_opener", return_value=opener):
            with self.assertRaises(OpnsenseApiError) as result:
                _post_json("https://fw.example.test", "key", "secret", "", "/api/ids/service/reconfigure", {})
        self.assertIn('Comprueba el estado',str(result.exception))
        self.assertNotIn('private',str(result.exception))


@override_settings(SECURE_SSL_REDIRECT=False)
class PortalWorkflowTests(TestCase):
    client_class = FreshMfaClient  # credential views require a fresh MFA
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="operator", password="test-pass-9821")
        workflow_access(self.user, reader=False)
        self.client_record = Client.objects.create(name="Empresa A", code="empresa-a")
        self.other_client = Client.objects.create(name="Empresa B", code="empresa-b")
        self.site_one = Site.objects.create(client=self.client_record, name="Madrid", code="madrid")
        self.site_two = Site.objects.create(client=self.client_record, name="Sevilla", code="sevilla")
        self.foreign_site = Site.objects.create(client=self.other_client, name="Valencia", code="valencia")
        self.device_record = Device.objects.create(site=self.site_two, name="FW Sevilla", vendor=Device.Vendor.OPNSENSE, software_version="25.7")

    def test_anonymous_user_cannot_read_inventory(self):
        response = self.client.get(reverse("client_detail", args=[self.client_record.pk]))
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login/", response.url)

    def test_client_can_have_multiple_sites_and_site_has_device(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("client_detail", args=[self.client_record.pk]))
        self.assertContains(response, "Madrid")
        self.assertContains(response, "Sevilla")
        response = self.client.get(reverse("site_detail", args=[self.site_two.pk]))
        self.assertContains(response, "FW Sevilla")
        self.assertContains(response, "25.7")

    def test_operator_creates_client_site_and_device_from_panel(self):
        self.client.force_login(self.user)
        response = self.client.post(reverse("client_new"), {"name": "Empresa C", "code": "empresa-c", "active": "on"})
        created_client = Client.objects.get(code="empresa-c")
        self.assertRedirects(response, reverse("client_detail", args=[created_client.pk]))
        response = self.client.post(reverse("site_new"), {
            "client": created_client.pk, "name": "Bilbao",
            "devices-TOTAL_FORMS": "1", "devices-INITIAL_FORMS": "0", "devices-MIN_NUM_FORMS": "0", "devices-MAX_NUM_FORMS": "20",
        })
        created_site = Site.objects.get(client=created_client, code="bilbao")
        self.assertRedirects(response, reverse("site_detail", args=[created_site.pk]))
        response = self.client.post(reverse("device_new"), {
            "site": created_site.pk, "name": "FW Bilbao", "vendor": "opnsense", "model": "DEC740",
            "software_version": "26.1", "zenarmor_edition": "Business", "zenarmor_version": "2.6",
            "management_method": "api", "log_method": "syslog", "active": "on",
        })
        created_device = Device.objects.get(site=created_site, name="FW Bilbao")
        self.assertRedirects(response, reverse("device_detail", args=[created_device.pk]))
        self.assertEqual(created_device.software_version, "26.1")
        self.assertEqual(created_device.zenarmor_version, "2.6")

    def test_site_creation_can_add_multiple_firewalls_and_connection_methods(self):
        self.client.force_login(self.user)
        response = self.client.post(reverse("site_new"), {
            "client": self.client_record.pk, "name": "Barcelona",
            "devices-TOTAL_FORMS": "2", "devices-INITIAL_FORMS": "0", "devices-MIN_NUM_FORMS": "0", "devices-MAX_NUM_FORMS": "20",
            "devices-0-name": "UDM Beast", "devices-0-vendor": "unifi", "devices-0-management_method": "none",
            "devices-1-name": "OPNsense", "devices-1-vendor": "opnsense", "devices-1-management_method": "ssh",
            "devices-1-management_address": "fw.example.test", "devices-1-ssh_username": "operator",
        })
        site = Site.objects.get(client=self.client_record, code="barcelona")
        self.assertRedirects(response, reverse("site_detail", args=[site.pk]))
        self.assertEqual(site.devices.count(), 2)
        unifi = site.devices.get(vendor=Device.Vendor.UNIFI)
        self.assertEqual(unifi.management_method, Device.ManagementMethod.NONE)
        self.assertEqual(unifi.model, "")
        self.assertEqual(site.devices.get(vendor=Device.Vendor.OPNSENSE).management_method, Device.ManagementMethod.SSH)
        response = self.client.get(reverse("site_detail", args=[site.pk]))
        self.assertContains(response, "Envío sin configurar")

    def test_site_creation_saves_unifi_key_and_discovers_model(self):
        self.user.user_permissions.add(Permission.objects.get(codename="manage_connections"))
        self.client.force_login(self.user)
        sites = [{"site_id": "site-1", "host_id": "host-1", "name": "Cliente"}]
        with mock.patch.dict("os.environ", {"SOC_PORTAL_UNIFI_KEY": Fernet.generate_key().decode()}):
            with mock.patch("core.views.provision_export") as provision, mock.patch("core.views.list_sites", return_value=sites), mock.patch(
                "core.views.get_console_details", return_value={"model": "UDM Beast", "software_version": "10.6.106"}
            ):
                provision.return_value = ExportConfiguration(status=ExportConfiguration.Status.CONFIGURED)
                response = self.client.post(reverse("site_new"), {
                    "client": self.client_record.pk, "name": "Laboratorio",
                    "devices-TOTAL_FORMS": "1", "devices-INITIAL_FORMS": "0", "devices-MIN_NUM_FORMS": "0", "devices-MAX_NUM_FORMS": "20",
                    "devices-0-name": "Gateway", "devices-0-vendor": "unifi", "devices-0-management_method": "api",
                    "devices-0-api_key": "private-unifi-key",
                })
                self.assertEqual(response.status_code, 302)
                device = Device.objects.get(site__client=self.client_record, site__code="laboratorio")
                self.assertEqual(device.model, "UDM Beast")
                self.assertEqual(device.software_version, "10.6.106")
                connection = device.unifi_cloud
                self.assertTrue(connection.last_ok)
                self.assertNotIn("private-unifi-key", connection.encrypted_api_key)

    def test_site_form_only_requests_essential_inventory_fields(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("site_new"), {"client": self.client_record.pk})
        self.assertContains(response, "Identificador")
        self.assertContains(response, "Nombre")
        self.assertContains(response, "Paso 1 de 5")
        self.assertNotContains(response, 'name="vendor"')
        self.assertNotContains(response, 'name="devices-0-model"')
        self.assertNotContains(response, 'name="devices-0-software_version"')
        self.assertNotContains(response, 'name="address"')

    def test_site_creation_saves_opnsense_credentials_and_discovers_version(self):
        self.user.user_permissions.add(Permission.objects.get(codename="manage_connections"))
        self.client.force_login(self.user)
        with mock.patch.dict("os.environ", {"SOC_PORTAL_OPNSENSE_KEY": Fernet.generate_key().decode()}):
            with mock.patch("core.views.provision_export") as provision, mock.patch("core.views.check_connection"), mock.patch(
                "core.views.get_firmware_info", return_value={"product_version": "26.1"}
            ):
                provision.return_value = ExportConfiguration(status=ExportConfiguration.Status.CONFIGURED)
                response = self.client.post(reverse("site_new"), {
                    "client": self.client_record.pk, "name": "Granada",
                    "devices-TOTAL_FORMS": "1", "devices-INITIAL_FORMS": "0", "devices-MIN_NUM_FORMS": "0", "devices-MAX_NUM_FORMS": "20",
                    "devices-0-name": "Firewall", "devices-0-vendor": "opnsense", "devices-0-management_method": "api",
                    "devices-0-api_url": "https://fw.example.test", "devices-0-api_key": "private-key", "devices-0-api_secret": "private-secret",
                })
                self.assertEqual(response.status_code, 302)
                device = Device.objects.get(site__client=self.client_record, site__code="granada")
                self.assertEqual(device.software_version, "26.1")
                self.assertTrue(device.opnsense_api.last_ok)
                self.assertNotIn("private-secret", device.opnsense_api.encrypted_api_secret)

    def test_invalid_connection_method_does_not_create_site(self):
        self.client.force_login(self.user)
        response = self.client.post(reverse("site_new"), {
            "client": self.client_record.pk, "name": "Valencia", "code": "valencia-2",
            "devices-TOTAL_FORMS": "1", "devices-INITIAL_FORMS": "0", "devices-MIN_NUM_FORMS": "0", "devices-MAX_NUM_FORMS": "20",
            "devices-0-name": "Hillstone", "devices-0-vendor": "hillstone", "devices-0-management_method": "api",
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "permiso para gestionar conexiones API")
        self.assertFalse(Site.objects.filter(client=self.client_record, code="valencia-2").exists())

    def test_cross_client_incident_is_rejected(self):
        incident = Incident(client=self.client_record, site=self.foreign_site, title="Cruce", description="No válido")
        with self.assertRaises(ValidationError):
            incident.full_clean()
        self.client.force_login(self.user)
        response = self.client.post(reverse("incident_new"), {
            "client": self.client_record.pk,
            "site": self.foreign_site.pk,
            "title": "Cruce",
            "description": "No válido",
            "severity": "medium",
            "status": "open",
            "observed_at": timezone.localtime().strftime("%Y-%m-%dT%H:%M"),
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(Incident.objects.count(), 0)

    def test_weekly_report_uses_client_and_week_boundaries(self):
        self.client.force_login(self.user)
        monday = timezone.localdate() - timedelta(days=timezone.localdate().weekday())
        this_week = timezone.make_aware(timezone.datetime.combine(monday + timedelta(days=1), timezone.datetime.min.time()))
        prior_week = this_week - timedelta(days=7)
        Incident.objects.create(client=self.client_record, site=self.site_one, title="Esta semana", description="A", observed_at=this_week)
        Incident.objects.create(client=self.client_record, title="Semana previa", description="B", observed_at=prior_week)
        Incident.objects.create(client=self.other_client, title="Otro cliente", description="C", observed_at=this_week)
        response = self.client.get(reverse("weekly_report", args=[self.client_record.pk]), {"week": monday.isoformat()})
        self.assertContains(response, "Esta semana")
        self.assertNotContains(response, "Semana previa")
        self.assertNotContains(response, "Otro cliente")

    def test_weekly_wazuh_report_filters_client_source_and_is_readable(self):
        from .reporting import collect_client_week
        ExportConfiguration.objects.create(device=self.device_record, source_ip="192.0.2.21", receiver_ready=True)
        from .testing_access import legacy_sources
        legacy_sources()
        monday = timezone.localdate() - timedelta(days=timezone.localdate().weekday() + 7)
        results = [
            {"hits": {"total": {"value": 3}}, "aggregations": {"high":{"doc_count":2},"availability":{"doc_count":0},"security": {"doc_count": 2, "allowed": {"doc_count": 1}, "blocked": {"doc_count": 1}}}},
            {"hits": {"total":{"value":1},"hits": [{"_source": {"id":"original","timestamp": "2026-09-24T09:00:00Z", "rule": {"description": "Detección"}, "data": {"unifi": {"ips_signature": "ET SCAN", "action": "allowed"}}}}]}},
        ]
        with mock.patch("core.reporting._search", side_effect=results) as search:
            values = collect_client_week(self.client_record, monday, "auth")
        self.assertEqual(values["security_count"], 2)
        self.assertEqual(values["notable_alerts"][0]["description"], "ET SCAN")
        self.assertEqual(search.call_args_list[0].args[0]["query"]["bool"]["filter"][0], {"terms": {"location": ["192.0.2.21"]}})
        report = WeeklyReport.objects.create(client=self.client_record, week_start=monday, **values)
        self.client.force_login(self.user)
        response = self.client.get(reverse("weekly_report", args=[self.client_record.pk]), {"week": monday.isoformat()})
        self.assertContains(response, "ET SCAN")
        self.assertContains(response, "2")
        self.assertEqual(report.client_id, self.client_record.pk)

    def test_weekly_email_requires_opt_in_and_does_not_repeat(self):
        from .reporting import send_report
        monday = timezone.localdate() - timedelta(days=timezone.localdate().weekday() + 7)
        report = WeeklyReport.objects.create(client=self.client_record, week_start=monday, sources=["192.0.2.21"], security_count=2)
        from .testing_access import collected_report
        collected_report(report)
        self.assertFalse(send_report(report))
        self.client_record.report_email = "security@client.test"
        self.client_record.weekly_reports_enabled = True
        self.client_record.save()
        self.assertFalse(send_report(report))
        MailSettings.objects.create(pk=1, region="global", from_email="soc@example.test", encrypted_api_key="encrypted", enabled=True, last_test_ok=True, public_reports_url="https://reports.example.test", public_reports_verified=True)
        with mock.patch("core.mail_delivery.send_via_sendgrid", return_value="accepted-id") as send:
            self.assertTrue(send_report(report))
            self.assertFalse(send_report(report))
        self.assertEqual(send.call_count, 1)
        self.assertEqual(send.call_args.args[1], "security@client.test")
        self.assertIn("https://reports.example.test/reports/", send.call_args.args[3])

    def test_customer_summary_separates_blocked_from_allowed_and_keeps_client_scope(self):
        from django.template.loader import render_to_string
        from .reporting import report_context
        monday = timezone.localdate() - timedelta(days=timezone.localdate().weekday() + 7)
        report = WeeklyReport.objects.create(
            client=self.client_record, week_start=monday, sources=["192.0.2.21"],
            security_count=3, blocked_count=3, findings=[{
                "asset_name": "Alarma", "asset_ip": "10.0.0.13", "site": "Madrid",
                "type": "security", "priority": "media", "count": 3,
                "first_seen": "25/09/2026 20:00", "last_seen": "26/09/2026 08:00",
                "action": "bloqueada", "asset_confirmed": True, "forwarded": True,
                "published_ports": "10001", "ports": ["10001"], "source_ips": ["203.0.113.8"],
                "source_count": 1, "signatures": ["Detección IPS"],
                "recommendations": ["Confirmar si el servicio sigue publicado."],
            }],
        )
        context = report_context(report)
        self.assertEqual(context["summary_title"], "Bloqueos registrados")
        self.assertEqual(context["priority_actions"][0]["asset"], "Alarma")
        html = render_to_string("weekly_report.html", {**context, "customer_view": True, "report_base": "customer_report_base.html"})
        self.assertIn("Qué hacer ahora", html)
        self.assertIn("Confirmar si el servicio sigue publicado.", html)
        self.assertNotIn("Empresa B", html)

    def test_mail_settings_requires_connection_permission_and_hides_key(self):
        self.client.force_login(self.user)
        self.assertEqual(self.client.get(reverse("mail_settings")).status_code, 403)
        self.user.user_permissions.add(Permission.objects.get(codename="manage_connections"))
        with mock.patch.dict("os.environ", {"SOC_PORTAL_MAIL_KEY": Fernet.generate_key().decode()}):
            response = self.client.post(reverse("mail_settings"), {
                "region": "global", "from_email": "soc@example.test", "api_key": "SG.private-key", "action": "save",
            })
            self.assertRedirects(response, reverse("mail_settings"))
            config = MailSettings.objects.get(pk=1)
            self.assertNotIn("SG.private-key", config.encrypted_api_key)
            self.assertFalse(config.enabled)
            response = self.client.get(reverse("mail_settings"))
            self.assertNotContains(response, "SG.private-key")
            self.assertContains(response, "Hay una clave guardada")

    def test_sendgrid_test_activates_only_when_accepted(self):
        self.user.user_permissions.add(Permission.objects.get(codename="manage_connections"))
        self.client.force_login(self.user)
        with mock.patch.dict("os.environ", {"SOC_PORTAL_MAIL_KEY": Fernet.generate_key().decode()}):
            with mock.patch("core.views.send_test_email", return_value="message-id") as send:
                response = self.client.post(reverse("mail_settings"), {
                    "region": "global", "from_email": "soc@example.test", "api_key": "SG.private-key",
                    "test_email": "internal@example.test", "action": "test",
                })
            self.assertRedirects(response, reverse("mail_settings"))
            config = MailSettings.objects.get(pk=1)
            self.assertTrue(config.enabled)
            self.assertTrue(config.last_test_ok)
            self.assertEqual(send.call_args.args[1], "internal@example.test")
            with mock.patch("core.views.send_test_email", side_effect=RuntimeError("secret upstream detail")):
                response = self.client.post(reverse("mail_settings"), {
                    "region": "global", "from_email": "soc@example.test", "api_key": "",
                    "test_email": "internal@example.test", "action": "test",
                })
            self.assertRedirects(response, reverse("mail_settings"))
            config.refresh_from_db()
            self.assertFalse(config.enabled)
            self.assertFalse(config.last_test_ok)
            self.assertNotContains(self.client.get(reverse("mail_settings")), "secret upstream detail")

    def test_sendgrid_payload_has_single_recipient_and_no_unverified_redirect(self):
        from .mail_delivery import encrypt_sendgrid_key, send_via_sendgrid
        with mock.patch.dict("os.environ", {"SOC_PORTAL_MAIL_KEY": Fernet.generate_key().decode()}):
            config = MailSettings(region="eu", from_email="soc@example.test", encrypted_api_key=encrypt_sendgrid_key("SG.private-key"))
            response = mock.MagicMock()
            response.status = 202
            response.headers = {"X-Message-Id": "message-id"}
            opener = mock.MagicMock()
            opener.open.return_value.__enter__.return_value = response
            with mock.patch("core.mail_delivery.request.build_opener", return_value=opener) as build:
                result = send_via_sendgrid(config, "customer@example.test", "Weekly", "Text", "<p>HTML</p>")
            self.assertEqual(result, "message-id")
            self.assertEqual(build.call_args.args[0].__class__.__name__, "_NoRedirect")
            outgoing = opener.open.call_args.args[0]
            self.assertEqual(outgoing.full_url, "https://api.eu.sendgrid.com/v3/mail/send")
            self.assertEqual(outgoing.get_header("Authorization"), "Bearer SG.private-key")
            payload = json.loads(outgoing.data)
            self.assertEqual(payload["personalizations"], [{"to": [{"email": "customer@example.test"}]}])
            self.assertEqual(payload["from"], {"email": "soc@example.test", "name": "ib-red empresas · Centro SOC"})

    def test_sendgrid_weekly_report_is_scoped_and_not_repeated(self):
        from .reporting import send_report
        monday = timezone.localdate() - timedelta(days=timezone.localdate().weekday() + 7)
        first = WeeklyReport.objects.create(client=self.client_record, week_start=monday, sources=["192.0.2.21"])
        second = WeeklyReport.objects.create(client=self.other_client, week_start=monday, sources=["192.0.2.22"])
        from .testing_access import collected_report
        collected_report(first);collected_report(second)
        for client, address in [(self.client_record, "a@example.test"), (self.other_client, "b@example.test")]:
            client.weekly_reports_enabled = True
            client.report_email = address
            client.save()
        MailSettings.objects.create(pk=1, region="global", from_email="soc@example.test", encrypted_api_key="encrypted", enabled=True, last_test_ok=True, public_reports_url="https://reports.example.test", public_reports_verified=True)
        with mock.patch("core.mail_delivery.send_via_sendgrid", return_value="accepted-id") as send:
            self.assertTrue(send_report(first))
            self.assertFalse(send_report(first))
            self.assertTrue(send_report(second))
        self.assertEqual([call.args[1] for call in send.call_args_list], ["a@example.test", "b@example.test"])
        first.refresh_from_db()
        self.assertEqual(first.provider_message_id, "accepted-id")

    def test_weekly_report_rejects_source_shared_by_clients(self):
        from .reporting import _source_owner_check
        other_device = Device.objects.create(site=self.foreign_site, name="FW Valencia", vendor=Device.Vendor.UNIFI)
        ExportConfiguration.objects.create(device=self.device_record, source_ip="192.0.2.21", receiver_ready=True)
        ExportConfiguration.objects.create(device=other_device, source_ip="192.0.2.21", receiver_ready=True)
        with self.assertRaisesRegex(RuntimeError, "más de un cliente"):
            _source_owner_check([self.client_record, self.other_client])

    def test_cannot_enable_weekly_email_without_recipient(self):
        from .forms import ClientForm
        form = ClientForm(data={"name": "Empresa C", "code": "empresa-c", "weekly_reports_enabled": "on", "active": "on"})
        self.assertFalse(form.is_valid())
        self.assertIn("report_email", form.errors)

    def test_findings_name_exact_unifi_device_and_recommend_safe_action(self):
        from .findings import build_findings
        inventory = {"88.18.85.95": {
            "device_name": "UDM BCM", "site_name": "Discoteca",
            "hosts": {"10.208.3.13": "Alarma Trablisa"},
            "identities": {("","2026-09-25T11:50:57.761000+00:00"): {"label": "Alarma Trablisa", "confidence": "recent"}},
            "forwards": [{"fwd": "10.208.3.13", "fwd_port": "10001,10002,10014", "enabled": True}],
        }}
        hits = []
        for port, source, signature in [("10001", "203.0.113.4", "ET CINS Poor Reputation"),
                                        ("10002", "198.51.100.8", "ET SCAN Zmap")]:
            hits.append({"_source": {"timestamp": "2026-09-25T11:50:57.761+0000", "location": "88.18.85.95",
                "data": {"srcip": source, "dstip": "10.208.3.13", "dstport": port,
                         "unifi": {"category": "Security", "action": "allowed", "ips_signature": signature}}}})
        hits.append({"_source": {"timestamp": "2026-09-25T12:14:11.669+0000", "location": "88.18.85.95",
            "data": {"unifi": {"event_name": "Internet Down"}}, "rule": {"description": "UniFi critical event: Internet Down."}}})
        findings, _ = build_findings(hits, inventory)
        alarm = next(item for item in findings if item["type"] == "security")
        outage = next(item for item in findings if item["type"] == "availability")
        self.assertEqual(alarm["asset_name"], "Alarma Trablisa")
        self.assertEqual(alarm["count"], 1)
        self.assertEqual(len([f for f in findings if f["type"]=="security"]),2)
        self.assertIn(alarm["ports"], [["10001"],["10002"]])
        self.assertTrue(alarm["forwarded"])
        self.assertIn("VPN", " ".join(alarm["recommendations"]))
        self.assertEqual(outage["asset_name"], "UDM BCM")
        self.assertNotIn("ataque", " ".join(outage["recommendations"]).lower())

    def test_finding_without_destination_requests_identification(self):
        from .findings import build_findings
        hits = [{"_source": {"timestamp": "2026-09-25T09:33:27.683+0000", "location": "88.18.85.95",
            "data": {"unifi": {"category": "Security", "action": "allowed", "event_name": "Threat Detected"}}}}]
        findings, _ = build_findings(hits, {})
        self.assertEqual(findings[0]["asset_name"], "Destino no informado")
        self.assertIn("recuperar la IP", findings[0]["recommendations"][0])

    def test_related_options_only_return_selected_clients_sites(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("related_options"), {"client": self.client_record.pk, "site": self.site_two.pk})
        data = response.json()
        self.assertEqual({entry["name"] for entry in data["sites"]}, {"Madrid", "Sevilla"})
        self.assertEqual([entry["name"] for entry in data["devices"]], ["FW Sevilla"])

    def test_main_pages_render_for_operator(self):
        self.client.force_login(self.user)
        for name, args in [
            ("dashboard", []), ("client_list", []), ("api_connections", []), ("device_detail", [self.device_record.pk]),
            ("incident_list", []), ("incident_new", []), ("weekly_report", [self.client_record.pk]),
        ]:
            with self.subTest(page=name):
                self.assertEqual(self.client.get(reverse(name, args=args)).status_code, 200)

    def test_connections_page_shows_where_to_configure_api(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("api_connections"))
        self.assertContains(response, "FW Sevilla")
        self.assertContains(response, "Sin permiso para gestionar conexiones")
        admin = get_user_model().objects.create_superuser(username="admin-test", password="test-pass-9821")
        self.client.force_login(admin)
        response = self.client.get(reverse("api_connections"))
        self.assertContains(response, reverse("opnsense_api", args=[self.device_record.pk]))

    def test_unifi_api_key_is_encrypted_and_only_superuser_can_manage_it(self):
        device = Device.objects.create(site=self.site_one, name="UDM Beast", vendor=Device.Vendor.UNIFI)
        url = reverse("unifi_cloud", args=[device.pk])
        self.client.force_login(self.user)
        self.assertEqual(self.client.get(url).status_code, 403)
        admin = get_user_model().objects.create_superuser(username="admin-test", password="test-pass-9821")
        self.client.force_login(admin)
        api_key = "test-key-do-not-store-in-cleartext"
        sites = [{"site_id": "remote-site", "host_id": "remote-host", "name": "Sede remota"}]
        with mock.patch.dict("os.environ", {"SOC_PORTAL_UNIFI_KEY": Fernet.generate_key().decode()}):
            with mock.patch("core.views.provision_export") as provision, mock.patch("core.views.list_sites", return_value=sites) as fetch, mock.patch("core.views.get_console_details", return_value={}), mock.patch("core.views.list_host_consoles", return_value={}), mock.patch("core.views.list_host_names", return_value={}):
                provision.return_value = ExportConfiguration(status=ExportConfiguration.Status.CONFIGURED)
                response = self.client.post(url, {"action": "save_key", "api_key": api_key})
                self.assertEqual(response.status_code, 200)
                self.assertNotContains(response, api_key)
                connection = UnifiCloudConnection.objects.get(device=device)
                self.assertNotIn(api_key, connection.encrypted_api_key)
                self.client.post(url, {"action": "link", "site_id": "remote-site"})
                connection.refresh_from_db()
                self.assertEqual(connection.remote_site_id, "remote-site")
                self.assertEqual(connection.remote_host_id, "remote-host")
                self.assertTrue(connection.last_ok)
                self.assertEqual(fetch.call_args.args[0], api_key)

    def test_unifi_site_selector_distinguishes_duplicate_default_sites(self):
        device = Device.objects.create(site=self.site_one, name="UDM Beast", vendor=Device.Vendor.UNIFI)
        admin = get_user_model().objects.create_superuser(username="admin-test", password="test-pass-9821")
        self.client.force_login(admin)
        with mock.patch.dict("os.environ", {"SOC_PORTAL_UNIFI_KEY": Fernet.generate_key().decode()}):
            UnifiCloudConnection.objects.create(device=device, encrypted_api_key=encrypt_api_key("test-key"))
            sites = [
                {"site_id": "one", "host_id": "host-one", "name": "Default"},
                {"site_id": "two", "host_id": "host-two", "name": "Default"},
                {"site_id": "three", "host_id": "host-three", "name": "super"},
            ]
            consoles = {
                "host-one": {"console_name": "UDM BCM", "model": "UDM Beast"},
                "host-two": {"console_name": "Otra consola", "model": "UDM Pro"},
            }
            with mock.patch("core.views.list_sites", return_value=sites), mock.patch("core.views.list_host_consoles", return_value=consoles), mock.patch("core.views.list_host_names", return_value={"host-three": "Biniatro"}):
                response = self.client.get(reverse("unifi_cloud", args=[device.pk]))
            self.assertContains(response, "UDM BCM · Default · UDM Beast")
            self.assertContains(response, "Otra consola · Default · UDM Pro")
            self.assertContains(response, "Biniatro · super")
            self.assertNotContains(response, "host-three")

    def test_unifi_key_is_not_saved_if_api_rejects_it(self):
        device = Device.objects.create(site=self.site_one, name="UDM Beast", vendor=Device.Vendor.UNIFI)
        admin = get_user_model().objects.create_superuser(username="admin-test", password="test-pass-9821")
        self.client.force_login(admin)
        with mock.patch("core.views.list_sites", side_effect=UnifiCloudError("Clave rechazada")):
            response = self.client.post(reverse("unifi_cloud", args=[device.pk]), {"action": "save_key", "api_key": "bad-key"})
        self.assertContains(response, "Clave rechazada")
        self.assertFalse(UnifiCloudConnection.objects.filter(device=device).exists())

    def test_opnsense_credentials_are_encrypted_and_admin_only(self):
        url = reverse("opnsense_api", args=[self.device_record.pk])
        self.device_record.management_method = Device.ManagementMethod.SSH
        self.device_record.save(update_fields=["management_method"])
        self.client.force_login(self.user)
        self.assertEqual(self.client.get(url).status_code, 403)
        admin = get_user_model().objects.create_superuser(username="admin-test", password="test-pass-9821")
        self.client.force_login(admin)
        with mock.patch.dict("os.environ", {"SOC_PORTAL_OPNSENSE_KEY": Fernet.generate_key().decode()}):
            response = self.client.post(url, {
                "action": "save", "api_url": "http://opnsense.example.test",
                "api_key": "key-test", "api_secret": "secret-test",
            })
            self.assertContains(response, "solo la dirección HTTPS")
            self.assertFalse(OpnsenseConnection.objects.filter(device=self.device_record).exists())
            with mock.patch("core.views.check_connection"), mock.patch("core.views.get_firmware_info", return_value={}), mock.patch("core.views.provision_export") as provision:
                provision.return_value = ExportConfiguration(status=ExportConfiguration.Status.CONFIGURED)
                response = self.client.post(url, {
                    "action": "save", "api_url": "https://opnsense.example.test",
                    "api_key": "key-test", "api_secret": "secret-test",
                })
            self.assertEqual(response.status_code, 200)
            self.assertNotContains(response, "secret-test")
            connection = OpnsenseConnection.objects.get(device=self.device_record)
            self.assertNotIn("key-test", connection.encrypted_api_key)
            self.assertNotIn("secret-test", connection.encrypted_api_secret)
            self.device_record.refresh_from_db()
            self.assertEqual(self.device_record.management_method, Device.ManagementMethod.API)
            with mock.patch("core.views.provision_export") as provision, mock.patch("core.views.check_connection") as check, mock.patch("core.views.get_firmware_info", return_value={}):
                provision.return_value = ExportConfiguration(status=ExportConfiguration.Status.CONFIGURED)
                response = self.client.post(url, {"action": "test"})
            self.assertEqual(response.status_code, 200)
            connection.refresh_from_db()
            self.assertTrue(connection.last_ok)
            check.assert_called_once_with("https://opnsense.example.test", "key-test", "secret-test", "")

    def test_ssh_requires_confirmed_host_key_and_encrypts_password(self):
        url = reverse("ssh_connection", args=[self.device_record.pk])
        self.client.force_login(self.user)
        self.assertEqual(self.client.get(url).status_code, 403)
        admin = get_user_model().objects.create_superuser(username="ssh-admin", password="test-pass-9821")
        self.client.force_login(admin)
        key = {"type": "ssh-ed25519", "base64": "public-key", "fingerprint": "SHA256:example"}
        with mock.patch.dict("os.environ", {"SOC_PORTAL_SSH_KEY": Fernet.generate_key().decode()}), mock.patch("core.views.probe_host_key", return_value=key), mock.patch("core.views.check_ssh", return_value="26.1"), mock.patch("core.views.provision_export") as provision:
            provision.return_value = ExportConfiguration(status=ExportConfiguration.Status.CONFIGURED)
            response = self.client.post(url, {"action": "probe", "hostname": "172.20.10.1", "port": "22", "username": "root"})
            self.assertContains(response, "SHA256:example")
            response = self.client.post(url, {"action": "save", "hostname": "172.20.10.1", "port": "22", "username": "root", "fingerprint": "wrong", "password": "private-password"})
            self.assertContains(response, "Confirma la huella exacta")
            self.assertFalse(SshConnection.objects.filter(device=self.device_record).exists())
            response = self.client.post(url, {"action": "save", "hostname": "172.20.10.1", "port": "22", "username": "root", "fingerprint": "SHA256:example", "password": "private-password"})
            self.assertEqual(response.status_code, 200)
            connection = SshConnection.objects.get(device=self.device_record)
            self.assertNotIn("private-password", connection.encrypted_password)
            self.assertTrue(connection.last_ok)
            provision.assert_called_once()

    def test_opnsense_provisioner_marks_error_without_valid_connection(self):
        from .provisioning import provision_export
        self.device_record.management_method = Device.ManagementMethod.API
        self.device_record.management_address = "https://172.20.10.1"
        self.device_record.save()
        config = provision_export(self.device_record)
        self.assertEqual(config.status, ExportConfiguration.Status.ERROR)
        self.assertEqual(config.source_ip, "172.20.10.1")
        self.assertFalse(config.receiver_ready)

    def test_wazuh_source_sync_preserves_existing_configuration(self):
        from .management.commands.sync_wazuh_sources import add_sources
        original = "<ossec_config><remote><connection>syslog</connection><port>5514</port><allowed-ips>10.0.0.1</allowed-ips></remote></ossec_config><ossec_config></ossec_config>"
        updated, changed = add_sources(original, ["172.20.10.1"])
        self.assertTrue(changed)
        self.assertIn("<allowed-ips>10.0.0.1</allowed-ips>", updated)
        self.assertIn("<allowed-ips>172.20.10.1</allowed-ips>", updated)
        self.assertEqual(add_sources(updated, ["172.20.10.1"]), (updated, False))

    def test_unifi_provisioner_keeps_existing_other_siem_destination(self):
        from .provisioning import _unifi_api, ProvisionError
        connection = mock.Mock(last_ok=True, remote_host_id="host-id", encrypted_api_key="ciphertext")
        row = {"key": "rsyslogd", "_id": "0123456789abcdef01234567", "ip": "192.0.2.20", "port": 514,
               "enabled": True, "contents": ["critical"]}
        with mock.patch("core.provisioning.decrypt_api_key", return_value="test-key"), mock.patch("core.provisioning.connector_json", return_value={"data": [row]}) as connector:
            with self.assertRaises(ProvisionError):
                _unifi_api(connection, "172.20.10.20", 5514)
            connector.assert_called_once()

    def test_unifi_source_discovery_uses_static_route_wan(self):
        from .unifi_cloud import discover_syslog_source
        def connector(_key, _host, path):
            if path.endswith("/routing"):
                return {"data": [{"enabled": True, "static-route_network": "172.20.10.0/24", "static-route_interface": "wan-id"}]}
            if path.endswith("/networkconf"):
                return {"data": [{"_id": "wan-id", "purpose": "wan", "wan_networkgroup": "WAN2"}]}
            return {"data": [{"type": "udm", "wan2": {"ip": "141.105.104.138"}}]}
        with mock.patch("core.unifi_cloud.connector_json", side_effect=connector):
            self.assertEqual(discover_syslog_source("key", "host", "172.20.10.20"), "141.105.104.138")

    def test_ssh_nologin_reports_actionable_error(self):
        from .ssh_connection import SshConnectionError, check_connection as check_ssh
        with mock.patch("core.ssh_connection.run_command", return_value=(1, "This account is currently not available.\n", "")):
            with self.assertRaisesRegex(SshConnectionError, "no tiene shell"):
                check_ssh(mock.Mock())

    def test_ssh_admin_requires_privileged_command_access(self):
        from .ssh_connection import SshConnectionError, check_connection as check_ssh
        with mock.patch("core.ssh_connection.decrypt_password", return_value="test-password"), mock.patch("core.ssh_connection.run_command", side_effect=[
            (0, "OPNsense 26.1\n", ""), (0, "1001\n", ""),
            (1, "", "sudo: a password is required"), (1, "", "sudo: incorrect password")
        ]):
            with self.assertRaisesRegex(SshConnectionError, "sudo activado"):
                check_ssh(mock.Mock())

    def test_ssh_admin_can_use_password_for_sudo(self):
        from .ssh_connection import check_connection as check_ssh
        with mock.patch("core.ssh_connection.decrypt_password", return_value="test-password"), mock.patch("core.ssh_connection.run_command", side_effect=[
            (0, "OPNsense 26.1\n", ""), (0, "1001\n", ""),
            (1, "", "sudo: a password is required"), (0, "0\n", "")
        ]) as command:
            self.assertEqual(check_ssh(mock.Mock()), "OPNsense 26.1")
            self.assertEqual(command.call_args.kwargs["stdin_data"], b"test-password\n")

    def test_public_destination_is_selected_for_unifi_only(self):
        from .provisioning import default_destination
        unifi = Device(site=self.site_one, name="UDM", vendor=Device.Vendor.UNIFI)
        with mock.patch.dict("os.environ", {"SOC_PORTAL_PUBLIC_SYSLOG_IP": "141.105.111.227"}):
            self.assertEqual(default_destination(unifi), "141.105.111.227")
            self.assertEqual(default_destination(self.device_record), "172.20.10.20")

    def test_rechecking_unifi_preserves_observed_source(self):
        from .provisioning import provision_export
        unifi = Device.objects.create(site=self.site_one, name="UDM", vendor=Device.Vendor.UNIFI,
                                      management_method=Device.ManagementMethod.API)
        UnifiCloudConnection.objects.create(device=unifi, encrypted_api_key="test-key", remote_host_id="host-id", last_ok=True)
        ExportConfiguration.objects.create(device=unifi, destination="141.105.111.227", source_ip="88.18.85.95",
                                           status=ExportConfiguration.Status.CONFIGURED, remote_identifier="0123456789abcdef01234567")
        with mock.patch.dict("os.environ", {"SOC_PORTAL_PUBLIC_SYSLOG_IP": "141.105.111.227"}), \
             mock.patch("core.provisioning._unifi_api", return_value=("0123456789abcdef01234567", "141.105.111.227")), \
             mock.patch("core.provisioning.decrypt_api_key", return_value="test-key"), \
             mock.patch("core.provisioning.discover_syslog_source", return_value=None):
            result = provision_export(unifi)
        self.assertEqual(result.status, ExportConfiguration.Status.CONFIGURED)
        self.assertEqual(result.source_ip, "88.18.85.95")

    def test_export_destination_rejects_other_server_ip(self):
        admin = get_user_model().objects.create_superuser(username="export-admin", password="test-pass-9821")
        self.client.force_login(admin)
        response = self.client.post(reverse("export_destination", args=[self.device_record.pk]), {"destination": "203.0.113.99"})
        self.assertRedirects(response, reverse("device_detail", args=[self.device_record.pk]))
        self.assertFalse(ExportConfiguration.objects.filter(device=self.device_record).exists())

    def test_export_destination_accepts_configured_public_ip(self):
        admin = get_user_model().objects.create_superuser(username="public-admin", password="test-pass-9821")
        self.client.force_login(admin)
        with mock.patch.dict("os.environ", {"SOC_PORTAL_PUBLIC_SYSLOG_IP": "141.105.111.227"}), mock.patch("core.views.provision_export") as provision:
            provision.return_value = ExportConfiguration(status=ExportConfiguration.Status.CONFIGURED, port=5514)
            response = self.client.post(reverse("export_destination", args=[self.device_record.pk]), {"destination": "141.105.111.227"})
            self.assertRedirects(response, reverse("device_detail", args=[self.device_record.pk]))
            self.assertContains(self.client.get(reverse("device_detail", args=[self.device_record.pk])), "141.105.111.227")
        self.assertEqual(ExportConfiguration.objects.get(device=self.device_record).destination, "141.105.111.227")
        provision.assert_called_once()


@override_settings(SECURE_SSL_REDIRECT=False)
class UrgentAlertTests(TestCase):
    def setUp(self):
        self.now = timezone.now().replace(microsecond=0)
        self.a = Client.objects.create(name="Cliente A", code="cliente-a", report_email="reports-a@example.test",
                                       urgent_email="urgent-a@example.test", urgent_alerts_enabled=True)
        self.b = Client.objects.create(name="Cliente B", code="cliente-b", report_email="reports-b@example.test",
                                       urgent_alerts_enabled=True)
        for client, source in [(self.a, "192.0.2.11"), (self.b, "192.0.2.22")]:
            site = Site.objects.create(client=client, name="Sede", code="sede")
            device = Device.objects.create(site=site, name="Firewall", vendor=Device.Vendor.UNIFI)
            ExportConfiguration.objects.create(device=device, source_ip=source, receiver_ready=True)
        from .testing_access import legacy_sources
        legacy_sources()
        MailSettings.objects.create(pk=1, from_email="soc@example.test", encrypted_api_key="encrypted",
                                    enabled=True, last_test_ok=True)

    def hit(self, event_id, location, action="allowed", destination="10.0.0.13", category="Security", name="Threat Detected"):
        return {"_index": "wazuh-alerts-test", "_id": event_id, "_source": {
            "timestamp": (self.now - timedelta(minutes=1)).isoformat(), "location": location,
            "rule": {"level": 10, "description": "UniFi security detection"},
            "data": {"srcip": "203.0.113.8", "dstip": destination, "dstport": "10001",
                     "unifi": {"category": category, "action": action, "event_name": name, "ips_signature": "ET SCAN"}},
        }}

    def test_first_poll_starts_now_without_sending_old_events(self):
        from .urgent_alerts import scan_events
        with mock.patch("core.urgent_alerts._search") as search:
            self.assertEqual(scan_events(self.now), 0)
        search.assert_not_called()
        self.assertEqual(UrgentMonitorCursor.objects.get(pk=1).last_checked_at, self.now)

    def test_urgent_mail_stays_with_its_client_and_is_not_repeated(self):
        from .urgent_alerts import deliver_pending, scan_events
        UrgentMonitorCursor.objects.create(pk=1, last_checked_at=self.now - timedelta(minutes=3))
        hits = [self.hit("a", "192.0.2.11"), self.hit("b", "192.0.2.22"), self.hit("blocked", "192.0.2.11", action="blocked")]
        response = {"hits": {"total": {"value": len(hits)}, "hits": hits}}
        inventory = lambda client, sources, events=None: {sources[0]: {"device_name": "Firewall", "site_name": "Sede", "hosts": {"10.0.0.13": f"Equipo {client.name}"}}}
        with mock.patch("core.urgent_alerts._search", return_value=response), mock.patch(
            "core.urgent_alerts.indexer_authorization", return_value="test-auth"
        ), mock.patch("core.urgent_alerts.inventories_for_sources", side_effect=inventory), mock.patch(
            "core.urgent_alerts.send_customer_email", return_value="provider-id"
        ) as send:
            self.assertEqual(scan_events(self.now), 2)
            self.assertEqual(deliver_pending(self.now), 2)
            self.assertEqual(scan_events(self.now + timedelta(minutes=1)), 0)
            self.assertEqual(deliver_pending(self.now + timedelta(minutes=1)), 0)
        self.assertEqual(UrgentAlert.objects.count(), 2)
        self.assertEqual([call.args[0] for call in send.call_args_list], ["urgent-a@example.test", "reports-b@example.test"])
        self.assertIn("Cliente A", send.call_args_list[0].args[2])
        self.assertNotIn("Cliente B", send.call_args_list[0].args[2])
        self.assertTrue(all(row.status == UrgentAlert.Status.ACCEPTED for row in UrgentAlert.objects.all()))

    def test_inventory_and_cloud_calls_happen_before_reserving_the_writer(self):
        from django.db import connection
        from .urgent_alerts import scan_events
        UrgentMonitorCursor.objects.create(pk=1, last_checked_at=self.now - timedelta(minutes=3))
        hits = [self.hit("a", "192.0.2.11"), self.hit("c", "192.0.2.11")]
        response = {"hits": {"total": {"value": 2}, "hits": hits}}
        baseline, depths, asked = len(connection.atomic_blocks), [], []
        def inventory(client, sources, events=None):
            depths.append(len(connection.atomic_blocks)); asked.append(len(events or []))
            return {sources[0]: {"device_name": "Firewall", "site_name": "Sede", "hosts": {}}}
        with mock.patch("core.urgent_alerts._search", return_value=response), mock.patch(
            "core.urgent_alerts.indexer_authorization", return_value="test-auth"
        ), mock.patch("core.urgent_alerts.inventories_for_sources", side_effect=inventory):
            self.assertEqual(scan_events(self.now), 2)
        self.assertEqual(depths, [baseline], 'una consulta por fuente y fuera de la transacción')
        self.assertEqual(asked, [2], 'solo las evidencias de los eventos de la página')

    def test_same_asset_is_grouped_for_one_hour(self):
        from .urgent_alerts import deliver_pending, scan_events
        UrgentMonitorCursor.objects.create(pk=1, last_checked_at=self.now - timedelta(minutes=3))
        hits = [self.hit("first", "192.0.2.11"), self.hit("second", "192.0.2.11")]
        response = {"hits": {"total": {"value": 2}, "hits": hits}}
        with mock.patch("core.urgent_alerts._search", return_value=response), mock.patch(
            "core.urgent_alerts.indexer_authorization", return_value="test-auth"
        ), mock.patch("core.urgent_alerts.inventories_for_sources", return_value={"192.0.2.11": {"device_name": "Firewall", "site_name": "Sede", "hosts": {}}}), mock.patch(
            "core.urgent_alerts.send_customer_email", return_value="provider-id"
        ) as send:
            self.assertEqual(scan_events(self.now), 2)
            self.assertEqual(deliver_pending(self.now), 1)
        self.assertEqual(send.call_count, 1)
        self.assertEqual(UrgentAlert.objects.filter(status=UrgentAlert.Status.SUPPRESSED).count(), 1)

    def test_no_mail_settings_or_opt_in_does_not_send(self):
        from .urgent_alerts import deliver_pending
        self.a.urgent_alerts_enabled = False
        self.a.save()
        MailSettings.objects.update(enabled=False)
        with mock.patch("core.urgent_alerts.send_customer_email") as send:
            self.assertEqual(deliver_pending(self.now), 0)
        send.assert_not_called()

    def test_client_form_requires_recipient_for_urgent_alerts(self):
        from .forms import ClientForm
        form = ClientForm(data={"name": "Otro", "code": "otro", "urgent_alerts_enabled": "on", "active": "on"})
        self.assertFalse(form.is_valid())
        self.assertIn("urgent_email", form.errors)

    def test_critical_and_internet_outage_rules_respect_client_choice(self):
        from .urgent_alerts import _event_kind
        critical = self.hit("critical", "192.0.2.11", action="blocked")["_source"]
        critical["rule"]["level"] = 12
        self.assertEqual(_event_kind(critical, self.a)[0], UrgentAlert.Kind.SECURITY_CRITICAL)
        outage = self.hit("outage", "192.0.2.11", action="", category="System", name="Internet Down")["_source"]
        self.assertIsNone(_event_kind(outage, self.a)[0])
        self.a.urgent_availability_enabled = True
        self.assertEqual(_event_kind(outage, self.a)[0], UrgentAlert.Kind.AVAILABILITY)

    def test_shared_wazuh_source_is_not_emailed_to_either_client(self):
        from .urgent_alerts import scan_events
        second = Device.objects.get(site__client=self.b)
        ExportConfiguration.objects.filter(device=second).update(source_ip="192.0.2.11")
        UrgentMonitorCursor.objects.create(pk=1, last_checked_at=self.now - timedelta(minutes=3))
        with mock.patch("core.urgent_alerts._search") as search:
            self.assertEqual(scan_events(self.now), 0)
        search.assert_not_called()
        self.assertFalse(UrgentAlert.objects.exists())

    def test_urgent_panel_shows_only_selected_client(self):
        user = get_user_model().objects.create_user(username="soc-operator", password="test-pass-9821")
        workflow_access(user, reader=False)
        self.client.force_login(user)
        for client, letter, source in [(self.a, "a", "192.0.2.11"), (self.b, "b", "192.0.2.22")]:
            UrgentAlert.objects.create(client=client, event_uid=letter * 64, fingerprint=letter * 64,
                                       kind=UrgentAlert.Kind.SECURITY_ALLOWED, observed_at=self.now,
                                       source_ip=source, recipient=client.report_email, asset_name="Equipo")
        response = self.client.get(reverse("urgent_alert_list"), {"client": self.a.pk})
        self.assertContains(response, "Cliente A")
        self.assertEqual([row.client_id for row in response.context["alerts"]], [self.a.pk])

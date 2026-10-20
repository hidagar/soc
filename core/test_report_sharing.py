from .testing_access import workflow_access
import json
from datetime import date, timedelta
from unittest import mock

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.core import signing
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from .mail_delivery import encrypt_sendgrid_key, send_via_sendgrid
from .models import Client, MailSettings, ReportShare, WeeklyReport
from .report_sharing import SALT, create_report_link


@override_settings(SECURE_SSL_REDIRECT=False)
class ReportSharingTests(TestCase):
    def setUp(self):
        self.customer = Client.objects.create(name="Cliente uno", code="one", report_email="client@example.test", weekly_reports_enabled=True)
        self.other = Client.objects.create(name="Cliente secreto dos", code="two")
        self.report = WeeklyReport.objects.create(client=self.customer, week_start=date(2026, 9, 21), sources=["192.0.2.1"], security_count=4, blocked_count=4,
            findings=[{"asset_name": "Alarma", "asset_ip": "10.0.0.13", "recommendations": ["Revisar el servicio publicado."], "signatures": ["ET SCAN"], "count":4}])
        self.config = MailSettings.objects.create(pk=1, from_email="soc@example.test", reply_to_email="noc@ibred.es", report_copy_email="noc@ibred.es",
            enabled=True, last_test_ok=True, encrypted_api_key="opaque", public_reports_url="https://reports.example.test", public_reports_verified=True)

    def link(self):
        return create_report_link(self.report).removeprefix(self.config.public_reports_url)

    def test_link_scopes_html_and_pdf_and_never_exposes_internal_portal(self):
        path = self.link()
        response = self.client.get(path, {"client": self.other.pk, "week":"2025-01-01"})
        self.assertContains(response, self.customer.name)
        self.assertContains(response, "Descargar PDF")
        self.assertContains(response, "ET SCAN")
        for private in (self.other.name, "Envío interno", "Clientes y sedes", "Administración", "Semana siguiente", "client@example.test"):
            self.assertNotContains(response, private)
        self.assertEqual(response["Referrer-Policy"], "no-referrer")
        self.assertIn("no-store", response["Cache-Control"])
        self.assertIn("noindex", response["X-Robots-Tag"])
        self.assertEqual(self.client.get(reverse("client_detail", args=[self.customer.pk])).status_code, 302)
        pdf = self.client.get(path + "pdf/")
        self.assertEqual(pdf.status_code, 200)
        self.assertEqual(pdf["Content-Type"], "application/pdf")
        self.assertTrue(pdf.content.startswith(b"%PDF"))
        self.assertIn("attachment", pdf["Content-Disposition"])

    def test_tampering_invalid_nonce_revocation_and_expiry_are_denied(self):
        path = self.link()
        token = path.split("/")[-2]
        for value in (token + "x", signing.dumps({"report": self.report.pk, "nonce":"invalid"}, salt=SALT),
                      signing.dumps({"report": 2**70, "nonce":"invalid"}, salt=SALT)):
            self.assertEqual(self.client.get(reverse("customer_report", args=[value])).status_code, 404)
        share = ReportShare.objects.get(report=self.report)
        share.revoked = True
        share.save()
        self.assertEqual(self.client.get(path).status_code, 404)
        self.assertEqual(self.client.get(path + "pdf/").status_code, 404)
        share.revoked = False
        share.expires_at = timezone.now() - timedelta(seconds=1)
        share.save()
        self.assertEqual(self.client.get(path).status_code, 404)
        share.expires_at = timezone.now() + timedelta(days=90)
        share.save()
        self.customer.active = False
        self.customer.save()
        self.assertEqual(self.client.get(path).status_code, 404)

    def test_renew_invalidates_old_link_without_sending_email(self):
        user = get_user_model().objects.create_user("operator")
        workflow_access(user, reader=False)
        self.client.force_login(user)
        old = self.link()
        url = reverse("manage_report_link", args=[self.report.pk])
        self.assertEqual(self.client.get(url).status_code, 405)
        self.assertEqual(self.client.post(url, {"action":"renew"}).status_code, 403)
        user.user_permissions.add(Permission.objects.get(codename="manage_connections"))
        self.client.post(url, {"action":"renew"})
        self.assertEqual(self.client.get(old).status_code, 404)
        self.assertEqual(self.client.get(self.link()).status_code, 200)
        self.report.refresh_from_db()
        self.assertIsNone(self.report.sent_at)

    def test_send_uses_brief_formal_message_and_link_without_sensitive_details(self):
        from .reporting import send_report
        from .testing_access import collected_report
        collected_report(self.report)
        with mock.patch("core.mail_delivery.send_via_sendgrid", return_value="message-id") as send:
            self.assertTrue(send_report(self.report))
            self.assertFalse(send_report(self.report))
        self.assertEqual(send.call_count, 1)
        self.assertEqual(send.call_args.kwargs["copy_to"], "noc@ibred.es")
        plain, html = send.call_args.args[3:5]
        self.assertIn("Estimado equipo de Cliente uno", plain)
        self.assertIn("21/09/2026 al 27/09/2026", plain)
        self.assertIn("Consultar informe", html)
        self.assertIn('https://reports.example.test/static/brand/ibred-empresas-color.png', html)
        self.assertIn('ib-red empresas', html)
        self.assertIn("https://reports.example.test/reports/", plain)
        self.assertNotIn("ET SCAN", plain)
        self.assertNotIn("10.0.0.13", html)

    def test_missing_or_unverified_public_url_prevents_customer_delivery(self):
        from .reporting import send_report
        self.config.public_reports_verified = False
        self.config.save()
        with mock.patch("core.mail_delivery.send_via_sendgrid") as send:
            self.assertFalse(send_report(self.report))
            send.assert_not_called()
        self.assertFalse(ReportShare.objects.exists())

    def test_sendgrid_sets_reply_to_bcc_and_disables_link_tracking_without_attachments(self):
        with mock.patch.dict("os.environ", {"SOC_PORTAL_MAIL_KEY":Fernet.generate_key().decode()}):
            self.config.encrypted_api_key = encrypt_sendgrid_key("SG.secret")
            response = mock.MagicMock(status=202)
            response.headers = {"X-Message-Id":"id"}
            opener = mock.MagicMock()
            opener.open.return_value.__enter__.return_value = response
            with mock.patch("core.mail_delivery.request.build_opener", return_value=opener):
                send_via_sendgrid(self.config, "client@example.test", "Report", "text", "html", copy_to="noc@ibred.es")
                payload = json.loads(opener.open.call_args.args[0].data)
                self.assertEqual(payload["reply_to"], {"email":"noc@ibred.es"})
                self.assertEqual(payload["personalizations"][0]["bcc"], [{"email":"noc@ibred.es"}])
                self.assertNotIn("attachments", payload)
                self.assertFalse(payload["tracking_settings"]["click_tracking"]["enable"])
                send_via_sendgrid(self.config, "NOC@ibred.es", "Report", "text", "html", copy_to="noc@ibred.es")
                self.assertNotIn("bcc", json.loads(opener.open.call_args.args[0].data)["personalizations"][0])

    def test_editing_report_settings_preserves_verified_sendgrid_but_resets_url_verification(self):
        user = get_user_model().objects.create_user("operator")
        workflow_access(user, reader=False)
        user.user_permissions.add(Permission.objects.get(codename="manage_connections"))
        self.client.force_login(user)
        response = self.client.post(reverse("mail_settings"), {"action":"save", "region":"global", "from_email":"soc@example.test",
            "reply_to_email":"noc@ibred.es", "report_copy_email":"noc@ibred.es", "public_reports_url":"https://new.example.test"})
        self.assertEqual(response.status_code, 302)
        self.config.refresh_from_db()
        self.assertTrue(self.config.enabled)
        self.assertTrue(self.config.last_test_ok)
        self.assertFalse(self.config.public_reports_verified)

    def test_public_endpoint_verification_rejects_tls_error_and_requires_correct_service(self):
        user = get_user_model().objects.create_user("operator")
        workflow_access(user, reader=False)
        user.user_permissions.add(Permission.objects.get(codename="manage_connections"))
        self.client.force_login(user)
        url = reverse("verify_public_reports")
        opener = mock.MagicMock()
        opener.open.side_effect = OSError("TLS error")
        with mock.patch("urllib.request.build_opener", return_value=opener):
            self.client.post(url)
        self.config.refresh_from_db()
        self.assertFalse(self.config.public_reports_verified)
        opener.open.side_effect = None
        response = mock.MagicMock(status=200)
        response.headers = {"X-SOC-Reports":"v1"}
        opener.open.return_value.__enter__.return_value = response
        with mock.patch("urllib.request.build_opener", return_value=opener):
            self.client.post(url)
        self.config.refresh_from_db()
        self.assertTrue(self.config.public_reports_verified)

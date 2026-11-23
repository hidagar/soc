"""Antivirus de los adjuntos: protocolo de clamd con un servidor simulado por socket Unix, resultados y descargas."""
import os
import shutil
import socket
import struct
import tempfile
import threading
from datetime import timedelta
from unittest import mock

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from . import antivirus
from .models import (AuditEvent, Client, CustomerRequest, CustomerRequestAttachment, CustomerRequestEntry, OperationalIssue,
                     StaffAccess)

PNG = b'\x89PNG\r\n\x1a\n' + b'\x00' * 64
MALWARE = b'%PDF-1.4\n' + b'MUESTRA-DE-PRUEBA' + b'\n' * 10
SIGNATURE_DATE = 'Sun Nov 22 09:29:35 2026'


class FakeClamd:
    """clamd mínimo: VERSION e INSTREAM; marca como infectado lo que contiene MUESTRA-DE-PRUEBA."""

    def __init__(self, signature_date=SIGNATURE_DATE):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, 'clamd.ctl')
        self.signature_date, self.streams = signature_date, []
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(self.path)
        self.server.listen(5)
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while True:
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            with conn:
                command = b''
                while not command.endswith(b'\0'):
                    command += conn.recv(1)
                if command == b'zVERSION\0':
                    conn.sendall(f'ClamAV 1.0.7/27450/{self.signature_date}\0'.encode())
                    continue
                data = b''
                while True:
                    size = struct.unpack('!L', self._read(conn, 4))[0]
                    if not size:
                        break
                    data += self._read(conn, size)
                self.streams.append(data)
                found = b'MUESTRA-DE-PRUEBA' in data
                conn.sendall(b'stream: Win.Test.Muestra FOUND\0' if found else b'stream: OK\0')

    @staticmethod
    def _read(conn, size):
        data = b''
        while len(data) < size:
            data += conn.recv(size - len(data))
        return data

    def close(self):
        self.server.close()
        shutil.rmtree(self.dir, True)


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class AntivirusTests(TestCase):
    def setUp(self):
        self.now = timezone.now()
        self.company = Client.objects.create(name='Empresa A', code='a')
        User = get_user_model()
        self.customer = User.objects.create_user('ana', email='ana@a.test')
        StaffAccess.objects.create(user=self.customer, role='customer').clients.add(self.company)
        self.operator = User.objects.create_user('operador')
        StaffAccess.objects.create(user=self.operator, role='operator').clients.add(self.company)
        self.operator.user_permissions.add(*Permission.objects.filter(codename__in=['change_incident']))
        self.client.force_login(self.customer)
        self.client.post(reverse('customer_requests'), {
            'kind': 'incident', 'subject': 'Correo raro', 'text': 'Adjunto el correo y la factura.',
            'attachments': [SimpleUploadedFile('captura.png', PNG), SimpleUploadedFile('factura.pdf', MALWARE)]})
        self.req = CustomerRequest.objects.get()
        CustomerRequest.objects.filter(pk=self.req.pk).update(soc_notified_at=self.now)

    def clamd(self, **kwargs):
        fake = FakeClamd(**kwargs)
        self.addCleanup(fake.close)
        patcher = mock.patch.dict(os.environ, {'SOC_PORTAL_CLAMD_SOCKET': fake.path})
        patcher.start()
        self.addCleanup(patcher.stop)
        return fake

    def items(self):
        return {a.name: a for a in CustomerRequestAttachment.objects.all()}

    def test_files_are_scanned_through_the_socket_and_malware_is_reported(self):
        fake = self.clamd()
        self.assertEqual(antivirus.scan_pending(self.now), 2)
        self.assertEqual(sorted(fake.streams), sorted([PNG, MALWARE]))  # el archivo descifrado, completo
        items = self.items()
        self.assertEqual((items['captura.png'].scan_status, items['factura.pdf'].scan_status), ('clean', 'infected'))
        self.assertEqual(items['factura.pdf'].scan_result, 'Win.Test.Muestra')
        self.assertTrue(items['factura.pdf'].scan_engine.startswith('ClamAV 1.0.7/27450'))
        note = CustomerRequestEntry.objects.filter(request=self.req, kind='internal').get()
        self.assertIn('Win.Test.Muestra', note.text)
        self.req.refresh_from_db()
        self.assertIsNone(self.req.soc_notified_at)  # novedad para el correo interno del SOC
        self.assertTrue(AuditEvent.objects.filter(action='request.attachment_infected').exists())
        self.assertEqual(antivirus.scan_pending(self.now), 0)  # no se repite

    def test_infected_files_are_blocked_for_the_customer_and_a_sample_for_the_soc(self):
        self.clamd()
        antivirus.scan_pending(self.now)
        items = self.items()
        bad, good = items['factura.pdf'], items['captura.png']
        page = self.client.get(reverse('customer_request_detail', args=[self.req.pk]))
        self.assertContains(page, 'Bloqueado por el antivirus')
        self.assertNotContains(page, 'Win.Test.Muestra')  # la nota interna no llega al cliente
        self.assertEqual(self.client.get(reverse('customer_request_attachment', args=[self.req.pk, bad.pk])).status_code, 403)
        self.assertEqual(self.client.get(reverse('customer_request_attachment', args=[self.req.pk, good.pk])).content, PNG)
        self.client.force_login(self.operator)
        page = self.client.get(reverse('request_detail', args=[self.req.pk]))
        self.assertContains(page, 'Malware: Win.Test.Muestra')
        self.assertContains(page, 'ClamAV: sin amenazas')
        self.assertEqual(self.client.get(reverse('request_attachment', args=[self.req.pk, bad.pk])).status_code, 403)
        sample = self.client.get(reverse('request_attachment', args=[self.req.pk, bad.pk]), {'muestra': '1'})
        self.assertEqual(sample.content, MALWARE)
        self.assertTrue(AuditEvent.objects.filter(action='request.attachment_download',
                                                  details__reason='muestra con malware').exists())

    def test_without_clamav_files_are_marked_unscanned_and_scanned_later(self):
        with mock.patch.dict(os.environ, {'SOC_PORTAL_CLAMD_SOCKET': ''}), \
                mock.patch.object(antivirus, 'DEFAULT_SOCKET', '/nonexistent/clamd.ctl'):
            self.assertEqual(antivirus.scan_pending(self.now), 0)
        self.assertEqual({a.scan_status for a in self.items().values()}, {'unscanned'})
        self.assertFalse(OperationalIssue.objects.filter(key=antivirus.ISSUE, active=True).exists())
        self.clamd()
        self.assertEqual(antivirus.scan_pending(self.now), 2)  # ClamAV instalado después: se analizan

    def test_configured_but_down_raises_an_issue_after_fifteen_minutes(self):
        with mock.patch.dict(os.environ, {'SOC_PORTAL_CLAMD_SOCKET': '/nonexistent/clamd.ctl'}):
            antivirus.scan_pending(self.now)
            self.assertFalse(OperationalIssue.objects.filter(key=antivirus.ISSUE, active=True).exists())
            antivirus.scan_pending(self.now + timedelta(minutes=16))
        issue = OperationalIssue.objects.get(key=antivirus.ISSUE, active=True)
        self.assertIn('no responde', issue.details)
        self.assertEqual({a.scan_status for a in self.items().values()}, {'pending'})

    def test_old_signatures_raise_an_issue(self):
        self.clamd(signature_date='Mon Nov 16 09:00:00 2026')
        antivirus.scan_pending(timezone.make_aware(timezone.datetime(2026, 11, 23, 12, 0)))
        self.assertIn('firmas', OperationalIssue.objects.get(key=antivirus.ISSUE, active=True).title)

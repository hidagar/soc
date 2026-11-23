"""Adjuntos de las solicitudes: tipos, límites, cifrado, descarga segura y visibilidad (invariante 3)."""
import os
from unittest import mock

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.urls import reverse

from .models import AuditEvent, Client, CustomerRequest, CustomerRequestAttachment, CustomerRequestEntry, StaffAccess
from .request_attachments import safe_name

PNG = b'\x89PNG\r\n\x1a\n' + b'\x00' * 64
PDF = b'%PDF-1.7\n' + b'contenido' * 10
EML = b'From: falso@banco.example\nSubject: Urgente\n\nHaz clic aqui.\n'


def upload(name, data, content_type='application/octet-stream'):
    return SimpleUploadedFile(name, data, content_type=content_type)


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class RequestAttachmentTests(TestCase):
    def setUp(self):
        self.company = Client.objects.create(name='Empresa A', code='a')
        self.other = Client.objects.create(name='Empresa B', code='b')
        User = get_user_model()
        self.customer = User.objects.create_user('ana', email='ana@a.test')
        StaffAccess.objects.create(user=self.customer, role='customer').clients.add(self.company)
        self.intruder = User.objects.create_user('beto', email='beto@b.test')
        StaffAccess.objects.create(user=self.intruder, role='customer').clients.add(self.other)
        self.operator = User.objects.create_user('operador')
        StaffAccess.objects.create(user=self.operator, role='operator').clients.add(self.company)
        self.operator.user_permissions.add(*Permission.objects.filter(codename__in=['change_incident', 'add_incident']))

    def create(self, *files, text='Me ha llegado este correo y lo he abierto.'):
        self.client.force_login(self.customer)
        return self.client.post(reverse('customer_requests'), {'kind': 'incident', 'subject': 'Correo sospechoso', 'text': text,
                                                               'attachments': list(files)})

    def test_customer_attaches_files_that_are_stored_encrypted_and_downloaded_safely(self):
        self.create(upload('captura.png', PNG), upload('../../etc/correo raro.eml', EML))
        req = CustomerRequest.objects.get()
        items = list(CustomerRequestAttachment.objects.order_by('pk'))
        self.assertEqual([(a.name, a.content_type, a.size) for a in items],
                         [('captura.png', 'image/png', len(PNG)), ('correo raro.eml', 'message/rfc822', len(EML))])
        self.assertNotIn(b'falso@banco', bytes(items[1].encrypted_data))  # cifrado en la base
        page = self.client.get(reverse('customer_request_detail', args=[req.pk]))
        self.assertContains(page, 'correo raro.eml')
        response = self.client.get(reverse('customer_request_attachment', args=[req.pk, items[1].pk]))
        self.assertEqual(response.content, EML)
        self.assertEqual(response['Content-Type'], 'application/octet-stream')
        self.assertTrue(response['Content-Disposition'].startswith('attachment; filename="correo raro.eml"'))
        self.assertEqual(response['X-Content-Type-Options'], 'nosniff')
        self.assertIn('sandbox', response['Content-Security-Policy'])
        self.assertIn('no-store', response['Cache-Control'])

    def test_disguised_executable_or_unknown_types_are_rejected(self):
        for files, text in (((upload('factura.pdf', b'MZ\x90\x00 ejecutable'),), 'no parece un archivo .pdf'),
                            ((upload('programa.exe', b'MZ'),), 'tipo de archivo no admitido'),
                            ((upload('notas.txt', b'texto\x00binario'),), 'no parece un archivo .txt'),
                            ((upload('vacio.png', b''),), 'está vacío'),
                            (tuple(upload(f'c{i}.png', PNG) for i in range(4)), 'Como máximo 3 archivos')):
            response = self.create(*files)
            self.assertContains(response, text)
        self.assertFalse(CustomerRequest.objects.exists())
        self.assertFalse(CustomerRequestAttachment.objects.exists())

    def test_total_size_follows_the_configured_limit(self):
        with mock.patch.dict(os.environ, {'SOC_PORTAL_ATTACHMENTS_MAX_MB': '0.1'}):
            response = self.create(upload('grande.pdf', PDF + b'x' * 200_000))
        self.assertContains(response, 'Se admiten hasta 3 archivos y 0,1 MB en total')
        self.assertFalse(CustomerRequestAttachment.objects.exists())

    def test_internal_note_attachments_never_reach_the_customer(self):
        self.create()
        req = CustomerRequest.objects.get()
        self.client.force_login(self.operator)
        self.client.post(reverse('request_detail', args=[req.pk]), {'action': 'note', 'text': 'Cabeceras analizadas',
                                                                    'attachments': [upload('analisis.pdf', PDF)]})
        self.client.post(reverse('request_detail', args=[req.pk]), {'action': 'reply', 'status': 'waiting', 'text': 'Os pasamos la guía',
                                                                    'attachments': [upload('guia.pdf', PDF)]})
        internal = CustomerRequestAttachment.objects.get(name='analisis.pdf')
        shared = CustomerRequestAttachment.objects.get(name='guia.pdf')
        page = self.client.get(reverse('request_detail', args=[req.pk]))
        self.assertContains(page, 'analisis.pdf')
        self.assertContains(page, 'ClamAV analiza los adjuntos')
        self.assertEqual(self.client.get(reverse('request_attachment', args=[req.pk, internal.pk])).content, PDF)
        self.assertTrue(AuditEvent.objects.filter(action='request.attachment_download').exists())
        self.client.force_login(self.customer)
        page = self.client.get(reverse('customer_request_detail', args=[req.pk]))
        self.assertContains(page, 'guia.pdf')
        self.assertNotContains(page, 'analisis.pdf')
        self.assertEqual(self.client.get(reverse('customer_request_attachment', args=[req.pk, internal.pk])).status_code, 404)
        self.assertEqual(self.client.get(reverse('customer_request_attachment', args=[req.pk, shared.pk])).content, PDF)

    def test_other_customers_cannot_download_and_ids_must_match(self):
        self.create(upload('captura.png', PNG))
        req = CustomerRequest.objects.get()
        item = CustomerRequestAttachment.objects.get()
        self.client.force_login(self.intruder)
        self.assertEqual(self.client.get(reverse('customer_request_attachment', args=[req.pk, item.pk])).status_code, 404)
        self.client.force_login(self.customer)
        other = CustomerRequest.objects.create(client=self.company, kind='question', subject='Otra')
        self.assertEqual(self.client.get(reverse('customer_request_attachment', args=[other.pk, item.pk])).status_code, 404)

    def test_customer_can_reply_with_only_a_file(self):
        self.create()
        req = CustomerRequest.objects.get()
        self.client.post(reverse('customer_request_detail', args=[req.pk]), {'text': '', 'attachments': [upload('log.txt', b'linea 1\n')]})
        entry = CustomerRequestEntry.objects.filter(request=req).latest('pk')
        self.assertEqual(entry.text, 'Adjunto log.txt.')
        self.assertEqual(entry.attachments.get().name, 'log.txt')

    def test_attachments_are_deleted_with_their_request(self):
        self.create(upload('captura.png', PNG))
        CustomerRequest.objects.all().delete()
        self.assertFalse(CustomerRequestAttachment.objects.exists())

    def test_file_names_are_cleaned(self):
        self.assertEqual(safe_name('C:\\Users\\ana\\captura\x00.png'), 'captura.png')
        self.assertEqual(safe_name('...'), 'adjunto')
        long = safe_name('a' * 300 + '.pdf')
        self.assertTrue(long.endswith('.pdf') and len(long) == 120)

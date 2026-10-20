"""Escritores concurrentes reales (hilos con conexiones propias), criterio del bloque 4.

Se omiten con SQLite en memoria: los hilos no comparten esa base. En CI se
ejecutan contra PostgreSQL y con la base SQLite de archivo del ensayo de testing.md.
"""
import json
import threading
import uuid

from django.db import connection, connections
from django.test import Client as HttpClient, TransactionTestCase, override_settings
from django.urls import reverse

from .models import AuditEvent, Client, Device, SecureLogReceipt, Site
from .secure_logs import prepare
from .security import audit, audit_integrity, decrypt

WRITERS = 6


def run_concurrently(target, count=WRITERS):
    start = threading.Barrier(count)
    results, errors = [], []

    def worker(index):
        try:
            start.wait(timeout=10)
            results.append(target(index))
        except Exception as exc:  # se informa en la aserción, sin ocultar el tipo
            errors.append(f'{type(exc).__name__}: {exc}')
        finally:
            connections.close_all()

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    if any(thread.is_alive() for thread in threads):
        raise AssertionError('Un escritor no terminó')
    return results, errors


class ConcurrentWritersTests(TransactionTestCase):
    def setUp(self):
        if connection.vendor == 'sqlite' and connection.is_in_memory_db():
            self.skipTest('Requiere PostgreSQL o SQLite de archivo (ver docs/testing.md).')

    def test_concurrent_audit_events_keep_a_single_valid_chain(self):
        results, errors = run_concurrently(lambda index: audit('concurrency.check', details={'count': index}).pk)
        self.assertEqual(errors, [])
        self.assertEqual(AuditEvent.objects.count(), WRITERS)
        self.assertEqual(len(set(AuditEvent.objects.values_list('previous_hash', flat=True))), WRITERS)
        self.assertTrue(audit_integrity())

    @override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
    def test_same_https_batch_delivered_concurrently_is_stored_once(self):
        owner = Client.objects.create(name='A', code='a')
        site = Site.objects.create(client=owner, name='Oficina', code='oficina')
        channel = prepare(Device.objects.create(name='Firewall', vendor='opnsense', site=site))
        channel.receiver_ready = True
        channel.save()
        body = json.dumps({'batch_id': str(uuid.uuid4()), 'messages': ['actividad ordinaria']})
        url = reverse('secure_log_ingest', args=[channel.pk])
        token = 'Bearer ' + decrypt(channel.encrypted_token)

        def deliver(index):
            response = HttpClient().post(url, body, content_type='application/json', secure=True,
                                         HTTP_AUTHORIZATION=token)
            return response.status_code, response.json().get('duplicate')

        results, errors = run_concurrently(deliver)
        self.assertEqual(errors, [])
        self.assertEqual(sorted(status for status, _ in results), [202] * WRITERS)
        self.assertEqual(sum(1 for _, duplicate in results if not duplicate), 1)
        self.assertEqual(SecureLogReceipt.objects.filter(channel=channel).count(), 1)

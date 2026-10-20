"""Traslado SQLite→PostgreSQL. El origen se crea en un proceso aparte con datos anonimizados."""
import os
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timezone as dt_timezone
from pathlib import Path
from unittest import mock

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management import CommandError, call_command
from django.db import connection
from django.test import SimpleTestCase, TransactionTestCase

from . import database_transfer
from .database_transfer import TransferError, field_problem, open_source, preflight, transfer

OLD = datetime(2025, 3, 4, 5, 6, 7, 891011, tzinfo=dt_timezone.utc)

POPULATE = r'''
import json, uuid
from datetime import datetime, timezone as tz
import django
django.setup()
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.contrib.sessions.backends.db import SessionStore
from core.models import (Client, Site, Device, ExportConfiguration, Incident, SecurityEvidence, SourceOwnership,
    StaffAccess, MfaProfile, WorkerState)
from core.secure_logs import prepare
from core.security import audit, encrypt
OLD = datetime(2025, 3, 4, 5, 6, 7, 891011, tzinfo=tz.utc)
U = get_user_model()
a = Client.objects.create(name='Empresa A', code='empresa-a', notes='Nota interna ñ')
b = Client.objects.create(name='Empresa B', code='empresa-b')
Client.objects.filter(pk=a.pk).update(created_at=OLD)
site = Site.objects.create(client=a, name='Oficina', code='oficina')
device = Device.objects.create(site=site, name='FW', vendor='opnsense')
ExportConfiguration.objects.create(device=device, source_ip='198.51.100.7')
channel = prepare(device)
operator = U.objects.create_user('operador', 'operador@example.test', 'Prueba-segura-2026')
operator.groups.add(Group.objects.get(name='SOC Operador'))
access = StaffAccess.objects.create(user=operator, role='operator'); access.clients.add(a, b)
MfaProfile.objects.create(user=operator, enabled=True, encrypted_secret=encrypt('JBSWY3DPEHPK3PXP'),
                          recovery_hashes=['pbkdf2$uno', 'pbkdf2$dos'])
incident = Incident.objects.create(client=a, site=site, device=device, title='Detección', description='Detalle',
                                   fingerprint='protection-1')
Incident.objects.filter(pk=incident.pk).update(created_at=OLD, updated_at=OLD)
SourceOwnership.objects.create(source='198.51.100.7', client_scope_id=a.pk, valid_from=OLD)
for index in range(25):
    SecurityEvidence.objects.create(uid=f'{index:064x}', device=device, incident=incident, observed_at=OLD,
        engine='suricata', signature=f'Firma {index}', source_ip='203.0.113.9', destination_ip='2001:db8::1',
        client_scope_id=a.pk, interpretation={'z': 1, 'a': [1, 2], 'texto': 'ñ'}, level=7)
WorkerState.objects.create(name='Zeta-cursor', details={'b': 2, 'a': 1})
WorkerState.objects.create(name='alfa-cursor')
for index in range(3):
    audit('transfer.seed', a, {'count': index})
session = SessionStore(); session['soc_mfa_user'] = operator.pk; session.create()
from core.models import WeeklyReport, ReportVersion
report = WeeklyReport.objects.create(client=a, week_start=OLD.date())
ReportVersion.objects.create(report=report, number=1, html='<p>Informe ñ</p>', pdf=b'%PDF-1.4\x00\xff binario',
                             html_sha256='h', pdf_sha256='p')
print('ok')
'''


def build_source(path, script=POPULATE):
    env = {k: v for k, v in os.environ.items() if not k.startswith('SOC_PORTAL_DB_')}
    env.update(SOC_PORTAL_DEBUG='1', SOC_PORTAL_MFA_REQUIRED='0', SOC_PORTAL_SQLITE_PATH=str(path),
               DJANGO_SETTINGS_MODULE='socportal.settings')
    for command in ([sys.executable, 'manage.py', 'migrate', '-v0'], [sys.executable, '-c', script]):
        result = subprocess.run(command, cwd=settings.BASE_DIR, env=env, capture_output=True, text=True)
        if result.returncode:
            raise AssertionError(result.stderr[-2000:])


class FieldProblemTests(SimpleTestCase):
    def test_values_postgresql_would_reject_are_named_without_showing_them(self):
        from .models import Client, SecurityEvidence
        name = Client._meta.get_field('name')
        self.assertEqual(field_problem(name, 'x' * (name.max_length + 1)), 'texto más largo que max_length')
        self.assertEqual(field_problem(name, 'a\x00b'), 'carácter NUL en texto')
        self.assertEqual(field_problem(SecurityEvidence._meta.get_field('source_ip'), 'foreign.test'), 'IP no válida')
        self.assertEqual(field_problem(SecurityEvidence._meta.get_field('level'), 40000), 'entero fuera de rango')
        self.assertEqual(field_problem(SecurityEvidence._meta.get_field('interpretation'), {'a': 'x\x00'}),
                         'carácter NUL en JSON')
        self.assertIsNone(field_problem(name, 'Empresa ñ'))


class PreflightTests(SimpleTestCase):
    databases = {'default'}

    def test_check_reports_by_table_and_field_and_never_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'origen.sqlite3'
            build_source(path)
            with sqlite3.connect(path) as db:
                db.execute("UPDATE core_client SET name=? WHERE code='empresa-b'", ('x' * 300,))
                db.execute("UPDATE core_securityevidence SET source_ip='no-es-ip' WHERE level=7")
            before = path.read_bytes()
            issues = preflight(open_source(path))
            self.assertEqual(issues[('core_client', 'name', 'texto más largo que max_length')], 1)
            self.assertEqual(issues[('core_securityevidence', 'source_ip', 'IP no válida')], 25)
            self.assertEqual(path.read_bytes(), before)
            with self.assertRaises(CommandError):
                call_command('transfer_database', source=str(path), check=True, stdout=open(os.devnull, 'w'))


class TransferToPostgresqlTests(TransactionTestCase):
    def setUp(self):
        if connection.vendor != 'postgresql':
            self.skipTest('Requiere PostgreSQL como base default (CI o docs/testing.md).')
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.source = Path(self.directory.name) / 'origen.sqlite3'
        build_source(self.source)

    def test_transfer_preserves_ids_relations_secrets_timestamps_and_sequences(self):
        from .models import AuditEvent, Client, Incident, MfaProfile, SecureLogChannel, SecurityEvidence, StaffAccess
        from .security import audit_integrity, decrypt
        report = transfer(self.source)
        self.assertIn(('core_securityevidence', 25), report)
        operator = get_user_model().objects.get(username='operador')
        self.assertTrue(operator.check_password('Prueba-segura-2026'))
        self.assertEqual(decrypt(MfaProfile.objects.get(user=operator).encrypted_secret), 'JBSWY3DPEHPK3PXP')
        self.assertEqual(sorted(StaffAccess.objects.get(user=operator).clients.values_list('code', flat=True)),
                         ['empresa-a', 'empresa-b'])
        self.assertTrue(operator.groups.filter(name='SOC Operador').exists())
        company = Client._base_manager.get(code='empresa-a')
        self.assertEqual(company.created_at, OLD)
        self.assertEqual(Incident._base_manager.get().updated_at, OLD)
        self.assertEqual(set(SecurityEvidence._base_manager.values_list('client_scope_id', flat=True)), {company.pk})
        self.assertTrue(SecureLogChannel._base_manager.get().token_hash)
        from .models import ReportVersion
        self.assertEqual(bytes(ReportVersion._base_manager.get().pdf), b'%PDF-1.4\x00\xff binario')
        self.assertTrue(audit_integrity())
        self.assertEqual(AuditEvent.objects.count(), 3)
        # Las secuencias continúan tras el último ID copiado.
        new = Client._base_manager.create(name='Nueva', code='nueva')
        self.assertGreater(new.pk, Client._base_manager.exclude(pk=new.pk).order_by('-pk').first().pk)

    def test_any_difference_rolls_back_everything(self):
        from .models import Client
        real = database_transfer.fingerprint

        def tampered(model, alias):
            count, digest = real(model, alias)
            return (count, digest[::-1]) if alias == 'default' and model is Client else (count, digest)

        with mock.patch.object(database_transfer, 'fingerprint', side_effect=tampered):
            with self.assertRaises(TransferError):
                transfer(self.source)
        self.assertFalse(Client._base_manager.exists())
        self.assertFalse(get_user_model().objects.exists())

    def test_refuses_target_with_data_or_different_migrations(self):
        from .models import Client
        Client._base_manager.create(name='Ya existe', code='ya-existe')
        with self.assertRaises(TransferError):
            transfer(self.source)
        Client._base_manager.all().delete()
        with sqlite3.connect(self.source) as db:
            db.execute("DELETE FROM django_migrations WHERE name='0046_acknowledged_wazuh_delivery'")
        with self.assertRaises(TransferError):
            transfer(self.source)

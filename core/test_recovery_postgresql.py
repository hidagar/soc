import hashlib
import io
import json
import tarfile
import tempfile
from pathlib import Path
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.db import connection
from django.test import TransactionTestCase

from . import recovery


def archive_with(directory, members):
    path = Path(directory) / 'archive.tar.gz'
    manifest = {'files': {name: hashlib.sha256(body).hexdigest() for name, body in members.items()}}
    with tarfile.open(path, 'w:gz') as archive:
        for name, body in [*members.items(), ('manifest.json', json.dumps(manifest).encode())]:
            entry = tarfile.TarInfo(name)
            entry.size = len(body)
            archive.addfile(entry, io.BytesIO(body))
    return path


class PostgresqlBackupTests(TransactionTestCase):
    def setUp(self):
        if connection.vendor != 'postgresql':
            self.skipTest('Requiere PostgreSQL como base default (CI o docs/testing.md).')
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def applied(self):
        with connection.cursor() as cursor:
            cursor.execute('SELECT count(*) FROM django_migrations')
            return cursor.fetchone()[0]

    def test_encrypted_archive_carries_a_readable_pg_dump_with_every_migration(self):
        files = recovery.dump_database(self.root)
        self.assertEqual(list(files), ['portal.pgdump'])
        key = self.root / 'key'
        key.write_bytes(Fernet.generate_key())
        archive = archive_with(self.root, {'portal.pgdump': files['portal.pgdump'].read_bytes(),
                                           'config/soc-portal/portal.env': b'private'})
        target = self.root / 'verify'
        target.mkdir()
        with patch.object(recovery, 'KEY', key):
            details = recovery.validate_tar(archive, target)
        self.assertEqual(details['database_integrity'], 'pg_dump_ok')
        self.assertEqual(details['database_engine'], 'postgresql')
        self.assertEqual(details['migrations'], self.applied())
        self.assertGreater(details['database_tables'], 50)

    def test_truncated_dump_is_rejected(self):
        dump = recovery.dump_database(self.root)['portal.pgdump']
        truncated = self.root / 'truncated.pgdump'
        truncated.write_bytes(dump.read_bytes()[:len(dump.read_bytes()) // 3])
        with self.assertRaises(Exception):
            recovery.verify_database('portal.pgdump', truncated)

    def test_archive_without_exactly_one_database_is_rejected(self):
        dump = recovery.dump_database(self.root)['portal.pgdump'].read_bytes()
        for members in ({'config/soc-portal/portal.env': b'private'},
                        {'portal.pgdump': dump, 'portal.sqlite3': b'x', 'config/soc-portal/portal.env': b'private'}):
            target = tempfile.mkdtemp(dir=self.root)
            with self.assertRaises(ValueError):
                recovery.validate_tar(archive_with(target, members), target)

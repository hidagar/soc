import os
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import mock

from django.conf import settings
from django.test import SimpleTestCase, TestCase

from .models import BackupRun
from .wazuh_tenant_objects import load


class DatabaseEngineSettingsTests(SimpleTestCase):
    def settings_for(self, **env):
        code = ('import json,socportal.settings as s;'
                'd=s.DATABASES["default"];print(json.dumps({"engine":d["ENGINE"],"name":str(d["NAME"]),'
                '"options":d.get("OPTIONS",{})}))')
        clean = {k: v for k, v in os.environ.items() if not k.startswith('SOC_PORTAL_DB_')}
        return subprocess.run([sys.executable, '-c', code], cwd=settings.BASE_DIR, capture_output=True, text=True,
                              env={**clean, 'SOC_PORTAL_DEBUG': '1', **env})

    def test_sqlite_remains_the_default(self):
        result = self.settings_for()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('django.db.backends.sqlite3', result.stdout)
        self.assertIn('portal.sqlite3', result.stdout)

    def test_postgresql_is_configured_from_environment_without_defaults_for_secrets(self):
        result = self.settings_for(SOC_PORTAL_DB_ENGINE='postgresql', SOC_PORTAL_DB_NAME='soc_staging',
                                   SOC_PORTAL_DB_SSLMODE='require')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('django.db.backends.postgresql', result.stdout)
        self.assertIn('soc_staging', result.stdout)
        self.assertIn('"sslmode": "require"', result.stdout)

    def test_unknown_engine_is_rejected(self):
        result = self.settings_for(SOC_PORTAL_DB_ENGINE='mysql')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('SOC_PORTAL_DB_ENGINE', result.stderr)


class SqliteOnlyComponentsTests(TestCase):
    def test_portal_backup_refuses_postgresql_instead_of_copying_a_stale_file(self):
        from . import recovery
        run = BackupRun.objects.create(status='queued')
        with mock.patch.object(recovery.connection, 'vendor', 'postgresql'), \
                mock.patch.object(recovery, 'native_snapshot') as snapshot, \
                mock.patch.object(recovery, 'ROOT') as root:
            recovery.make_backup(run)
        snapshot.assert_not_called()
        root.mkdir.assert_not_called()
        run.refresh_from_db()
        self.assertEqual(run.status, 'failed')
        self.assertIn('PostgreSQL', run.error)

    def test_dashboard_sync_reads_through_the_portal_unless_it_is_the_installation_sqlite(self):
        sync = load('sync_wazuh_dashboards')
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / 'portal.env'
            self.assertEqual(sync.portal_database_engine(env), 'sqlite')
            env.write_text('SOC_PORTAL_SECRET_KEY=x\nSOC_PORTAL_DB_ENGINE=postgresql\n', encoding='utf-8')
            self.assertEqual(sync.portal_database_engine(env), 'postgresql')
        rows = ([('a', 'A')], [('a', '198.51.100.7')])
        for engine, path, direct in (('sqlite', '', True), ('postgresql', '', False), ('sqlite', '/otra.sqlite3', False)):
            values = {'SOC_PORTAL_DB_ENGINE': engine, 'SOC_PORTAL_SQLITE_PATH': path}
            with mock.patch.object(sync, 'portal_env_value', side_effect=lambda name, default, *a: values[name] or default), \
                    mock.patch.object(sync, 'sqlite_rows', return_value=rows) as sqlite_rows, \
                    mock.patch.object(sync, 'portal_rows', return_value=rows) as portal_rows:
                clients = sync.clients_and_sources()
            self.assertEqual(clients, [{'code': 'a', 'name': 'A', 'sources': {'198.51.100.7'}}])
            self.assertEqual((sqlite_rows.called, portal_rows.called), (direct, not direct))

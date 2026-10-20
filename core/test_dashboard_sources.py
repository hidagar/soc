import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from django.conf import settings
from django.test import SimpleTestCase

from .test_database_transfer import POPULATE, build_source
from .wazuh_tenant_objects import load

VARIANTS = POPULATE.replace("print('ok')", """
from core.models import Client, Site, Device, ExportConfiguration
b = Client.objects.get(code='empresa-b')
ExportConfiguration.objects.filter(device=device).update(receiver_ready=True)
site_b = Site.objects.create(client=b, name='Central', code='central')
for name, ip, ready, active in (('Listo', '198.51.100.8', True, True), ('Sin receptor', '198.51.100.9', False, True),
                                ('Inactivo', '198.51.100.10', True, False), ('Sin origen', None, True, True)):
    d = Device.objects.create(site=site_b, name=name, vendor='unifi', active=active)
    ExportConfiguration.objects.create(device=d, source_ip=ip, receiver_ready=ready)
Client.objects.create(name='Empresa inactiva', code='inactiva', active=False)
print('ok')""")


class DashboardSourcesTests(SimpleTestCase):
    def test_portal_command_selects_exactly_what_the_direct_sqlite_reader_selects(self):
        sync = load('sync_wazuh_dashboards')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'portal.sqlite3'
            build_source(path, VARIANTS)
            direct = sync.group_sources(*sync.sqlite_rows(path))
            env = {k: v for k, v in os.environ.items() if not k.startswith('SOC_PORTAL_DB_')}
            env.update(SOC_PORTAL_DEBUG='1', SOC_PORTAL_SQLITE_PATH=str(path))
            result = subprocess.run([sys.executable, 'manage.py', 'dashboard_sources'], cwd=settings.BASE_DIR,
                                    env=env, capture_output=True, text=True, check=True)
            data = json.loads(result.stdout)
            through_portal = sync.group_sources([tuple(r) for r in data['clients']], [tuple(r) for r in data['sources']])
        self.assertEqual(through_portal, direct)
        self.assertEqual({c['code']: c['sources'] for c in direct},
                         {'empresa-a': {'198.51.100.7'}, 'empresa-b': {'198.51.100.8'}})

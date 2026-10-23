"""deploy/envfile.py lee portal.env como systemd: sin expansión de $ ni ejecución de comandos."""
import subprocess
import sys
import tempfile
from pathlib import Path

from django.test import SimpleTestCase

from .wazuh_tenant_objects import load

SAMPLE = r"""# comentario
; otro comentario
SOC_PORTAL_DB_ENGINE="postgresql"
SOC_PORTAL_DB_PASSWORD=Xy$9k`id`$(id) con espacios
SOC_PORTAL_SQLITE_PATH='/srv/soc portal/data.sqlite3'
SOC_PORTAL_MAIL_KEY = nueva,anterior
SOC_PORTAL_SECRET_KEY="con \"comillas\" y \$dolar"
export MALO=1
1INVALIDA=x
SOC_PORTAL_DB_ENGINE=sqlite
SOC_PORTAL_MULTILINEA="linea1
linea2"
"""


class EnvFileTests(SimpleTestCase):
    def setUp(self):
        self.envfile = load('envfile')

    def test_values_are_literal_like_systemd(self):
        values = self.envfile.parse(SAMPLE)
        self.assertEqual(values['SOC_PORTAL_DB_PASSWORD'], 'Xy$9k`id`$(id) con espacios')
        self.assertEqual(values['SOC_PORTAL_SQLITE_PATH'], '/srv/soc portal/data.sqlite3')
        self.assertEqual(values['SOC_PORTAL_MAIL_KEY'], 'nueva,anterior')
        self.assertEqual(values['SOC_PORTAL_SECRET_KEY'], 'con "comillas" y $dolar')
        self.assertEqual(values['SOC_PORTAL_DB_ENGINE'], 'sqlite', 'la última asignación gana')
        self.assertEqual(values['SOC_PORTAL_MULTILINEA'], 'linea1\nlinea2')
        self.assertNotIn('MALO', values)
        self.assertNotIn('export MALO', values)
        self.assertNotIn('1INVALIDA', values)

    def test_shell_output_is_safe_to_eval_and_fingerprints_hide_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'portal.env'
            path.write_text(SAMPLE, encoding='utf-8')
            script = Path(__file__).resolve().parent.parent / 'deploy' / 'envfile.py'
            exports = subprocess.run([sys.executable, '-I', str(script), '--shell', str(path)], capture_output=True,
                                     text=True, check=True).stdout
            shown = subprocess.run(['bash', '-c', 'set -eu; eval "$1"; printf %s "$SOC_PORTAL_DB_PASSWORD"', '_', exports],
                                   capture_output=True, text=True, check=True).stdout
            self.assertEqual(shown, 'Xy$9k`id`$(id) con espacios')
            prints = subprocess.run([sys.executable, '-I', str(script), '--fingerprints', str(path)],
                                    capture_output=True, text=True, check=True).stdout
            self.assertEqual([line.split()[0] for line in prints.splitlines()],
                             ['SOC_PORTAL_SECRET_KEY', 'SOC_PORTAL_MAIL_KEY', 'SOC_PORTAL_MAIL_KEY'])
            self.assertNotIn('nueva', prints)
            self.assertNotIn('comillas', prints)

"""Registros sin los secretos que viajan en la URL: Django, gunicorn, Nginx y el script que lo aplica."""
import logging
import os
import runpy
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path

from django.test import SimpleTestCase

from socportal.log_redaction import HIDDEN, RedactingFormatter, redact

ROOT = Path(__file__).resolve().parent.parent
TOKEN = 'Zx9-' + 'a' * 39  # como secrets.token_urlsafe(32)
SIGNED = 'eyJyZXBvcnQiOjF9:1tXYZa:' + 'b' * 43  # como signing.dumps
SECRET_PATHS = {
    f'/reports/{SIGNED}/': '/reports/[oculto]/',
    f'/reports/{SIGNED}/pdf/': '/reports/[oculto]/pdf/',
    f'/feeds/bloqueo/3/{TOKEN}/': '/feeds/bloqueo/3/[oculto]/',
    f'/feeds/bloqueo/3/{TOKEN}/salida/': '/feeds/bloqueo/3/[oculto]/salida/',
    f'/activate/12/{TOKEN}/': '/activate/12/[oculto]/',
}
PLAIN_PATHS = ['/reports/health/', '/reports/delivery-events/', '/activate/12/set-password/',
               '/ingest/2b1c3e9a-0000-4000-8000-000000000000/', '/clients/4/?q=1']


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class RedactionTests(SimpleTestCase):
    def test_secret_paths_are_hidden_and_the_rest_kept(self):
        for path, expected in SECRET_PATHS.items():
            self.assertEqual(redact(path), expected)
            self.assertEqual(redact(f'GET https://soc.example.test{path} 404'), f'GET https://soc.example.test{expected} 404')
        for path in PLAIN_PATHS:
            self.assertEqual(redact(path), path)

    def test_django_error_logs_hide_the_token_also_in_the_traceback(self):
        handler = logging.getLogger('django.request').handlers[0]
        self.assertIsInstance(handler.formatter, RedactingFormatter)
        try:
            raise ValueError(f'fallo en /feeds/bloqueo/3/{TOKEN}/')
        except ValueError:
            record = logging.LogRecord('django.request', logging.ERROR, __file__, 1, 'Internal Server Error: %s',
                                       (f'/reports/{SIGNED}/',), sys.exc_info())
        text = handler.formatter.format(record)
        self.assertNotIn(TOKEN, text)
        self.assertNotIn(SIGNED, text)
        self.assertIn(HIDDEN, text)
        self.assertIn('Traceback', text)

    def test_gunicorn_keeps_no_access_log(self):
        config = runpy.run_path(str(ROOT / 'deploy' / 'gunicorn.conf.py'))
        self.assertIsNone(config['accesslog'])
        self.assertEqual(config['bind'], '127.0.0.1:8000')
        # Hilos: una acción lenta no deja sin atender la ingesta ni las descargas de los firewalls.
        self.assertEqual(config['worker_class'], 'gthread')
        self.assertGreaterEqual(config['workers'] * config['threads'], 8)
        unit = (ROOT / 'deploy' / 'install.sh').read_text()
        self.assertIn('gunicorn -c /srv/soc-portal/deploy/gunicorn.conf.py', unit)
        self.assertNotIn('--access-logfile', unit)


@unittest.skipUnless(shutil.which('nginx') or Path('/usr/sbin/nginx').exists(), 'Nginx no está instalado.')
class NginxRedactionTests(SimpleTestCase):
    NGINX = shutil.which('nginx') or '/usr/sbin/nginx'

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir, True)

    def nginx_conf(self, port, include, server_extra=''):
        d = self.dir
        conf = d / 'nginx.conf'
        conf.write_text(f'''pid {d}/nginx.pid;
error_log {d}/error.log;
events {{}}
http {{
    client_body_temp_path {d}/b; proxy_temp_path {d}/p; fastcgi_temp_path {d}/f; uwsgi_temp_path {d}/u; scgi_temp_path {d}/s;
    access_log off;
    include {include};
    server {{
        listen 127.0.0.1:{port};
        access_log {d}/access.log soc_redacted;
        {server_extra}
        location / {{ return 200 "ok"; }}
    }}
}}
''')
        return conf

    def test_access_log_hides_tokens_in_path_and_referer(self):
        port = free_port()
        conf = self.nginx_conf(port, ROOT / 'deploy' / 'nginx' / 'soc-log-redaction.conf')
        base = [self.NGINX, '-e', str(self.dir / 'error.log'), '-c', str(conf), '-p', str(self.dir)]
        subprocess.run(base + ['-t'], check=True, capture_output=True)
        subprocess.run(base, check=True, capture_output=True)
        try:
            referer = f'https://soc.example.test/reports/{SIGNED}/'
            for path in [*SECRET_PATHS, *PLAIN_PATHS]:
                urllib.request.urlopen(urllib.request.Request(f'http://127.0.0.1:{port}{path}', headers={'Referer': referer}),
                                       timeout=5).read()
        finally:
            subprocess.run(base + ['-s', 'stop'], capture_output=True)
        for _ in range(50):
            log = (self.dir / 'access.log').read_text() if (self.dir / 'access.log').exists() else ''
            if log.count('\n') >= len(SECRET_PATHS) + len(PLAIN_PATHS):
                break
            time.sleep(0.1)
        self.assertNotIn(TOKEN, log)
        self.assertNotIn(SIGNED, log)
        for expected in [*SECRET_PATHS.values(), *PLAIN_PATHS]:
            self.assertIn(f' {expected} HTTP/1.1', log)
        self.assertIn('"https://soc.example.test/reports/[oculto]/"', log)


@unittest.skipUnless(shutil.which('nginx') or Path('/usr/sbin/nginx').exists(), 'Nginx no está instalado.')
class ConfigureLogsScriptTests(SimpleTestCase):
    """deploy/configurar_registros.sh en un entorno simulado: Nginx real para `nginx -t`; systemctl y curl simulados."""
    NGINX = shutil.which('nginx') or '/usr/sbin/nginx'

    def setUp(self):
        d = self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        for sub in ('nginx/conf.d', 'nginx/sites-available', 'units', 'bin', 'app/deploy/nginx', 'run'):
            (d / sub).mkdir(parents=True)
        shutil.copy(ROOT / 'deploy' / 'gunicorn.conf.py', d / 'app/deploy')
        shutil.copy(ROOT / 'deploy' / 'nginx' / 'soc-log-redaction.conf', d / 'app/deploy/nginx')
        self.site = d / 'nginx/sites-available/soc-portal'
        self.site.write_text('server {\n    listen 127.0.0.1:%d;\n    server_name 127.0.0.1;\n    location / { return 200; }\n}\n'
                             % free_port())
        (d / 'nginx/nginx.conf').write_text(f'''pid {d}/run/nginx.pid;
error_log {d}/run/error.log;
events {{}}
http {{
    client_body_temp_path {d}/run/b; proxy_temp_path {d}/run/p; fastcgi_temp_path {d}/run/f; uwsgi_temp_path {d}/run/u; scgi_temp_path {d}/run/s;
    include {d}/nginx/conf.d/*.conf;
    include {self.site};
}}
''')
        self.stub('nginx', f'[[ -f {d}/fail-nginx ]] && exit 1\nexec {self.NGINX} -e {d}/run/error.log -t -q -c {d}/nginx/nginx.conf -p {d}/run')
        self.stub('systemctl', f'echo "$*" >> {d}/calls.log')
        self.stub('curl', 'echo 200')

    def stub(self, name, body):
        path = self.dir / 'bin' / name
        path.write_text('#!/bin/bash\n' + body + '\n')
        path.chmod(0o755)

    def run_script(self, *args):
        env = {**os.environ, 'PATH': f'{self.dir}/bin:{os.environ["PATH"]}', 'SOC_APP': str(self.dir / 'app'),
               'SOC_NGINX_DIR': str(self.dir / 'nginx'), 'SOC_SYSTEMD_DIR': str(self.dir / 'units')}
        return subprocess.run(['bash', str(ROOT / 'deploy' / 'configurar_registros.sh'), *args, '--yes'],
                              env=env, capture_output=True, text=True, timeout=120)

    def calls(self):
        path = self.dir / 'calls.log'
        return path.read_text().split('\n') if path.exists() else []

    def test_applies_once_and_can_be_removed(self):
        self.assertEqual(self.run_script().returncode, 0)
        self.assertEqual(self.run_script().returncode, 0)  # repetir no duplica
        site = self.site.read_text()
        self.assertEqual(site.count('soc_redacted;'), 1)
        self.assertLess(site.index('server_name'), site.index('access_log /var/log/nginx/access.log soc_redacted;'))
        dropin = (self.dir / 'units/soc-portal.service.d/gunicorn.conf').read_text()
        self.assertIn('ExecStart=\n', dropin)
        self.assertIn(f'gunicorn -c {self.dir}/app/deploy/gunicorn.conf.py socportal.wsgi:application', dropin)
        self.assertIn('restart soc-portal', self.calls())
        self.assertEqual(self.run_script('--quitar').returncode, 0)
        self.assertNotIn('soc_redacted', self.site.read_text())
        self.assertFalse((self.dir / 'nginx/conf.d/soc-log-redaction.conf').exists())
        self.assertFalse((self.dir / 'units/soc-portal.service.d').exists())

    def test_rejected_nginx_configuration_is_restored_without_touching_the_portal(self):
        (self.dir / 'fail-nginx').touch()
        original = self.site.read_text()
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.site.read_text(), original)
        self.assertFalse((self.dir / 'nginx/conf.d/soc-log-redaction.conf').exists())
        self.assertFalse((self.dir / 'units/soc-portal.service.d').exists())
        self.assertNotIn('restart soc-portal', self.calls())

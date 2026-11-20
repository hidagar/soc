"""deploy/configurar_wazuh_nginx.sh: las rutas de Wazuh pasan a un archivo común incluido también en el bloque por IP.

Nginx real para `nginx -t` (la prueba se salta sin Nginx); systemctl simulado. El secreto es de prueba.
"""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from django.test import SimpleTestCase

ROOT = Path(__file__).resolve().parent.parent
SECRET = 'secreto-de-prueba-0123456789'
WAZUH = '''    location = /_soc_wazuh_auth {
        internal;
        proxy_pass http://127.0.0.1:8000/security/wazuh/check/;
        proxy_set_header X-SOC-Wazuh-Key "%s";
        proxy_set_header Cookie $http_cookie;
    }
    location = /wazuh { absolute_redirect off; return 302 /security/wazuh/enter/; }
    location /wazuh/ {
        auth_request /_soc_wazuh_auth;
        auth_request_set $soc_wazuh_user $upstream_http_x_soc_wazuh_user;
        error_page 401 = @soc_wazuh_login;
        proxy_pass https://127.0.0.1:5602;
        proxy_ssl_verify on;
        proxy_ssl_trusted_certificate /etc/wazuh-dashboard/certs/root-ca.pem;
        proxy_set_header X-SOC-Wazuh-User $soc_wazuh_user;
    }
    location @soc_wazuh_login {
        absolute_redirect off;
        return 302 /security/wazuh/enter/;
    }
''' % SECRET


@unittest.skipUnless(shutil.which('nginx') and shutil.which('openssl'), 'Nginx u OpenSSL no están instalados.')
class WazuhNginxScriptTests(SimpleTestCase):
    def setUp(self):
        d = self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        for sub in ('nginx/conf.d', 'nginx/sites-available', 'nginx/sites-enabled', 'bin', 'run', 'backups'):
            (d / sub).mkdir(parents=True)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=prueba',
                        '-keyout', str(d / 'run/ca.key'), '-out', str(d / 'run/ca.pem')], check=True, capture_output=True)
        self.public = d / 'nginx/sites-available/soc-publico'
        self.public.write_text('server {\n    listen 127.0.0.1:18443;\n    server_name soc.example;\n\n    location = / { return 200; }\n'
                               + WAZUH + '\n    location / {\n        return 200;\n    }\n}\n')
        self.ip = d / 'nginx/sites-available/soc-portal'
        self.ip.write_text('server {\n    listen 127.0.0.1:18443;\n    server_name 192.0.2.10;\n\n'
                           '    location /static/ {\n        return 200;\n    }\n    location / {\n        return 200;\n    }\n}\n')
        for site in (self.public, self.ip):
            (d / 'nginx/sites-enabled' / site.name).symlink_to(site)
        (d / 'nginx/nginx.conf').write_text(f'''pid {d}/run/nginx.pid;
error_log {d}/run/error.log;
events {{}}
http {{
    client_body_temp_path {d}/run/b; proxy_temp_path {d}/run/p; fastcgi_temp_path {d}/run/f; uwsgi_temp_path {d}/run/u; scgi_temp_path {d}/run/s;
    access_log {d}/run/access.log;
    include {d}/run/enabled/*;
}}
''')
        # El certificado del Wazuh Dashboard no existe aquí: `nginx -t` se ejecuta sobre copias con el de la prueba.
        cert = f's#/etc/wazuh-dashboard/certs/root-ca.pem#{d}/run/ca.pem#g'
        snippet = f'{d}/nginx/snippets/soc-wazuh.conf'
        self.stub('nginx', f'[[ -f {d}/fail-nginx ]] && exit 1\nrm -rf {d}/run/enabled; mkdir -p {d}/run/enabled\n'
                           f'[[ -f {snippet} ]] && sed "{cert}" {snippet} > {d}/run/soc-wazuh.conf\n'
                           f'for f in {d}/nginx/sites-enabled/*; do sed -e "{cert}" -e "s#{snippet}#{d}/run/soc-wazuh.conf#g" '
                           f'"$f" > {d}/run/enabled/$(basename "$f"); done\n'
                           f'exec {shutil.which("nginx")} -e {d}/run/error.log -t -q -c {d}/nginx/nginx.conf -p {d}/run')
        self.stub('systemctl', f'echo "$*" >> {d}/calls.log')

    def stub(self, name, body):
        path = self.dir / 'bin' / name
        path.write_text('#!/bin/bash\n' + body + '\n')
        path.chmod(0o755)

    def run_script(self, *args):
        env = {**os.environ, 'PATH': f'{self.dir}/bin:{os.environ["PATH"]}', 'SOC_NGINX_DIR': str(self.dir / 'nginx'),
               'SOC_BACKUP_DIR': str(self.dir / 'backups')}
        return subprocess.run(['bash', str(ROOT / 'deploy' / 'configurar_wazuh_nginx.sh'), *args], env=env,
                              capture_output=True, text=True, timeout=120)

    def snippet(self):
        return self.dir / 'nginx/snippets/soc-wazuh.conf'

    def test_moves_the_routes_to_a_shared_file_included_by_both_blocks(self):
        result = self.run_script('--yes')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn(SECRET, result.stdout + result.stderr)
        snippet = self.snippet().read_text()
        self.assertIn(SECRET, snippet)
        self.assertIn('location /wazuh/ {', snippet)
        self.assertEqual(oct(self.snippet().stat().st_mode & 0o777), '0o600')
        include = f'include {self.snippet()};'
        public, ip = self.public.read_text(), self.ip.read_text()
        self.assertNotIn(SECRET, public)
        self.assertNotIn('location /wazuh/', public)
        self.assertEqual((public.count(include), ip.count(include)), (1, 1))
        self.assertLess(ip.index(include), ip.index('location /static/'))
        self.assertIn('reload nginx', (self.dir / 'calls.log').read_text())
        # Repetir no duplica nada.
        again = self.run_script('--yes')
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertIn('Ya está aplicado', again.stdout)
        self.assertEqual(self.ip.read_text().count(include), 1)
        shown = self.run_script('--ver')
        self.assertIn('incluye las rutas de Wazuh', shown.stdout)
        self.assertNotIn(SECRET, shown.stdout)

    def test_rejected_configuration_is_restored_without_reloading(self):
        (self.dir / 'fail-nginx').touch()
        public, ip = self.public.read_text(), self.ip.read_text()
        result = self.run_script('--yes')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.public.read_text(), self.ip.read_text()), (public, ip))
        self.assertFalse(self.snippet().exists())
        self.assertFalse((self.dir / 'calls.log').exists())

    def test_without_a_single_source_it_stops_without_changes(self):
        self.public.write_text(self.public.read_text().replace(WAZUH, ''))
        result = self.run_script('--yes')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("único sitio con 'location /wazuh/'", result.stderr)
        self.assertFalse(self.snippet().exists())

    def test_the_example_in_deploy_is_valid_nginx(self):
        d = self.dir
        example = (ROOT / 'deploy/nginx/soc-wazuh.conf.example').read_text()
        self.assertIn('__SOC_WAZUH_PROXY_KEY__', example)
        (d / 'run/ejemplo.conf').write_text(example.replace('/etc/wazuh-dashboard/certs/root-ca.pem', f'{d}/run/ca.pem'))
        (d / 'run/enabled').mkdir()
        (d / 'run/enabled/sitio').write_text(f'server {{\n    listen 127.0.0.1:18444;\n    include {d}/run/ejemplo.conf;\n}}\n')
        result = subprocess.run([shutil.which('nginx'), '-e', f'{d}/run/error.log', '-t', '-q', '-c', f'{d}/nginx/nginx.conf',
                                 '-p', f'{d}/run'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

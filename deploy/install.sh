#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run as root" >&2
  exit 1
fi

upload_dir="${1:-/home/deploy/soc-portal-upload}"
if [[ ! -f "$upload_dir/manage.py" || ! -f "$upload_dir/requirements.txt" ]]; then
  echo "Portal source not found: $upload_dir" >&2
  exit 1
fi

# Valores de la instalación; por defecto, los de la VM original. Ver docs/deployment.md.
PORTAL_ADDRESS="${SOC_INSTALL_ADDRESS:-172.20.10.20}"
PORTAL_PORT="${SOC_INSTALL_PORT:-8443}"
PYTHON_PACKAGE="${SOC_INSTALL_PYTHON_PACKAGE:-python3.14-venv}"
python3 -c 'import ipaddress,sys; ipaddress.ip_address(sys.argv[1])' "$PORTAL_ADDRESS" 2>/dev/null \
  || { echo "SOC_INSTALL_ADDRESS must be an IP address" >&2; exit 1; }
[[ "$PORTAL_PORT" =~ ^[0-9]+$ ]] && (( PORTAL_PORT >= 1 && PORTAL_PORT <= 65535 )) \
  || { echo "SOC_INSTALL_PORT must be a TCP port" >&2; exit 1; }

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y "$PYTHON_PACKAGE" nginx

if ! id socportal >/dev/null 2>&1; then
  useradd --system --home /nonexistent --shell /usr/sbin/nologin socportal
fi

install -d -m 0755 /srv/soc-portal /srv/soc-portal/staticfiles
install -d -m 0700 /srv/soc-portal/data
chown socportal:socportal /srv/soc-portal/data /srv/soc-portal/staticfiles
chmod 0700 /srv/soc-portal/data
code_items=(manage.py requirements.txt core socportal templates static deploy)
if git -c safe.directory="$upload_dir" -C "$upload_dir" rev-parse --git-dir >/dev/null 2>&1; then
  # Checkout Git: instalar exactamente el commit y registrarlo, como deploy/update.sh.
  [[ -z "$(git -c safe.directory="$upload_dir" -C "$upload_dir" status --porcelain --untracked-files=no)" ]] \
    || { echo "The Git checkout has uncommitted changes" >&2; exit 1; }
  git -c safe.directory="$upload_dir" -C "$upload_dir" archive HEAD "${code_items[@]}" | tar -x -C /srv/soc-portal
  git -c safe.directory="$upload_dir" -C "$upload_dir" rev-parse HEAD > /srv/soc-portal/.deployed-commit
else
  cp -a "${code_items[@]/#/$upload_dir/}" /srv/soc-portal/
fi
chown -R root:root /srv/soc-portal/manage.py /srv/soc-portal/requirements.txt /srv/soc-portal/core /srv/soc-portal/socportal /srv/soc-portal/templates /srv/soc-portal/static /srv/soc-portal/deploy
find /srv/soc-portal -type d -not -path '/srv/soc-portal/data*' -not -path '/srv/soc-portal/staticfiles*' -exec chmod 0755 {} +

if [[ ! -x /opt/soc-portal-venv/bin/python ]]; then
  python3 -m venv /opt/soc-portal-venv
fi
/opt/soc-portal-venv/bin/python -m pip install --disable-pip-version-check --requirement /srv/soc-portal/requirements.txt

install -d -m 0750 -o root -g socportal /etc/soc-portal
if [[ ! -f /etc/soc-portal/portal.env ]]; then
  portal_secret="$(openssl rand -hex 48)"
  cat > /etc/soc-portal/portal.env <<EOF
SOC_PORTAL_SECRET_KEY=$portal_secret
SOC_PORTAL_ALLOWED_HOSTS=$PORTAL_ADDRESS
SOC_PORTAL_CSRF_ORIGINS=https://$PORTAL_ADDRESS:$PORTAL_PORT
EOF
  chown root:socportal /etc/soc-portal/portal.env
  chmod 0640 /etc/soc-portal/portal.env
fi

if ! grep -q '^SOC_PORTAL_UNIFI_KEY=' /etc/soc-portal/portal.env; then
  printf 'SOC_PORTAL_UNIFI_KEY=%s\n' "$(openssl rand -base64 32 | tr -d '\n')" >> /etc/soc-portal/portal.env
fi
if ! grep -q '^SOC_PORTAL_OPNSENSE_KEY=' /etc/soc-portal/portal.env; then
  printf 'SOC_PORTAL_OPNSENSE_KEY=%s\n' "$(openssl rand -base64 32 | tr -d '\n')" >> /etc/soc-portal/portal.env
fi
if ! grep -q '^SOC_PORTAL_MAIL_KEY=' /etc/soc-portal/portal.env; then
  printf 'SOC_PORTAL_MAIL_KEY=%s\n' "$(openssl rand -base64 32 | tr -d '\n')" >> /etc/soc-portal/portal.env
fi
/opt/soc-portal-venv/bin/python /srv/soc-portal/deploy/ensure_ssh_key.py
chown root:socportal /etc/soc-portal/portal.env
chmod 0640 /etc/soc-portal/portal.env

if [[ ! -f /etc/soc-portal/tls.key ]]; then
  openssl req -x509 -newkey rsa:3072 -sha256 -days 365 -nodes \
    -keyout /etc/soc-portal/tls.key -out /etc/soc-portal/tls.crt \
    -subj "/CN=$PORTAL_ADDRESS" -addext "subjectAltName=IP:$PORTAL_ADDRESS" >/dev/null 2>&1
  chmod 0600 /etc/soc-portal/tls.key
  chmod 0644 /etc/soc-portal/tls.crt
fi

cat > /etc/systemd/system/soc-portal.service <<'EOF'
[Unit]
Description=SOC customer operations portal
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=socportal
Group=socportal
WorkingDirectory=/srv/soc-portal
EnvironmentFile=/etc/soc-portal/portal.env
# Opciones de gunicorn en el código (deploy/gunicorn.conf.py): update.sh las actualiza; sin registro de accesos.
ExecStart=/opt/soc-portal-venv/bin/gunicorn -c /srv/soc-portal/deploy/gunicorn.conf.py socportal.wsgi:application
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/srv/soc-portal/data
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
EOF

if [[ -f /var/ossec/etc/ossec.conf ]]; then
  install -m 0644 /srv/soc-portal/deploy/systemd/soc-job@.service /etc/systemd/system/soc-job@.service
  install -m 0644 /srv/soc-portal/deploy/systemd/soc-monitor.service /etc/systemd/system/soc-monitor.service
  install -m 0644 /srv/soc-portal/deploy/systemd/soc-monitor.timer /etc/systemd/system/soc-monitor.timer
  install -m 0644 /srv/soc-portal/deploy/soc-wazuh-sources.service /etc/systemd/system/soc-wazuh-sources.service
  install -m 0644 /srv/soc-portal/deploy/soc-wazuh-sources.timer /etc/systemd/system/soc-wazuh-sources.timer
  install -m 0644 /srv/soc-portal/deploy/soc-wazuh-dashboards.service /etc/systemd/system/soc-wazuh-dashboards.service
  install -m 0644 /srv/soc-portal/deploy/soc-wazuh-dashboards.timer /etc/systemd/system/soc-wazuh-dashboards.timer
  install -m 0644 /srv/soc-portal/deploy/soc-weekly-reports.service /etc/systemd/system/soc-weekly-reports.service
  install -m 0644 /srv/soc-portal/deploy/soc-weekly-reports.timer /etc/systemd/system/soc-weekly-reports.timer
  install -m 0644 /srv/soc-portal/deploy/soc-urgent-alerts.service /etc/systemd/system/soc-urgent-alerts.service
  install -m 0644 /srv/soc-portal/deploy/soc-urgent-alerts.timer /etc/systemd/system/soc-urgent-alerts.timer
fi

# Registro de accesos sin los secretos de URL (enlaces de informes, listas de bloqueo, invitaciones).
install -m 0644 /srv/soc-portal/deploy/nginx/soc-log-redaction.conf /etc/nginx/conf.d/soc-log-redaction.conf
cat > /etc/nginx/sites-available/soc-portal <<'EOF'
server {
    listen __PORTAL_LISTEN__ ssl;
    server_name __PORTAL_ADDRESS__;
    access_log /var/log/nginx/access.log soc_redacted;
    ssl_certificate /etc/soc-portal/tls.crt;
    ssl_certificate_key /etc/soc-portal/tls.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    client_max_body_size 2m;

    location /static/ {
        alias /srv/soc-portal/staticfiles/;
        expires 7d;
        add_header X-Content-Type-Options nosniff always;
    }

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 30s;
    }
}
EOF
listen="$PORTAL_ADDRESS:$PORTAL_PORT"
[[ "$PORTAL_ADDRESS" == *:* ]] && listen="[$PORTAL_ADDRESS]:$PORTAL_PORT"
sed -i "s/__PORTAL_LISTEN__/$listen/; s/__PORTAL_ADDRESS__/$PORTAL_ADDRESS/" /etc/nginx/sites-available/soc-portal
ln -sfn /etc/nginx/sites-available/soc-portal /etc/nginx/sites-enabled/soc-portal
rm -f /etc/nginx/sites-enabled/default

runuser -u socportal -- /bin/sh -c 'set -a; . /etc/soc-portal/portal.env; set +a; /opt/soc-portal-venv/bin/python /srv/soc-portal/manage.py migrate --noinput'
runuser -u socportal -- /bin/sh -c 'set -a; . /etc/soc-portal/portal.env; set +a; /opt/soc-portal-venv/bin/python /srv/soc-portal/manage.py collectstatic --noinput --verbosity 0'

if [[ ! -f /etc/soc-portal/initial-admin-password ]]; then
  openssl rand -base64 24 > /etc/soc-portal/initial-admin-password
fi
chown root:socportal /etc/soc-portal/initial-admin-password
chmod 0640 /etc/soc-portal/initial-admin-password
runuser -u socportal -- /bin/sh -c 'set -a; . /etc/soc-portal/portal.env; set +a; /opt/soc-portal-venv/bin/python /srv/soc-portal/manage.py shell -c "from django.contrib.auth import get_user_model; from pathlib import Path; User=get_user_model(); User.objects.create_superuser(\"ibred\", password=Path(\"/etc/soc-portal/initial-admin-password\").read_text().strip()) if not User.objects.filter(username=\"ibred\").exists() else None"'
chown root:root /etc/soc-portal/initial-admin-password
chmod 0600 /etc/soc-portal/initial-admin-password

nginx -t
systemctl daemon-reload
systemctl enable --now soc-portal nginx
systemctl restart soc-portal nginx
if [[ -f /var/ossec/etc/ossec.conf ]]; then
  systemctl enable --now soc-wazuh-sources.timer
  systemctl enable --now soc-wazuh-dashboards.timer
  systemctl enable --now soc-weekly-reports.timer
  systemctl enable --now soc-urgent-alerts.timer
  systemctl enable --now soc-monitor.timer
fi
echo "Portal ready at https://$PORTAL_ADDRESS:$PORTAL_PORT/"

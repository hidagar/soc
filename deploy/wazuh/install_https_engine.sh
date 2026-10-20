#!/usr/bin/env bash
# Run as root with the protected portal environment already loaded.
set -euo pipefail
[[ $(id -u) == 0 ]]
cd /srv/soc-portal
for unit in soc-wazuh-https.service soc-wazuh-https-db.service; do
  if systemctl is-active --quiet "$unit"; then
    echo "Stop the private HTTPS engine before updating its profile." >&2; exit 1
  fi
done
/opt/soc-portal-venv/bin/python manage.py shell --no-imports -c 'from core.wazuh_delivery import provision_pipeline; provision_pipeline()'
/opt/soc-portal-venv/bin/python deploy/wazuh/prepare_https_engine.py /var/lib/soc-wazuh-https --pipeline soc-https-wazuh-v1
for file in soc-wazuh-https-db.service soc-wazuh-https.service soc-https-delivery.timer; do
  systemd-analyze verify "deploy/systemd/$file"
  install -m 0644 "deploy/systemd/$file" "/etc/systemd/system/$file"
done
systemctl daemon-reload
systemctl enable --now soc-wazuh-https-db.service soc-wazuh-https.service
sleep 2
systemctl is-active --quiet soc-wazuh-https.service soc-wazuh-https-db.service
systemctl enable --now soc-https-delivery.timer

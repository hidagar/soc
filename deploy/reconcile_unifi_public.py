"""One-time pilot reconciliation after the operator changes its SIEM address."""

import os
import sys

sys.path.insert(0, "/srv/soc-portal")
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "socportal.settings")

import django
django.setup()

from core.models import Device, ExportConfiguration
from core.provisioning import provision_export


device = Device.objects.get(pk=1, vendor=Device.Vendor.UNIFI)
config, _ = ExportConfiguration.objects.get_or_create(device=device)
config.destination = os.environ["SOC_PORTAL_PUBLIC_SYSLOG_IP"]
config.save(update_fields=["destination"])
result = provision_export(device)
print("Equipo", device.pk, "destino", result.destination, "estado", result.status,
      "origen", result.source_ip or "sin confirmar", "receptor", result.receiver_ready)
if result.last_error:
    print("Error:", result.last_error)

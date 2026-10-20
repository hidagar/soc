"""One-off verification for the linked pilot; prints no credentials."""

import os
import sys

sys.path.insert(0, "/srv/soc-portal")
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "socportal.settings")

import django
django.setup()

from core.models import Device
from core.provisioning import provision_export


device = Device.objects.get(pk=1)
print("host_id", repr(device.unifi_cloud.remote_host_id))
result = provision_export(device)
print("device", device.pk, "status", result.status, "source", result.source_ip or "unknown")
if result.last_error:
    print("error", result.last_error)

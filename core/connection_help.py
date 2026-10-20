"""Operator guidance using the same destinations as actual provisioning."""

from django.contrib.auth.decorators import login_required
from django.http import Http404
from django.shortcuts import get_object_or_404, render
from django.urls import reverse

from .models import Device, OpnsenseConnection, SshConnection, UnifiCloudConnection, HillstoneConnection
from .provisioning import PORT, available_destinations, default_destination


@login_required
def connection_guide(request):
    device_id = request.GET.get("device", "")
    device = None
    if device_id:
        if not device_id.isascii() or not device_id.isdecimal() or len(device_id) > 18:
            raise Http404("Equipo no válido")
        device = get_object_or_404(Device.objects.select_related("site__client"), pk=int(device_id))

    vendors = dict(Device.Vendor.choices)
    vendor = device.vendor if device else request.GET.get("vendor", Device.Vendor.OPNSENSE)
    if vendor not in vendors:
        vendor = Device.Vendor.OPNSENSE
    method = request.GET.get("method", "")
    if vendor == Device.Vendor.OPNSENSE:
        if method not in ("api", "ssh"):
            method = "ssh" if device and device.management_method == Device.ManagementMethod.SSH else "api"
    else:
        method = "api" if vendor == Device.Vendor.UNIFI else "manual"

    export = getattr(device, "export_configuration", None) if device else None
    destination = export.destination if export else default_destination(device) if device else available_destinations()[0]
    connection_ready = False
    connection_url = None
    if device:
        if method == "ssh":
            connection_ready = SshConnection.objects.filter(device=device, last_ok=True).exists()
            connection_url = reverse("ssh_connection", args=[device.pk])
        elif vendor == Device.Vendor.OPNSENSE:
            connection_ready = OpnsenseConnection.objects.filter(device=device, last_ok=True).exists()
            connection_url = reverse("opnsense_api", args=[device.pk])
        elif vendor == Device.Vendor.UNIFI:
            connection_ready = UnifiCloudConnection.objects.filter(device=device, last_ok=True).exclude(remote_site_id="").exists()
            connection_url = reverse("unifi_cloud", args=[device.pk])
        elif vendor == Device.Vendor.HILLSTONE:
            connection_ready = HillstoneConnection.objects.filter(device=device, last_ok=True).exists()
            connection_url = reverse("hillstone_api", args=[device.pk])

    guide_query = f"device={device.pk}" if device else f"vendor={vendor}"
    return render(request, "connection_guide.html", {
        "device": device,
        "guide_devices": Device.objects.select_related("site__client").filter(active=True),
        "vendors": Device.Vendor.choices,
        "vendor": vendor,
        "vendor_label": vendors[vendor],
        "method": method,
        "guide_query": guide_query,
        "guide_storage_key": f"soc-guide-v1-{request.user.pk}-{device.pk if device else 'new'}-{vendor}-{method}",
        "export": export,
        "destination": destination,
        "destinations": available_destinations(),
        "syslog_port": PORT,
        "connection_ready": connection_ready,
        "connection_url": connection_url,
    })

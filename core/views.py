from datetime import date, datetime, timedelta

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.db.models.deletion import ProtectedError
from django.db.models import Count, Q
from django.http import Http404, HttpResponseForbidden, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_http_methods

from .forms import ClientForm, DeviceForm, IncidentForm, MailSettingsForm, SiteDeviceFormSet, SiteEditForm, SiteForm
from .models import Client, Device, ExportConfiguration, Incident, MailSettings, OpnsenseConnection, Site, SshConnection, UnifiCloudConnection, UrgentAlert, UrgentMonitorCursor, WeeklyReport
from .mail_delivery import MailConfigurationError, encrypt_sendgrid_key, send_test_email
from .reporting import report_context
from .opnsense_api import OpnsenseApiError, check_connection, decrypt_credential, discover_version, encrypt_credential, get_firmware_info, validate_api_url, validate_ca_certificate
from .provisioning import available_destinations, default_destination, provision_export
from .ssh_connection import SshConnectionError, check_connection as check_ssh, check_generic_connection, encrypt_password, probe_host_key, validate_host, validate_port
from .unifi_cloud import UnifiCloudError, decrypt_api_key, encrypt_api_key, get_console_details, list_host_consoles, list_host_names, list_sites


def _update_unifi_details(device, api_key, host_id):
    details = get_console_details(api_key, host_id)
    fields = []
    for key in ("model", "software_version"):
        if details.get(key):
            setattr(device, key, details[key])
            fields.append(key)
    if fields:
        device.save(update_fields=fields)
    from .device_inventory import queue
    queue(device)


def _update_opnsense_details(device, api_url, api_key, api_secret, ca_certificate):
    info = get_firmware_info(api_url, api_key, api_secret, ca_certificate)
    version = discover_version(info)
    if version:
        device.software_version = version
        device.save(update_fields=["software_version"])


@login_required
def dashboard(request):
    return render(request, "dashboard.html", {
        "client_count": Client.objects.filter(active=True).count(),
        "site_count": Site.objects.filter(active=True).count(),
        "device_count": Device.objects.filter(active=True).count(),
        "connected_count": Device.objects.filter(active=True, integration=Device.Integration.CONNECTED).count(),
        "open_count": Incident.objects.exclude(status=Incident.Status.RESOLVED).count(),
        "critical_count": Incident.objects.exclude(status=Incident.Status.RESOLVED).filter(severity=Incident.Severity.CRITICAL).count(),
        "recent_incidents": Incident.objects.select_related("client", "site")[:8],
        "recent_clients": Client.objects.annotate(site_count=Count("sites", distinct=True), device_count=Count("sites__devices", distinct=True))[:8],
    })


@login_required
def api_connections(request):
    devices = Device.objects.all().select_related(
        "site__client", "unifi_cloud", "opnsense_api", "hillstone_api", "gdms_cloud", "ssh_connection", "export_configuration"
    )
    rows = []
    for device in devices:
        if device.management_method == Device.ManagementMethod.SSH:
            connection = getattr(device, "ssh_connection", None)
            url_name = "ssh_connection"
            ready = bool(connection and connection.last_ok)
        elif device.vendor == Device.Vendor.UNIFI:
            connection = getattr(device, "unifi_cloud", None)
            url_name = "unifi_cloud"
            ready = bool(connection and connection.remote_site_id and connection.last_ok)
        elif device.vendor == Device.Vendor.OPNSENSE:
            connection = getattr(device, "opnsense_api", None)
            url_name = "opnsense_api"
            ready = bool(connection and connection.last_ok)
        elif device.vendor == Device.Vendor.GRANDSTREAM_GCC:
            connection = getattr(device, "gdms_cloud", None)
            if connection and connection.client_scope_id != device.site.client_id:
                connection = None
            url_name = "gdms_cloud"
            ready = bool(connection and connection.last_ok)
        elif device.vendor == Device.Vendor.HILLSTONE:
            connection = getattr(device, "hillstone_api", None)
            url_name = "hillstone_api"
            ready = bool(connection and connection.last_ok)
        else:
            connection = None
            url_name = "ssh_connection"
            ready = False
        rows.append({"device": device, "url_name": url_name, "configured": bool(connection), "ready": ready,
                     "export": getattr(device, "export_configuration", None)})
    return render(request, "api_connections.html", {"rows": rows})


@login_required
def urgent_alert_list(request):
    client_id = request.GET.get("client", "")
    alerts = UrgentAlert.objects.select_related("client")
    if client_id.isdigit():
        alerts = alerts.filter(client_id=int(client_id))
    monitor = UrgentMonitorCursor.objects.filter(pk=1).first()
    return render(request, "urgent_alerts.html", {
        "alerts": alerts[:100], "clients": Client.objects.all(), "selected_client": client_id,
        "monitor": monitor, "monitor_stale": bool(monitor and timezone.now() - monitor.last_checked_at > timedelta(minutes=5)),
        "mail_ready": MailSettings.objects.filter(pk=1, enabled=True, last_test_ok=True).exists(),
    })


@login_required
@never_cache
def mail_settings(request):
    if not request.user.has_perm("core.manage_connections"):
        return HttpResponseForbidden("Tu cuenta no tiene permiso para gestionar el correo de informes.")
    config = MailSettings.objects.filter(pk=1).first()
    if request.method == "POST" and request.POST.get("action") == "disable":
        if config:
            config.enabled = False
            config.save(update_fields=["enabled", "updated_at"])
        messages.success(request, "Envío automático desactivado.")
        return redirect("mail_settings")
    form = MailSettingsForm(request.POST or None, instance=config)
    if request.method == "POST":
        action = request.POST.get("action")
        valid = form.is_valid()
        if valid and action == "test" and not form.cleaned_data.get("test_email"):
            form.add_error("test_email", "Indica la dirección que recibirá el correo de prueba.")
            valid = False
        if valid and action in ("save", "test"):
            delivery_changed = not config or bool(form.cleaned_data.get("api_key")) or bool(set(form.changed_data) & {"region", "from_email"})
            url_changed = not config or "public_reports_url" in form.changed_data
            config = form.save(commit=False)
            config.pk = 1
            if delivery_changed:
                config.enabled = False
                config.last_test_ok = False
                config.last_tested_at = None
            if url_changed:
                config.public_reports_verified = False
            api_key = form.cleaned_data.get("api_key", "")
            try:
                if api_key:
                    config.encrypted_api_key = encrypt_sendgrid_key(api_key)
            except MailConfigurationError as exc:
                form.add_error("api_key", str(exc))
            else:
                config.save()
                if action == "save":
                    messages.success(request, "Configuración guardada. Comprueba la URL pública de informes; si cambiaste las credenciales de envío, envía una prueba de correo.")
                    return redirect("mail_settings")
                config.last_tested_at = timezone.now()
                try:
                    send_test_email(config, form.cleaned_data["test_email"])
                except Exception:
                    accepted = False
                else:
                    accepted = True
                config.last_test_ok = accepted
                config.enabled = accepted
                config.save(update_fields=["last_tested_at", "last_test_ok", "enabled", "updated_at"])
                if accepted:
                    messages.success(request, "SendGrid aceptó la prueba. Comprueba que llegó al buzón; los envíos semanales quedan activos.")
                else:
                    messages.error(request, "SendGrid no aceptó la prueba. Revisa la clave con permiso Mail Send, el remitente verificado y la región de la cuenta.")
                return redirect("mail_settings")
        elif valid:
            form.add_error(None, "Acción no reconocida.")
    return render(request, "mail_settings.html", {"form": form, "config": config})


@login_required
def client_list(request):
    query = request.GET.get("q", "").strip()
    clients = Client.objects.annotate(site_count=Count("sites", distinct=True), device_count=Count("sites__devices", distinct=True))
    if query:
        clients = clients.filter(Q(name__icontains=query) | Q(code__icontains=query))
    return render(request, "clients.html", {"clients": clients, "query": query})


@login_required
def client_detail(request, pk):
    client = get_object_or_404(Client, pk=pk)
    return render(request, "client_detail.html", {
        "client": client,
        "latest_report": client.weekly_reports.first(),
        "sites": client.sites.annotate(device_count=Count("devices")),
        "incidents": client.incidents.select_related("site", "device")[:10],
        "recent_urgent_alerts": client.urgent_alerts.all()[:5],
        "device_count": Device.objects.filter(site__client=client).count(),
        "client_devices": Device.objects.filter(site__client=client).select_related('site'),
        "open_count": client.incidents.exclude(status=Incident.Status.RESOLVED).count(),
    })


@login_required
def site_detail(request, pk):
    site = get_object_or_404(Site.objects.select_related("client"), pk=pk)
    return render(request, "site_detail.html", {"site": site, "devices": site.devices.all(), "incidents": site.incidents.all()[:8]})


@login_required
@never_cache
@require_http_methods(['GET', 'POST'])
def site_delete(request, pk):
    if not request.user.has_perm('core.manage_connections'):
        return HttpResponseForbidden('Tu cuenta no tiene permiso para eliminar sedes y sus conexiones.')
    site = get_object_or_404(Site.objects.select_related('client'), pk=pk)
    error = ''
    incidents = Incident.objects.filter(Q(site=site) | Q(device__site=site)).distinct().count()
    from .models import SecurityEvidence,ChangePlan,VpnPeer
    retained=[]
    for label,count in [('evidencias de seguridad',SecurityEvidence.objects.filter(device__site=site).count()),
                        ('propuestas de cambios',ChangePlan.objects.filter(device__site=site).count()),
                        ('configuraciones VPN',VpnPeer.objects.filter(site=site).count())]:
        if count: retained.append({'label':label,'count':count})
    if request.method == 'POST':
        if incidents:
            error = 'Esta sede tiene incidencias asociadas. Se conserva para mantener su historial; puedes desactivarla desde «Editar».'
        elif retained:
            error = 'Esta sede tiene registros del SOC que deben conservarse. Puedes desactivarla desde «Editar».'
        elif request.POST.get('confirm') != 'yes':
            error = 'Confirma que quieres eliminar la sede y sus equipos antes de continuar.'
        else:
            client_id, site_name = site.client_id, site.name
            try:
                with transaction.atomic():
                    # Site -> Device is PROTECT; explicitly delete only this site's devices.
                    # Incident references remain protected and roll back the entire operation.
                    Device.objects.filter(site=site).delete()
                    site.delete()
            except ProtectedError:
                error = 'No se puede eliminar: hay registros asociados que deben conservarse. No se ha borrado ningún dato.'
                incidents = Incident.objects.filter(Q(site=site) | Q(device__site=site)).distinct().count()
            else:
                messages.success(request, f'Sede «{site_name}» eliminada del panel junto con sus equipos y conexiones guardadas.')
                return redirect('client_detail', pk=client_id)
    return render(request, 'site_delete.html', {
        'site': site, 'devices': site.devices.all(), 'incident_count': incidents, 'retained':retained,'error_message': error,
    })


@login_required
def device_detail(request, pk):
    device = get_object_or_404(Device.objects.select_related("site__client"), pk=pk)
    from .device_inventory import facts
    return render(request, "device_detail.html", {"device": device, "incidents": device.incidents.all()[:8],
                                                  "export": ExportConfiguration.objects.filter(device=device).first(),
                                                  "destinations": available_destinations(),
                                                  "default_destination": default_destination(device), 'inventory_facts': facts(device),
                                                  'gdms_connection': getattr(device, 'gdms_cloud', None) if device.vendor == 'grandstream_gcc' else None,
                                                  'device_health': getattr(device, 'health', None)})


@login_required
def export_destination(request, pk):
    if not request.user.has_perm("core.manage_connections"):
        return HttpResponseForbidden("Tu cuenta no tiene permiso para gestionar conexiones.")
    device = get_object_or_404(Device, pk=pk)
    if request.method != "POST":
        return redirect("device_detail", pk=pk)
    destination = request.POST.get("destination", "")
    if destination not in available_destinations():
        messages.error(request, "Selecciona una dirección del servidor permitida.")
        return redirect("device_detail", pk=pk)
    export, _ = ExportConfiguration.objects.get_or_create(device=device)
    export.destination = destination
    export.status = ExportConfiguration.Status.PENDING
    export.receiver_ready = False
    export.save(update_fields=["destination", "status", "receiver_ready"])
    result = provision_export(device)
    if result.status == ExportConfiguration.Status.CONFIGURED:
        messages.success(request, f"Exportación configurada hacia {destination}:{result.port}.")
    else:
        messages.warning(request, f"Destino guardado; exportación pendiente: {result.last_error}")
    return redirect("device_detail", pk=pk)


def _save_form(request, form_class, instance, initial, title, cancel_url, success_url):
    form = form_class(request.POST or None, instance=instance, initial=initial)
    if request.method == "POST" and form.is_valid():
        from django.db import IntegrityError
        try:
            with transaction.atomic():
                obj = form.save()
        except IntegrityError:
            mac = form.cleaned_data.get('mac_address')
            if form_class is not DeviceForm or not mac or not Device._base_manager.filter(mac_address=mac).exclude(pk=form.instance.pk).exists():
                raise
            form.add_error('mac_address', 'Esta MAC ya está registrada en otro equipo.')
        else:
            messages.success(request, f"{title} guardado correctamente.")
            return redirect(success_url, pk=obj.pk)
    return render(request, "object_form.html", {"form": form, "title": title, "cancel_url": cancel_url, "is_edit": instance is not None})


@login_required
def client_form(request, pk=None):
    instance = get_object_or_404(Client, pk=pk) if pk else None
    return _save_form(request, ClientForm, instance, {}, "Cliente", reverse("client_detail", args=[pk]) if pk else reverse("client_list"), "client_detail")


@login_required
def site_form(request, pk=None):
    if pk is None and (request.method == 'GET' or request.POST.get('wizard_step') == '1'):
        from .onboarding import new_site
        return new_site(request)
    instance = get_object_or_404(Site, pk=pk) if pk else None
    client_id = request.GET.get("client", "")
    if instance is not None:
        initial = {"client": client_id} if client_id.isdigit() and Client.objects.filter(pk=client_id).exists() else {}
        cancel = reverse("site_detail", args=[pk])
        return _save_form(request, SiteEditForm, instance, initial, "Sede", cancel, "site_detail")
    selected_client = None
    if client_id:
        if not client_id.isascii() or not client_id.isdecimal() or len(client_id) > 18:
            raise Http404('Cliente no válido')
        selected_client = get_object_or_404(Client, pk=int(client_id))
    cancel = reverse('client_detail', args=[selected_client.pk]) if selected_client else reverse('client_list')
    form = SiteForm(request.POST or None, selected_client=selected_client)
    devices_formset = SiteDeviceFormSet(
        request.POST or None, prefix="devices",
        form_kwargs={"can_manage_connections": request.user.has_perm("core.manage_connections")},
    )
    site_valid = form.is_valid() if request.method == "POST" else False
    devices_valid = devices_formset.is_valid() if request.method == "POST" else False
    if site_valid and devices_valid:
        prepared = []
        try:
            for device_form in devices_formset:
                if not device_form.has_changed():
                    continue
                values = device_form.cleaned_data
                credentials = None
                if values["management_method"] == Device.ManagementMethod.API:
                    if values["vendor"] == Device.Vendor.UNIFI:
                        credentials = {"encrypted_api_key": encrypt_api_key(values["api_key"])}
                    elif values["vendor"] == Device.Vendor.OPNSENSE:
                        credentials = {
                            "api_url": values["api_url"],
                            "encrypted_api_key": encrypt_credential(values["api_key"]),
                            "encrypted_api_secret": encrypt_credential(values["api_secret"]),
                            "ca_certificate": values.get("ca_certificate", ""),
                        }
                prepared.append((device_form, credentials))
        except (UnifiCloudError, OpnsenseApiError) as exc:
            form.add_error(None, str(exc))
        else:
            with transaction.atomic():
                site = form.save()
                created = []
                for device_form, credentials in prepared:
                    device = device_form.save(commit=False)
                    device.site = site
                    device.integration = Device.Integration.PENDING
                    if device.vendor == Device.Vendor.OPNSENSE and credentials:
                        device.management_address = credentials["api_url"]
                    device.save()
                    if credentials and device.vendor == Device.Vendor.UNIFI:
                        UnifiCloudConnection.objects.create(device=device, **credentials)
                    elif credentials and device.vendor == Device.Vendor.OPNSENSE:
                        OpnsenseConnection.objects.create(device=device, **credentials)
                    created.append(device)
            messages.success(request, f"Sede creada con {len(created)} equipo(s).")
            for device in created:
                if device.management_method != Device.ManagementMethod.API:
                    continue
                try:
                    if device.vendor == Device.Vendor.UNIFI:
                        connection = device.unifi_cloud
                        api_key = decrypt_api_key(connection.encrypted_api_key)
                        sites = list_sites(api_key)
                        connection.last_checked_at = timezone.now()
                        if len(sites) == 1 and not UnifiCloudConnection.objects.filter(remote_site_id=sites[0]["site_id"]).exclude(device=device).exists():
                            selected = sites[0]
                            connection.remote_site_id = selected["site_id"]
                            connection.remote_host_id = selected["host_id"]
                            connection.remote_site_name = selected["name"]
                            connection.last_ok = True
                            connection.save()
                            try:
                                _update_unifi_details(device, api_key, selected["host_id"])
                            except UnifiCloudError:
                                messages.warning(request, f"{device.name}: conexión verificada; modelo y versión siguen pendientes.")
                        else:
                            connection.save(update_fields=["last_checked_at"])
                            messages.info(request, f"{device.name}: selecciona la sede UniFi en «Configurar API».")
                    elif device.vendor == Device.Vendor.OPNSENSE:
                        connection = device.opnsense_api
                        api_key = decrypt_credential(connection.encrypted_api_key)
                        api_secret = decrypt_credential(connection.encrypted_api_secret)
                        check_connection(connection.api_url, api_key, api_secret, connection.ca_certificate)
                        connection.last_ok = True
                        connection.last_checked_at = timezone.now()
                        connection.save(update_fields=["last_ok", "last_checked_at"])
                        try:
                            _update_opnsense_details(device, connection.api_url, api_key, api_secret, connection.ca_certificate)
                        except OpnsenseApiError:
                            messages.warning(request, f"{device.name}: conexión verificada; versión pendiente de descubrir.")
                except (UnifiCloudError, OpnsenseApiError) as exc:
                    messages.warning(request, f"{device.name}: guardado, pero no se pudo verificar la API: {exc}")
                else:
                    if ((device.vendor == Device.Vendor.OPNSENSE and device.opnsense_api.last_ok)
                            or (device.vendor == Device.Vendor.UNIFI and device.unifi_cloud.last_ok)):
                        export = provision_export(device)
                        if export.status == ExportConfiguration.Status.ERROR:
                            messages.warning(request, f"{device.name}: API verificada; exportación pendiente: {export.last_error}")
            if (len(created) == 1 and created[0].management_method == Device.ManagementMethod.SSH
                    and request.user.has_perm("core.manage_connections")):
                return redirect("ssh_connection", pk=created[0].pk)
            return redirect("site_detail", pk=site.pk)
    return render(request, "site_with_devices_form.html", {
        "form": form,
        "devices_formset": devices_formset,
        "cancel_url": cancel,
        "selected_client": selected_client,
    })


@login_required
def device_form(request, pk=None):
    instance = get_object_or_404(Device, pk=pk) if pk else None
    site_id = request.GET.get("site", "")
    initial = {"site": site_id} if site_id.isdigit() and Site.objects.filter(pk=site_id).exists() else {}
    cancel = reverse("device_detail", args=[pk]) if pk else reverse("site_detail", args=[site_id]) if initial else reverse("client_list")
    return _save_form(request, DeviceForm, instance, initial, "Equipo", cancel, "device_detail")


@login_required
@never_cache
def unifi_cloud(request, pk):
    if not request.user.has_perm("core.manage_connections"):
        return HttpResponseForbidden("Tu cuenta no tiene permiso para gestionar conexiones API.")
    device = get_object_or_404(Device.objects.select_related("site__client"), pk=pk, vendor=Device.Vendor.UNIFI)
    connection = UnifiCloudConnection.objects.filter(device=device).first()
    sites = None
    error_message = ""
    if request.method == "POST":
        action = request.POST.get("action")
        try:
            if action == "save_key":
                api_key = request.POST.get("api_key", "").strip()
                if len(api_key) > 512:
                    raise UnifiCloudError("La clave API es demasiado larga.")
                sites = list_sites(api_key)
                ciphertext = encrypt_api_key(api_key)
                connection, _ = UnifiCloudConnection.objects.update_or_create(
                    device=device,
                    defaults={
                        "encrypted_api_key": ciphertext,
                        "remote_site_id": "",
                        "remote_host_id": "",
                        "remote_site_name": "",
                        "last_checked_at": timezone.now(),
                        "last_ok": False,
                    },
                )
                messages.success(request, "Clave validada y guardada. Selecciona la sede UniFi correspondiente.")
            elif action in ("refresh", "link"):
                if connection is None:
                    raise UnifiCloudError("Primero guarda una clave API.")
                sites = list_sites(decrypt_api_key(connection.encrypted_api_key))
                connection.last_checked_at = timezone.now()
                if action == "link":
                    site_id = request.POST.get("site_id", "")
                    selected = next((site for site in sites if site["site_id"] == site_id), None)
                    if selected is None:
                        raise UnifiCloudError("Selecciona una sede incluida en la cuenta UniFi.")
                    if UnifiCloudConnection.objects.filter(remote_site_id=selected["site_id"]).exclude(device=device).exists():
                        raise UnifiCloudError("Esta sede UniFi ya está vinculada a otro equipo del panel.")
                    connection.remote_site_id = selected["site_id"]
                    connection.remote_host_id = selected["host_id"]
                    connection.remote_site_name = selected["name"]
                    connection.last_ok = True
                    messages.success(request, "Sede UniFi vinculada y acceso API verificado.")
                    try:
                        _update_unifi_details(device, decrypt_api_key(connection.encrypted_api_key), selected["host_id"])
                    except UnifiCloudError:
                        messages.warning(request, "Acceso verificado; modelo y versión pendientes de descubrir.")
                elif connection.remote_site_id:
                    connection.last_ok = any(
                        site["site_id"] == connection.remote_site_id and site["host_id"] == connection.remote_host_id
                        for site in sites
                    )
                    if connection.last_ok:
                        messages.success(request, "Acceso API verificado.")
                    else:
                        messages.warning(request, "La sede vinculada ya no está accesible con esta clave.")
                connection.save()
                if action == "link" and connection.last_ok:
                    export = provision_export(device)
                    if export.status == ExportConfiguration.Status.CONFIGURED:
                        messages.success(request, "Activity Logging configurado para enviar al SOC.")
                    else:
                        messages.warning(request, f"Exportación pendiente: {export.last_error}")
            elif action == "remove":
                if connection is not None:
                    connection.delete()
                messages.success(request, "Clave API eliminada del panel. Revócala también en UniFi si ya no se utilizará.")
                return redirect("unifi_cloud", pk=device.pk)
            else:
                raise UnifiCloudError("Acción no válida.")
        except UnifiCloudError as exc:
            error_message = str(exc)
            if connection is not None and action == "refresh":
                connection.last_ok = False
                connection.last_checked_at = timezone.now()
                connection.save(update_fields=["last_ok", "last_checked_at"])
    if request.method == "GET" and connection is not None:
        try:
            sites = list_sites(decrypt_api_key(connection.encrypted_api_key))
        except UnifiCloudError as exc:
            error_message = str(exc)
    linked_label = ""
    if sites:
        try:
            api_key = decrypt_api_key(connection.encrypted_api_key)
            consoles = list_host_consoles(api_key)
        except UnifiCloudError:
            consoles = {}
        try:
            host_names = list_host_names(decrypt_api_key(connection.encrypted_api_key))
        except UnifiCloudError:
            host_names = {}
        for index, site in enumerate(sites, 1):
            details = consoles.get(site["host_id"], {})
            host_name = details.get("console_name") or host_names.get(site["host_id"]) or details.get("host_name") or f"Consola {index}"
            model = details.get("model")
            site_name = site["name"] if site["name"] != site["site_id"] else "Sede sin nombre"
            site["choice_label"] = " · ".join(part for part in (host_name, site_name, model) if part)
            if connection and site["site_id"] == connection.remote_site_id and site["host_id"] == connection.remote_host_id:
                linked_label = site["choice_label"]
    return render(request, "unifi_cloud.html", {
        "device": device,
        "connection": connection,
        "export": ExportConfiguration.objects.filter(device=device).first(),
        "sites": sites,
        "linked_label": linked_label,
        "error_message": error_message,
    })


@login_required
@never_cache
def opnsense_api(request, pk):
    if not request.user.has_perm("core.manage_connections"):
        return HttpResponseForbidden("Tu cuenta no tiene permiso para gestionar conexiones API.")
    device = get_object_or_404(Device.objects.select_related("site__client"), pk=pk, vendor=Device.Vendor.OPNSENSE)
    connection = OpnsenseConnection.objects.filter(device=device).first()
    error_message = ""
    if request.method == "POST":
        action = request.POST.get("action")
        try:
            if action == "save":
                api_url = validate_api_url(request.POST.get("api_url", ""))
                ca_certificate = validate_ca_certificate(request.POST.get("ca_certificate", ""))
                encrypted_key = encrypt_credential(request.POST.get("api_key", ""))
                encrypted_secret = encrypt_credential(request.POST.get("api_secret", ""))
                connection, _ = OpnsenseConnection.objects.update_or_create(
                    device=device,
                    defaults={
                        "api_url": api_url,
                        "encrypted_api_key": encrypted_key,
                        "encrypted_api_secret": encrypted_secret,
                        "ca_certificate": ca_certificate,
                        "last_checked_at": None,
                        "last_ok": False,
                    },
                )
                messages.success(request, "Conexión guardada. Se verificará el acceso para preparar la exportación.")
                action = "test"
            if action == "test":
                if connection is None:
                    raise OpnsenseApiError("Primero guarda la conexión API.")
                connection.last_checked_at = timezone.now()
                connection.last_ok = False
                connection.save(update_fields=["last_checked_at", "last_ok"])
                check_connection(
                    connection.api_url,
                    decrypt_credential(connection.encrypted_api_key),
                    decrypt_credential(connection.encrypted_api_secret),
                    connection.ca_certificate,
                )
                connection.last_ok = True
                connection.save(update_fields=["last_ok"])
                if device.management_method != Device.ManagementMethod.API:
                    device.management_method = Device.ManagementMethod.API
                    device.save(update_fields=["management_method"])
                try:
                    _update_opnsense_details(
                        device, connection.api_url,
                        decrypt_credential(connection.encrypted_api_key),
                        decrypt_credential(connection.encrypted_api_secret), connection.ca_certificate,
                    )
                except OpnsenseApiError:
                    messages.warning(request, "Acceso verificado; versión pendiente de descubrir.")
                messages.success(request, "Acceso API de OPNsense verificado.")
                from .device_inventory import queue as queue_inventory
                queue_inventory(device)
                if not device.management_address:
                    device.management_address = connection.api_url
                    device.save(update_fields=['management_address'])
                export = provision_export(device)
                if export.status == ExportConfiguration.Status.CONFIGURED:
                    messages.success(request, "Destino syslog creado o verificado en OPNsense.")
                else:
                    messages.warning(request, f"Exportación pendiente: {export.last_error}")
            elif action == "remove":
                if connection is not None:
                    connection.delete()
                messages.success(request, "Credenciales eliminadas del panel. Revoca también la pareja API en OPNsense si ya no se usará.")
                return redirect("opnsense_api", pk=device.pk)
            else:
                raise OpnsenseApiError("Acción no válida.")
        except OpnsenseApiError as exc:
            error_message = str(exc)
    return render(request, "opnsense_api.html", {
        "device": device,
        "connection": connection,
        "export": ExportConfiguration.objects.filter(device=device).first(),
        "error_message": error_message,
    })


@login_required
@never_cache
def ssh_connection(request, pk):
    if not request.user.has_perm("core.manage_connections"):
        return HttpResponseForbidden("Tu cuenta no tiene permiso para gestionar conexiones.")
    device = get_object_or_404(Device.objects.select_related("site__client"), pk=pk)
    connection = SshConnection.objects.filter(device=device).first()
    error_message = ""
    probe = request.session.get(f"ssh_probe_{pk}")
    values = {"hostname": connection.hostname if connection else device.management_address,
              "port": connection.port if connection else 22,
              "username": connection.username if connection else device.ssh_username}
    if request.method == "POST":
        action = request.POST.get("action", "")
        try:
            if action == "probe":
                values = {"hostname": validate_host(request.POST.get("hostname", "")),
                          "port": validate_port(request.POST.get("port", 22)),
                          "username": request.POST.get("username", "").strip()}
                probe = probe_host_key(values["hostname"], values["port"])
                probe.update(values)
                request.session[f"ssh_probe_{pk}"] = probe
                messages.info(request, "Comprueba la huella SSH del equipo y confírmala antes de guardar la contraseña.")
            elif action == "save":
                values = {"hostname": validate_host(request.POST.get("hostname", "")),
                          "port": validate_port(request.POST.get("port", 22)),
                          "username": request.POST.get("username", "").strip()}
                if not values["username"] or len(values["username"]) > 120 or any(c in values["username"] for c in "\r\n\t"):
                    raise SshConnectionError("Indica un usuario SSH válido.")
                if not probe or any(probe.get(key) != values[key] for key in values):
                    raise SshConnectionError("Obtén de nuevo la huella SSH para esta dirección, puerto y usuario.")
                if request.POST.get("fingerprint", "").strip() != probe["fingerprint"]:
                    raise SshConnectionError("Confirma la huella exacta que muestra el panel.")
                current = probe_host_key(values["hostname"], values["port"])
                if current["base64"] != probe["base64"] or current["type"] != probe["type"]:
                    raise SshConnectionError("La clave SSH del equipo ha cambiado. Revisa la huella.")
                encrypted = encrypt_password(request.POST.get("password", ""))
                connection, _ = SshConnection.objects.update_or_create(device=device, defaults={
                    **values, "encrypted_password": encrypted, "host_key_type": current["type"],
                    "host_key_base64": current["base64"], "fingerprint": current["fingerprint"],
                    "last_checked_at": None, "last_ok": False,
                })
                del request.session[f"ssh_probe_{pk}"]
                probe = None
                device.management_method = Device.ManagementMethod.SSH
                device.management_address = values["hostname"]
                device.ssh_username = values["username"]
                device.save(update_fields=["management_method", "management_address", "ssh_username"])
                action = "test"
            if action == "test":
                if connection is None:
                    raise SshConnectionError("Primero guarda la conexión SSH.")
                connection.last_checked_at = timezone.now()
                connection.last_ok = False
                connection.save(update_fields=["last_checked_at", "last_ok"])
                version = check_ssh(connection) if device.vendor == Device.Vendor.OPNSENSE else check_generic_connection(connection)
                if version and device.vendor == Device.Vendor.OPNSENSE:
                    device.software_version = version
                    device.save(update_fields=["software_version"])
                connection.last_ok = True
                connection.save(update_fields=["last_ok"])
                messages.success(request, "Conexión SSH verificada y huella comprobada.")
                from .device_inventory import queue as queue_inventory
                queue_inventory(device)
                if device.vendor == Device.Vendor.OPNSENSE:
                    export = provision_export(device)
                    if export.status == ExportConfiguration.Status.CONFIGURED:
                        messages.success(request, "Destino syslog configurado en OPNsense.")
                    else:
                        messages.warning(request, f"Exportación pendiente: {export.last_error}")
            elif action == "remove":
                if connection:
                    connection.delete()
                request.session.pop(f"ssh_probe_{pk}", None)
                messages.success(request, "Credenciales SSH eliminadas del panel.")
                return redirect("ssh_connection", pk=pk)
            elif action not in ("probe", "save"):
                raise SshConnectionError("Acción no válida.")
        except SshConnectionError as exc:
            error_message = str(exc)
    return render(request, "ssh_connection.html", {"device": device, "connection": connection,
                                                     "probe": probe, "values": values, "error_message": error_message})


@login_required
def incident_list(request):
    incidents = Incident.objects.select_related("client", "site", "device", "owner")
    status = request.GET.get("status", "")
    client_id = request.GET.get("client", "")
    if status in Incident.Status.values:
        incidents = incidents.filter(status=status)
    if client_id.isdigit():
        incidents = incidents.filter(client_id=client_id)
    return render(request, "incidents.html", {"incidents": incidents[:200], "clients": Client.objects.all(), "selected_status": status, "selected_client": client_id, "statuses": Incident.Status.choices})


@login_required
def incident_detail(request, pk):
    incident = get_object_or_404(Incident.objects.select_related("client", "site", "device", "owner"), pk=pk)
    evidences=incident.evidence.select_related('asset').all()
    from .asset_context import review,describe
    from .models import AttributionCatalog
    contexts={r.device_id:r for r in AttributionCatalog.objects.filter(device_id__in=evidences.values('device_id'))}
    visible_evidences=list(evidences[:300])
    for e in visible_evidences:
        e.context_note=describe(review(contexts.get(e.device_id),e.source_ip,e.destination_ip,e.destination_port,e.flow)) if not e.asset_id else ''
    return render(request, "incident_detail.html", {"incident": incident,'evidences':visible_evidences,
        'evidence_total':evidences.count(),'blocked_total':evidences.filter(action='blocked').count(),
        'allowed_total':evidences.filter(action='allowed').count(),'unknown_total':evidences.exclude(action__in=('blocked','allowed')).count()})


@login_required
def incident_form(request, pk=None):
    instance = get_object_or_404(Incident, pk=pk) if pk else None
    initial = {}
    for field in ("client", "site", "device"):
        value = request.GET.get(field, "")
        if value.isdigit():
            initial[field] = value
    return _save_form(request, IncidentForm, instance, initial, "Incidencia", reverse("incident_detail", args=[pk]) if pk else reverse("incident_list"), "incident_detail")


@login_required
def related_options(request):
    client_id = request.GET.get("client", "")
    site_id = request.GET.get("site", "")
    sites = Site.objects.filter(client_id=client_id).values("id", "name") if client_id.isdigit() else []
    devices = Device.objects.filter(site_id=site_id, site__client_id=client_id).values("id", "name") if site_id.isdigit() and client_id.isdigit() else []
    return JsonResponse({"sites": list(sites), "devices": list(devices)})


@login_required
def weekly_report(request, client_pk):
    client = get_object_or_404(Client, pk=client_pk)
    raw_week = request.GET.get("week", "")
    try:
        chosen = date.fromisoformat(raw_week)
    except ValueError:
        today = timezone.localdate()
        chosen = today - timedelta(days=today.weekday())
    monday = chosen - timedelta(days=chosen.weekday())
    report = WeeklyReport.objects.filter(client=client, week_start=monday).first()
    if report:
        context = report_context(report)
        context.update({"previous_week": monday - timedelta(days=7), "next_week": monday + timedelta(days=7)})
        if request.user.has_perm("core.manage_connections"):
            from .report_sharing import share_path
            share = getattr(report, "customer_share", None)
            config = MailSettings.objects.order_by("pk").first()
            context["share"] = share
            if share and not share.revoked and share.expires_at > timezone.now() and config and config.public_reports_url:
                context["customer_link"] = config.public_reports_url.rstrip("/") + share_path(share)
        return render(request, "weekly_report.html", context)
    next_monday = monday + timedelta(days=7)
    start = timezone.make_aware(datetime.combine(monday, datetime.min.time()))
    end = timezone.make_aware(datetime.combine(next_monday, datetime.min.time()))
    incidents = client.incidents.filter(observed_at__gte=start, observed_at__lt=end).select_related("site", "device")
    return render(request, "weekly_report.html", {
        "client": client,
        "monday": monday,
        "sunday": next_monday - timedelta(days=1),
        "previous_week": monday - timedelta(days=7),
        "next_week": next_monday,
        "incidents": incidents,
        "incident_count": incidents.count(),
        "resolved_count": incidents.filter(status=Incident.Status.RESOLVED).count(),
        "open_count": incidents.exclude(status=Incident.Status.RESOLVED).count(),
        "site_count": client.sites.filter(active=True).count(),
        "device_count": Device.objects.filter(site__client=client, active=True).count(),
        "connected_count": Device.objects.filter(site__client=client, active=True, integration=Device.Integration.CONNECTED).count(),
        "report": None,
        "provisional": monday + timedelta(days=7) > timezone.localdate(),
    })

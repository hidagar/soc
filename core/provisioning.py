"""Idempotent, per-device syslog provisioning for supported management methods."""

import ipaddress
import json
import os
import re
from urllib.parse import urlsplit

from django.utils import timezone

from .models import Device, ExportConfiguration, FirewallOnboarding
from .opnsense_api import OpnsenseApiError, _get_json, _post_json, decrypt_credential
from .ssh_connection import SshConnectionError, decrypt_password, run_command
from .unifi_cloud import UnifiCloudError, connector_json, decrypt_api_key, discover_syslog_source


class ProvisionError(Exception):
    pass


DESTINATION = "172.20.10.20"
PORT = 5514


def available_destinations():
    values = [DESTINATION]
    # Retain previous endpoints during a verified receiver migration. The public
    # default remains last, so existing UniFi behaviour is preserved.
    extra = os.environ.get("SOC_PORTAL_EXTRA_SYSLOG_IPS", "").split(',')
    public = os.environ.get("SOC_PORTAL_PUBLIC_SYSLOG_IP", "").strip()
    for candidate in [*(value for value in extra if value.strip() != public), public]:
        try:
            address = ipaddress.ip_address(candidate.strip())
            if address.version == 4 and str(address) not in values:
                values.append(str(address))
        except ValueError:
            pass
    return values


def default_destination(device):
    options = available_destinations()
    return options[-1] if device.vendor == Device.Vendor.UNIFI else DESTINATION


def _source_ip(device):
    address = device.management_address.strip()
    if not address:
        return None
    if "://" in address:
        address = urlsplit(address).hostname or ""
    try:
        source = ipaddress.ip_address(address)
    except ValueError:
        return None
    return str(source) if source.version == 4 else None


def _marker(device):
    return f"Centro SOC equipo {device.pk}"


def _api_request(connection, path, payload=None):
    args = (connection.api_url, decrypt_credential(connection.encrypted_api_key),
            decrypt_credential(connection.encrypted_api_secret), connection.ca_certificate, path)
    return _get_json(*args) if payload is None else _post_json(*args, payload)


def _opnsense_api(device, connection, destination, port):
    marker = _marker(device)
    result = _api_request(connection, "/api/syslog/settings/search_destinations")
    rows = result.get("rows")
    if not isinstance(rows, list):
        raise ProvisionError("OPNsense no devolvió la lista de destinos syslog esperada.")
    managed = next((row for row in rows if row.get("description") == marker), None)
    if managed is None and any(str(row.get("hostname")) == destination and str(row.get("port")) == str(port) for row in rows):
        raise ProvisionError("Ya existe un destino syslog hacia el SOC creado fuera del panel. Revísalo antes de continuar.")
    values = {"enabled": "1", "transport": "udp4", "hostname": destination,
              "port": str(port), "description": marker, "program": "", "level": "", "facility": "", "rfc5424": "0"}
    if managed is None:
        response = _api_request(connection, "/api/syslog/settings/add_destination", {"destination": values})
        uuid = response.get("uuid")
    else:
        uuid = managed.get("uuid")
        if not isinstance(uuid, str) or not uuid:
            raise ProvisionError("El destino syslog existente no tiene identificador.")
        if all(str(managed.get(key)) == str(values[key]) for key in ("enabled", "transport", "hostname", "port")):
            return uuid
        response = _api_request(connection, f"/api/syslog/settings/set_destination/{uuid}", {"destination": values})
    if response.get("result") not in ("saved", "ok", "success"):
        raise ProvisionError("OPNsense no confirmó el guardado del destino syslog.")
    if not isinstance(uuid, str) or not uuid:
        raise ProvisionError("OPNsense guardó el destino sin devolver su identificador.")
    apply_result = _api_request(connection, "/api/syslog/service/reconfigure", {})
    if apply_result.get("status") not in ("ok", "done", "success"):
        raise ProvisionError("El destino quedó guardado, pero OPNsense no confirmó su aplicación.")
    verify = _api_request(connection, f"/api/syslog/settings/get_destination/{uuid}")
    current = verify.get("destination")
    if not isinstance(current, dict) or str(current.get("hostname")) != destination or str(current.get("port")) != str(port):
        raise ProvisionError("OPNsense no devolvió el destino esperado después de aplicarlo.")
    return uuid


_SSH_PHP = r'''<?php
require_once('/usr/local/opnsense/mvc/script/load_phalcon.php');
use OPNsense\Syslog\Syslog;
use OPNsense\Core\Config;
try {
    if (posix_geteuid() !== 0) { throw new Exception('La configuración por SSH requiere una cuenta con permisos root.'); }
    $model = new Syslog();
    $marker = __MARKER__;
    $host = __HOST__;
    $port = __PORT__;
    $managed = null;
    foreach ($model->destinations->destination->iterateItems() as $key => $item) {
        if ((string)$item->description === $marker) { $managed = $item; break; }
        if ((string)$item->hostname === $host && (string)$item->port === $port) {
            throw new Exception('Ya existe un destino syslog hacia el SOC creado fuera del panel.');
        }
    }
    if ($managed === null) { $managed = $model->destinations->destination->add(); }
    $managed->enabled = '1';
    $managed->transport = 'udp4';
    $managed->hostname = $host;
    $managed->port = $port;
    $managed->description = $marker;
    $managed->program = '';
    $managed->level = '';
    $managed->facility = '';
    $managed->rfc5424 = '0';
    $issues = $model->performValidation();
    if ($issues->count() !== 0) { throw new Exception('OPNsense rechazó los valores del destino syslog.'); }
    $model->serializeToConfig();
    Config::getInstance()->save();
    $output = [];
    $code = 0;
    exec('/usr/local/sbin/configctl syslog reconfigure 2>&1', $output, $code);
    if ($code !== 0) { throw new Exception('El destino quedó guardado, pero falló la aplicación de syslog.'); }
    $check = new Syslog();
    foreach ($check->destinations->destination->iterateItems() as $key => $item) {
        if ((string)$item->description === $marker && (string)$item->hostname === $host && (string)$item->port === $port) {
            echo json_encode(['status' => 'ok', 'uuid' => (string)$key]);
            exit(0);
        }
    }
    throw new Exception('No se pudo verificar el destino syslog guardado.');
} catch (Throwable $error) {
    echo json_encode(['status' => 'error', 'message' => substr($error->getMessage(), 0, 220)]);
    exit(1);
}
'''


def _opnsense_ssh(device, connection, destination, port):
    script = (_SSH_PHP.replace("__MARKER__", json.dumps(_marker(device)))
             .replace("__HOST__", json.dumps(destination))
             .replace("__PORT__", json.dumps(str(port))))
    uid_status, uid_output, _ = run_command(connection, "id -u")
    if uid_status != 0:
        raise ProvisionError("No se pudieron comprobar los permisos SSH antes de configurar syslog.")
    if uid_output.strip() == "0":
        command = "/usr/local/bin/php -f /dev/stdin"
        payload = script.encode("utf-8")
    else:
        sudo_status, sudo_output, _ = run_command(connection, "sudo -n id -u")
        if sudo_status == 0 and sudo_output.strip() == "0":
            command = "sudo -n /usr/local/bin/php -f /dev/stdin"
            payload = script.encode("utf-8")
        else:
            command = "sudo -k -S -p '' /usr/local/bin/php -f /dev/stdin"
            payload = (decrypt_password(connection.encrypted_password) + "\n" + script).encode("utf-8")
    status, output, _ = run_command(connection, command, stdin_data=payload)
    try:
        result = json.loads(output)
    except (TypeError, ValueError) as exc:
        raise ProvisionError("OPNsense no devolvió una respuesta válida al configurar syslog por SSH.") from exc
    if status != 0 or result.get("status") != "ok":
        raise ProvisionError(result.get("message") or "OPNsense rechazó la configuración syslog por SSH.")
    return str(result.get("uuid") or "")[:160]


UNIFI_CONTENTS = ("admin_activity", "client", "critical", "device", "security_detections", "triggers", "updates", "vpn")


def _unifi_api(connection, destination, port, managed_identifier=""):
    if not connection.last_ok or not connection.remote_host_id:
        raise ProvisionError("Vincula y verifica primero la consola UniFi.")
    api_key = decrypt_api_key(connection.encrypted_api_key)
    path = "/network/api/s/default/rest/setting"
    def current_row():
        result = connector_json(api_key, connection.remote_host_id, path)
        rows = result.get("data")
        if not isinstance(rows, list):
            raise ProvisionError("UniFi no devolvió la configuración de Activity Logging.")
        return next((row for row in rows if isinstance(row, dict) and row.get("key") == "rsyslogd"), None)

    row = current_row()
    if row is None:
        raise ProvisionError("Esta versión de UniFi no expone Activity Logging en la API.")
    identifier = row.get("_id")
    if not isinstance(identifier, str) or not re.fullmatch(r"[a-fA-F0-9]{24}", identifier):
        raise ProvisionError("UniFi no devolvió un identificador de Activity Logging válido.")
    old_ip = str(row.get("ip") or "").strip()
    old_port = str(row.get("port") or "")
    if old_ip and (old_ip != destination or old_port not in ("", "0", str(port))) and identifier != managed_identifier:
        raise ProvisionError("UniFi ya exporta a otro servidor SIEM; el panel no cambiará ese destino.")
    wanted = set(UNIFI_CONTENTS)
    existing = {item for item in row.get("contents", []) if isinstance(item, str)}
    if old_ip == destination and old_port == str(port) and row.get("enabled") is True and wanted.issubset(existing):
        return identifier
    values = {"ip": destination, "port": port, "enabled": True,
              "contents": sorted(existing | wanted)}
    try:
        # Settings are addressed by their key; the object ID is retained only
        # to identify our managed export. Using the ID returns api.err.Invalid.
        connector_json(api_key, connection.remote_host_id, f"{path}/rsyslogd", method="PUT", payload=values)
    except UnifiCloudError as exc:
        if "HTTP 400" in str(exc):
            raise ProvisionError(
                "UniFi Cloud rechazó el cambio de Activity Logging. Configura el destino SIEM "
                f"{destination}:{port} en UniFi Network y vuelve a comprobar la conexión en el panel."
            ) from exc
        raise
    verified = current_row()
    if not isinstance(verified, dict) or str(verified.get("ip")) != destination or str(verified.get("port")) != str(port) or verified.get("enabled") is not True:
        raise ProvisionError("UniFi no confirmó el destino SIEM después de guardarlo.")
    if not wanted.issubset(set(verified.get("contents") or [])):
        raise ProvisionError("UniFi no confirmó todas las categorías de Activity Logging.")
    return identifier


def provision_export(device):
    config, _ = ExportConfiguration.objects.get_or_create(
        device=device, defaults={"destination": default_destination(device)}
    )
    # HTTPS transport is installed locally; an API refresh must not replace it
    # with a public UDP destination or with a guessed WAN source address.
    if FirewallOnboarding.objects.filter(device=device,method='https').exists():return config
    if config.destination not in available_destinations():
        config.status = ExportConfiguration.Status.ERROR
        config.last_error = "El destino de exportación no está entre las direcciones del servidor configuradas."
        config.save(update_fields=["status", "last_error"])
        return config
    confirmed_source = config.source_ip if config.status == ExportConfiguration.Status.CONFIGURED else None
    # The wizard asks for the real log origin, which can differ from management.
    wizard_source = config.source_ip if FirewallOnboarding.objects.filter(device=device, step=4).exists() else None
    config.port = PORT
    config.source_ip = wizard_source or _source_ip(device) or confirmed_source
    config.receiver_ready = False
    config.status = ExportConfiguration.Status.CONFIGURING
    config.last_error = ""
    config.last_attempt_at = timezone.now()
    config.save()
    try:
        if device.vendor == Device.Vendor.UNIFI and device.management_method == Device.ManagementMethod.API:
            identifier = _unifi_api(device.unifi_cloud, config.destination, PORT, config.remote_identifier)
            try:
                discovered_source = discover_syslog_source(
                    decrypt_api_key(device.unifi_cloud.encrypted_api_key), device.unifi_cloud.remote_host_id, config.destination
                )
                if discovered_source and not wizard_source:
                    config.source_ip = discovered_source
            except UnifiCloudError:
                pass
        elif device.vendor == Device.Vendor.OPNSENSE and device.management_method == Device.ManagementMethod.API:
            connection = device.opnsense_api
            if not connection.last_ok:
                raise ProvisionError("Verifica primero la conexión API.")
            identifier = _opnsense_api(device, connection, config.destination, PORT)
        elif device.vendor == Device.Vendor.OPNSENSE and device.management_method == Device.ManagementMethod.SSH:
            connection = device.ssh_connection
            if not connection.last_ok:
                raise ProvisionError("Verifica primero la conexión SSH.")
            identifier = _opnsense_ssh(device, connection, config.destination, PORT)
        else:
            raise ProvisionError("Este fabricante o método aún no admite configuración automática de syslog.")
        config.remote_identifier = identifier
        config.status = ExportConfiguration.Status.CONFIGURED
        config.configured_at = timezone.now()
        config.save()
        device.log_method = Device.LogMethod.SYSLOG
        device.save(update_fields=["log_method"])
        if device.vendor==Device.Vendor.OPNSENSE and device.management_method==Device.ManagementMethod.API and device.zenarmor_enabled:
            from .zenarmor_export import queue
            queue(device)
    except (ProvisionError, OpnsenseApiError, SshConnectionError, UnifiCloudError, AttributeError) as exc:
        config.status = ExportConfiguration.Status.ERROR
        config.last_error = str(exc)[:500]
        config.save(update_fields=["status", "last_error"])
    return config

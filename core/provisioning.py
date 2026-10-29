"""Idempotent, per-device syslog provisioning for supported management methods."""

import base64
import ipaddress
import json
import os
import re
import socket
from urllib.parse import urlsplit

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils import timezone

from .models import Device, ExportConfiguration, FirewallOnboarding
from .opnsense_api import OpnsenseApiError, _get_json, _post_json, decrypt_credential
from .ssh_connection import SshConnectionError, decrypt_password, run_command
from .unifi_cloud import UnifiCloudError, connector_json, decrypt_api_key, discover_syslog_source


class ProvisionError(Exception):
    pass


def _receiver():
    try:
        address = ipaddress.IPv4Address(settings.SOC_RECEIVER_IP)
    except ValueError as exc:
        raise ImproperlyConfigured("SOC_PORTAL_RECEIVER_IP debe ser una IPv4.") from exc
    if not 1 <= settings.SOC_RECEIVER_PORT <= 65535:
        raise ImproperlyConfigured("SOC_PORTAL_RECEIVER_PORT debe estar entre 1 y 65535.")
    return str(address), settings.SOC_RECEIVER_PORT


DESTINATION, PORT = _receiver()


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


def _soc_address(host):
    """Dirección del SOC a la que apunta un destino, o None. Admite IP o nombre (p. ej. soc.ibred.es)."""
    host = str(host or "").strip()
    known = available_destinations()
    if host in known:
        return host
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", host):
        return None
    try:
        resolved = {info[4][0] for info in socket.getaddrinfo(host, None, socket.AF_INET)}
    except OSError:
        return None
    return next((ip for ip in known if ip in resolved), None)


def _soc_rows(rows, port):
    """Destinos syslog del equipo que ya envían al SOC por este puerto, con la dirección a la que llegan."""
    found = []
    for row in rows:
        if isinstance(row, dict) and str(row.get("port")) == str(port):
            address = _soc_address(row.get("hostname"))
            if address:
                found.append((row, address))
    return found


def _opnsense_api(device, connection, destination, port):
    """Crea, verifica o adopta el destino syslog hacia el SOC. Devuelve (uuid, destino, aviso).

    Si alguien creó a mano un destino hacia el SOC, se adopta en lugar de crear otro: dos
    destinos duplicarían cada evento. Solo se corrige lo imprescindible (activado y UDP IPv4)
    y se conserva su descripción. Con varios destinos hacia el SOC se pide dejar uno.
    """
    marker = _marker(device)
    result = _api_request(connection, "/api/syslog/settings/search_destinations")
    rows = result.get("rows")
    if not isinstance(rows, list):
        raise ProvisionError("OPNsense no devolvió la lista de destinos syslog esperada.")
    to_soc = _soc_rows(rows, port)
    managed = next((row for row in rows if isinstance(row, dict) and row.get("description") == marker), None)
    others = [(row, address) for row, address in to_soc if row is not managed]
    notice = ""
    if managed is None and len(others) > 1:
        names = ", ".join(f"«{row.get('description') or row.get('hostname')}»" for row, _ in others)
        raise ProvisionError(f"El firewall tiene {len(others)} destinos syslog hacia el SOC ({names}); cada evento llegaría "
                             "repetido. Deja solo uno en OPNsense y vuelve a probar.")
    if managed is None and others:
        managed, destination = others[0]
        notice = (f"Se ha reutilizado el destino syslog «{managed.get('description') or destination}» que ya existía "
                  "en el firewall; no se ha creado otro.")
    elif others:
        notice = ("Además del destino del panel hay otro destino syslog hacia el SOC creado a mano: los eventos llegarán "
                  "repetidos. Elimínalo en OPNsense.")
    values = {"enabled": "1", "transport": "udp4", "hostname": destination,
              "port": str(port), "description": marker, "program": "", "level": "", "facility": "", "rfc5424": "0"}
    if managed is None:
        response = _api_request(connection, "/api/syslog/settings/add_destination", {"destination": values})
        uuid = response.get("uuid")
    else:
        uuid = managed.get("uuid")
        if not isinstance(uuid, str) or not uuid:
            raise ProvisionError("El destino syslog existente no tiene identificador.")
        if managed.get("description") != marker:
            # Adoptado: se conserva lo que el técnico configuró (nombre, aplicaciones, niveles) y solo se
            # corrige lo que impide recibir. La búsqueda devuelve textos de pantalla; el detalle, las claves.
            current = _api_request(connection, f"/api/syslog/settings/get_destination/{uuid}").get("destination")
            if not isinstance(current, dict):
                raise ProvisionError("OPNsense no devolvió el destino syslog existente.")
            current = {key: _option(value) for key, value in current.items()}
            if str(current.get("enabled")) == "1" and current.get("transport") == "udp4":
                return uuid, destination, notice
            values = {**current, "enabled": "1", "transport": "udp4"}
            notice += " Se ha activado y pasado a UDP IPv4, que es lo que recibe el SOC."
        elif all(str(managed.get(key)) == str(values[key]) for key in ("enabled", "transport", "hostname", "port")):
            return uuid, destination, notice
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
    if (not isinstance(current, dict) or _soc_address(_option(current.get("hostname"))) != destination
            or str(_option(current.get("port"))) != str(port)):
        raise ProvisionError("OPNsense no devolvió el destino esperado después de aplicarlo.")
    return uuid, destination, notice.strip()


def _option(value):
    """`get_destination` devuelve las listas como {clave: {value, selected}}; se envía la clave elegida."""
    if isinstance(value, dict):
        chosen = [key for key, item in value.items() if isinstance(item, dict) and str(item.get("selected")) in ("1", "True", "true")]
        return ",".join(chosen)
    return value


_SSH_PHP = r'''<?php
require_once('/usr/local/opnsense/mvc/script/load_phalcon.php');
use OPNsense\Syslog\Syslog;
use OPNsense\Core\Config;
// Misma política que la API: destino del panel, o se adopta uno hacia el SOC creado a mano.
function soc_address($host, $known) {
    $host = trim((string)$host);
    if (in_array($host, $known, true)) { return $host; }
    if (filter_var($host, FILTER_VALIDATE_IP) || !preg_match('/^[A-Za-z0-9.-]{1,253}$/', $host)) { return null; }
    $resolved = gethostbynamel($host) ?: [];
    foreach ($known as $ip) { if (in_array($ip, $resolved, true)) { return $ip; } }
    return null;
}
try {
    if (posix_geteuid() !== 0) { throw new Exception('La configuración por SSH requiere una cuenta con permisos root.'); }
    $model = new Syslog();
    // Los datos llegan en JSON y base64 dentro de comillas simples: PHP no interpreta nada de ellos.
    $params = json_decode(base64_decode('__PARAMS__'), true);
    $marker = (string)$params['marker'];
    $host = (string)$params['host'];
    $port = (string)$params['port'];
    $known = array_map('strval', $params['known']);
    $managed = null; $managedKey = null; $others = [];
    foreach ($model->destinations->destination->iterateItems() as $key => $item) {
        if ((string)$item->description === $marker) { $managed = $item; $managedKey = (string)$key; continue; }
        $address = (string)$item->port === $port ? soc_address((string)$item->hostname, $known) : null;
        if ($address !== null) { $others[] = [(string)$key, $item, $address]; }
    }
    $notice = '';
    $adopted = false;
    if ($managed === null && count($others) > 1) {
        throw new Exception('El firewall tiene ' . count($others) . ' destinos syslog hacia el SOC; cada evento llegaría repetido. Deja solo uno y vuelve a probar.');
    }
    if ($managed === null && count($others) === 1) {
        [$managedKey, $managed, $host] = $others[0];
        $adopted = true;
        $notice = 'Se ha reutilizado el destino syslog «' . ((string)$managed->description ?: $host) . '» que ya existía en el firewall; no se ha creado otro.';
    } elseif (count($others) > 0) {
        $notice = 'Además del destino del panel hay otro destino syslog hacia el SOC creado a mano: los eventos llegarán repetidos. Elimínalo en OPNsense.';
    }
    if ($adopted && (string)$managed->enabled === '1' && (string)$managed->transport === 'udp4') {
        echo json_encode(['status' => 'ok', 'uuid' => $managedKey, 'host' => $host, 'notice' => $notice]);
        exit(0);
    }
    if ($managed === null) { $managed = $model->destinations->destination->add(); }
    $managed->enabled = '1';
    $managed->transport = 'udp4';
    if (!$adopted) {
        $managed->hostname = $host;
        $managed->port = $port;
        $managed->description = $marker;
        $managed->program = '';
        $managed->level = '';
        $managed->facility = '';
        $managed->rfc5424 = '0';
    } else {
        $notice .= ' Se ha activado y pasado a UDP IPv4, que es lo que recibe el SOC.';
    }
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
        $own = $adopted ? (string)$key === $managedKey : (string)$item->description === $marker;
        if ($own && (string)$item->enabled === '1' && soc_address((string)$item->hostname, $known) === $host && (string)$item->port === $port) {
            echo json_encode(['status' => 'ok', 'uuid' => (string)$key, 'host' => $host, 'notice' => $notice]);
            exit(0);
        }
    }
    throw new Exception('No se pudo verificar el destino syslog guardado.');
} catch (Throwable $error) {
    echo json_encode(['status' => 'error', 'message' => substr($error->getMessage(), 0, 300)]);
    exit(1);
}
'''


def _opnsense_ssh(device, connection, destination, port):
    # Antes cada valor iba como JSON entre comillas dobles de PHP, que interpreta `$` y `{$…}`: hoy son una
    # IP y un texto fijo, pero bastaba con añadir un dato escrito por un usuario para ejecutar código.
    params = {"marker": _marker(device), "host": destination, "port": str(port), "known": available_destinations()}
    script = _SSH_PHP.replace("__PARAMS__", base64.b64encode(json.dumps(params).encode("utf-8")).decode("ascii"))
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
    host = result.get("host") if result.get("host") in available_destinations() else destination
    return str(result.get("uuid") or "")[:160], host, str(result.get("notice") or "")[:400]


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
    if (old_ip and identifier != managed_identifier and old_port in ("", "0", str(port))
            and _soc_address(old_ip) and _soc_address(old_ip) != destination):
        # Ya envía al SOC por otra de sus direcciones (pública o privada): se respeta la ruta elegida a mano.
        destination = _soc_address(old_ip)
    if old_ip and (old_ip != destination or old_port not in ("", "0", str(port))) and identifier != managed_identifier:
        raise ProvisionError("UniFi ya exporta a otro servidor SIEM; el panel no cambiará ese destino.")
    wanted = set(UNIFI_CONTENTS)
    existing = {item for item in row.get("contents", []) if isinstance(item, str)}
    if old_ip == destination and old_port == str(port) and row.get("enabled") is True and wanted.issubset(existing):
        return identifier, destination
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
    return identifier, destination


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
    config.notice = ""  # aviso de esta ejecución (destino adoptado o duplicado); no se guarda
    try:
        if device.vendor == Device.Vendor.UNIFI and device.management_method == Device.ManagementMethod.API:
            identifier, config.destination = _unifi_api(device.unifi_cloud, config.destination, PORT, config.remote_identifier)
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
            identifier, config.destination, config.notice = _opnsense_api(device, connection, config.destination, PORT)
        elif device.vendor == Device.Vendor.OPNSENSE and device.management_method == Device.ManagementMethod.SSH:
            connection = device.ssh_connection
            if not connection.last_ok:
                raise ProvisionError("Verifica primero la conexión SSH.")
            identifier, config.destination, config.notice = _opnsense_ssh(device, connection, config.destination, PORT)
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

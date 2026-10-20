"""Read-only UniFi Site Manager access for one configured device."""

import json
import os
import re
from urllib import error, parse, request

from cryptography.fernet import InvalidToken
from .keyring import multifernet


class UnifiCloudError(Exception):
    pass


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _fernet():
    key = os.environ.get("SOC_PORTAL_UNIFI_KEY", "")
    if not key:
        raise UnifiCloudError("Falta la clave de cifrado del panel.")
    try:
        return multifernet(key)
    except (ValueError, UnicodeError) as exc:
        raise UnifiCloudError("La clave de cifrado del panel no es válida.") from exc


def encrypt_api_key(api_key):
    api_key = api_key.strip()
    if not api_key or any(char in api_key for char in "\r\n\t"):
        raise UnifiCloudError("La clave API no es válida.")
    return _fernet().encrypt(api_key.encode("utf-8")).decode("ascii")


def decrypt_api_key(ciphertext):
    try:
        return _fernet().decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except (InvalidToken, UnicodeError, ValueError) as exc:
        raise UnifiCloudError("No se puede leer la clave API guardada.") from exc


def list_sites(api_key):
    if not api_key or any(char in api_key for char in "\r\n\t"):
        raise UnifiCloudError("La clave API no es válida.")
    opener = request.build_opener(_NoRedirect())
    sites = []
    next_token = ""
    for _ in range(10):
        query = {"pageSize": "100"}
        if next_token:
            query["nextToken"] = next_token
        url = "https://api.ui.com/v1/sites?" + parse.urlencode(query)
        req = request.Request(url, headers={"Accept": "application/json", "X-API-Key": api_key})
        try:
            with opener.open(req, timeout=10) as response:
                payload = json.load(response)
        except error.HTTPError as exc:
            if exc.code in (401, 403):
                raise UnifiCloudError("UniFi rechazó la clave API o sus permisos.") from exc
            if exc.code == 429:
                raise UnifiCloudError("UniFi ha limitado temporalmente las consultas. Reinténtalo más tarde.") from exc
            raise UnifiCloudError(f"UniFi devolvió un error HTTP {exc.code}.") from exc
        except (error.URLError, TimeoutError, OSError, ValueError) as exc:
            raise UnifiCloudError("No se pudo consultar UniFi Cloud.") from exc
        if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
            raise UnifiCloudError("UniFi devolvió una respuesta inesperada.")
        for item in payload["data"]:
            if not isinstance(item, dict):
                continue
            site_id = item.get("siteId")
            host_id = item.get("hostId")
            if not isinstance(site_id, str) or not isinstance(host_id, str):
                continue
            meta = item.get("meta") if isinstance(item.get("meta"), dict) else {}
            name = meta.get("desc") or meta.get("name") or site_id
            sites.append({"site_id": site_id, "host_id": host_id, "name": str(name)[:200]})
        new_token = payload.get("nextToken")
        if not new_token:
            return sites
        if not isinstance(new_token, str) or new_token == next_token:
            raise UnifiCloudError("La paginación de UniFi no es válida.")
        next_token = new_token
    raise UnifiCloudError("La cuenta tiene demasiadas sedes para esta consulta.")


def list_host_consoles(api_key):
    """Read console identity for site selection and inventory discovery."""
    opener = request.build_opener(_NoRedirect())
    consoles = {}
    next_token = ""
    for _ in range(10):
        query = {"pageSize": "100"}
        if next_token:
            query["nextToken"] = next_token
        req = request.Request(
            "https://api.ui.com/v1/devices?" + parse.urlencode(query),
            headers={"Accept": "application/json", "X-API-Key": api_key},
        )
        try:
            with opener.open(req, timeout=10) as response:
                payload = json.load(response)
        except (error.HTTPError, error.URLError, TimeoutError, OSError, ValueError) as exc:
            raise UnifiCloudError("No se pudieron descubrir los datos del equipo UniFi.") from exc
        if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
            raise UnifiCloudError("UniFi devolvió datos de equipos inesperados.")
        for host in payload["data"]:
            if not isinstance(host, dict) or not isinstance(host.get("hostId"), str):
                continue
            details = {"host_name": str(host.get("hostName") or "")[:160], "model": "", "software_version": ""}
            for device in host.get("devices", []):
                if isinstance(device, dict) and device.get("isConsole"):
                    details.update({
                        "console_name": str(device.get("name") or "")[:160],
                        "model": str(device.get("model") or "")[:120],
                        "software_version": str(device.get("version") or "")[:120],
                        "serial_number": str(device.get("serialNumber") or device.get("serial") or "")[:120],
                    })
                    break
            consoles[host["hostId"]] = details
        new_token = payload.get("nextToken")
        if not new_token:
            return consoles
        if not isinstance(new_token, str) or new_token == next_token:
            raise UnifiCloudError("La paginación de equipos UniFi no es válida.")
        next_token = new_token
    raise UnifiCloudError("La cuenta tiene demasiados equipos para esta consulta.")


def list_host_names(api_key):
    """Read configured console/server names, including hosts absent from the device list."""
    opener = request.build_opener(_NoRedirect())
    names = {}
    next_token = ""
    for _ in range(10):
        query = {"pageSize": "100"}
        if next_token:
            query["nextToken"] = next_token
        req = request.Request(
            "https://api.ui.com/v1/hosts?" + parse.urlencode(query),
            headers={"Accept": "application/json", "X-API-Key": api_key},
        )
        try:
            with opener.open(req, timeout=10) as response:
                payload = json.load(response)
        except (error.HTTPError, error.URLError, TimeoutError, OSError, ValueError) as exc:
            raise UnifiCloudError("No se pudieron leer los nombres de las consolas UniFi.") from exc
        if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
            raise UnifiCloudError("UniFi devolvió nombres de consolas inesperados.")
        for host in payload["data"]:
            if not isinstance(host, dict) or not isinstance(host.get("id"), str):
                continue
            state = host.get("reportedState") if isinstance(host.get("reportedState"), dict) else {}
            name = state.get("name") or state.get("hostname")
            if isinstance(name, str) and name.strip():
                names[host["id"]] = name.strip()[:160]
        new_token = payload.get("nextToken")
        if not new_token:
            return names
        if not isinstance(new_token, str) or new_token == next_token:
            raise UnifiCloudError("La paginación de consolas UniFi no es válida.")
        next_token = new_token
    raise UnifiCloudError("La cuenta tiene demasiadas consolas para esta consulta.")


def get_console_details(api_key, host_id):
    return list_host_consoles(api_key).get(host_id, {})


def connector_json(api_key, host_id, path, *, method="GET", payload=None):
    if not isinstance(host_id, str) or not re.fullmatch(r"[A-Za-z0-9:-]{1,200}", host_id):
        raise UnifiCloudError("Selecciona una consola UniFi válida.")
    if not path.startswith("/network/api/s/default/") or ".." in path or "?" in path:
        raise UnifiCloudError("Ruta UniFi no permitida.")
    url = f"https://api.ui.com/v1/connector/consoles/{parse.quote(host_id, safe='')}{path}"
    req = request.Request(url, data=json.dumps(payload).encode("utf-8") if payload is not None else None,
                          method=method, headers={"Accept": "application/json", "Content-Type": "application/json", "X-API-Key": api_key})
    try:
        with request.build_opener(_NoRedirect()).open(req, timeout=25) as response:
            result = json.load(response)
            if not isinstance(result, dict):
                raise UnifiCloudError("UniFi devolvió una respuesta inesperada.")
            return result
    except error.HTTPError as exc:
        if exc.code in (401, 403):
            raise UnifiCloudError("La clave de UniFi no permite configurar Activity Logging.") from exc
        raise UnifiCloudError(f"UniFi devolvió HTTP {exc.code} al configurar Activity Logging.") from exc
    except (error.URLError, TimeoutError, OSError, ValueError) as exc:
        raise UnifiCloudError("No se pudo consultar o configurar Activity Logging en UniFi.") from exc


def discover_syslog_source(api_key, host_id, destination):
    """Infer the WAN IP used by an explicit static route to the SOC."""
    import ipaddress

    target = ipaddress.ip_address(destination)
    routes = connector_json(api_key, host_id, "/network/api/s/default/rest/routing").get("data", [])
    networks = connector_json(api_key, host_id, "/network/api/s/default/rest/networkconf").get("data", [])
    devices = connector_json(api_key, host_id, "/network/api/s/default/stat/device").get("data", [])
    if not all(isinstance(rows, list) for rows in (routes, networks, devices)):
        return None
    matches = []
    for route in routes:
        if not isinstance(route, dict) or route.get("enabled") is False:
            continue
        try:
            network = ipaddress.ip_network(str(route.get("static-route_network")), strict=False)
        except ValueError:
            continue
        if target in network:
            matches.append((network.prefixlen, route.get("static-route_interface")))
    if not matches:
        return None
    interface_id = max(matches, key=lambda item: item[0])[1]
    interface = next((item for item in networks if isinstance(item, dict) and item.get("_id") == interface_id), None)
    if not interface or interface.get("purpose") != "wan":
        return None
    group = str(interface.get("wan_networkgroup") or "").lower()
    if group not in ("wan1", "wan2", "wan3"):
        return None
    gateway = next((item for item in devices if isinstance(item, dict) and item.get("type") in ("ugw", "udm")), None)
    value = gateway.get(group) if gateway else None
    candidate = value.get("ip") if isinstance(value, dict) else None
    try:
        source = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    return str(source) if source.version == 4 else None

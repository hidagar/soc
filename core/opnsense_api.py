"""Credential storage and read-only OPNsense API connectivity check."""

import base64
import json
import os
import ssl
from urllib import error, parse, request

from cryptography.fernet import InvalidToken
from .keyring import multifernet


class OpnsenseApiError(Exception):
    pass


# Las tablas de reglas o ARP de un firewall grande caben de sobra; un equipo comprometido no puede agotar la memoria.
MAX_RESPONSE = 16 * 1024 * 1024


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _fernet():
    key = os.environ.get("SOC_PORTAL_OPNSENSE_KEY", "")
    if not key:
        raise OpnsenseApiError("Falta la clave de cifrado de OPNsense en el servidor.")
    try:
        return multifernet(key)
    except (ValueError, UnicodeError) as exc:
        raise OpnsenseApiError("La clave de cifrado de OPNsense no es válida.") from exc


def encrypt_credential(value):
    value = value.strip()
    if not value or len(value) > 512 or any(char in value for char in "\r\n\t"):
        raise OpnsenseApiError("La clave o el secreto API no son válidos.")
    return _fernet().encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_credential(ciphertext):
    try:
        return _fernet().decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except (InvalidToken, UnicodeError, ValueError) as exc:
        raise OpnsenseApiError("No se pueden leer las credenciales guardadas.") from exc


def validate_api_url(value):
    try:
        parsed = parse.urlsplit(value.strip())
        port = parsed.port
    except ValueError as exc:
        raise OpnsenseApiError("La dirección API no es válida.") from exc
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment or port == 0):
        raise OpnsenseApiError("Indica solo la dirección HTTPS de OPNsense, sin ruta ni credenciales.")
    return f"https://{parsed.netloc}"


def validate_ca_certificate(value):
    value = value.strip()
    if len(value) > 20000:
        raise OpnsenseApiError("El certificado CA es demasiado grande.")
    try:
        ssl.create_default_context(cadata=value or None)
    except ssl.SSLError as exc:
        raise OpnsenseApiError("El certificado CA pegado no es válido.") from exc
    return value


def _request_json(api_url, api_key, api_secret, ca_certificate, path, method="GET", payload=None):
    base = validate_api_url(api_url)
    ca_certificate = validate_ca_certificate(ca_certificate)
    credentials = base64.b64encode(f"{api_key}:{api_secret}".encode("utf-8")).decode("ascii")
    context = ssl.create_default_context(cadata=ca_certificate or None)
    opener = request.build_opener(request.HTTPSHandler(context=context), _NoRedirect())
    headers = {"Accept": "application/json", "Authorization": "Basic " + credentials}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    req = request.Request(
        base + path,
        data=json.dumps(payload).encode("utf-8") if payload is not None else None,
        headers=headers,
        method=method,
    )
    try:
        # Applying IDS output settings installs the ruleset and restarts Suricata.
        # Keep regular reads short; this specific operation needs a bounded wait.
        timeout = 60 if method == 'POST' and path == '/api/ids/service/reconfigure' else 10
        with opener.open(req, timeout=timeout) as response:
            if "json" not in response.headers.get("Content-Type", "").lower():
                raise OpnsenseApiError("OPNsense no devolvió JSON en la API.")
            raw = response.read(MAX_RESPONSE + 1)
            if len(raw) > MAX_RESPONSE:
                raise OpnsenseApiError("La respuesta de OPNsense supera el tamaño permitido.")
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                raise OpnsenseApiError("La respuesta API de OPNsense no es válida.")
            return payload
    except error.HTTPError as exc:
        if exc.code in (401, 403):
            raise OpnsenseApiError("OPNsense rechazó las credenciales o los permisos de la cuenta API.") from exc
        raise OpnsenseApiError(f"OPNsense devolvió un error HTTP {exc.code}.") from exc
    except TimeoutError as exc:
        raise OpnsenseApiError("OPNsense no respondió dentro del plazo. Comprueba el estado antes de repetir una operación de configuración.") from exc
    except (error.URLError, OSError, ValueError) as exc:
        raise OpnsenseApiError("No se pudo conectar o validar el certificado HTTPS de OPNsense.") from exc


def _get_json(api_url, api_key, api_secret, ca_certificate, path):
    return _request_json(api_url, api_key, api_secret, ca_certificate, path)


def _post_json(api_url, api_key, api_secret, ca_certificate, path, payload=None):
    return _request_json(api_url, api_key, api_secret, ca_certificate, path, "POST", payload or {})


def check_connection(api_url, api_key, api_secret, ca_certificate=""):
    return _get_json(api_url, api_key, api_secret, ca_certificate, "/api/core/system/status")


def get_firmware_info(api_url, api_key, api_secret, ca_certificate=""):
    return _get_json(api_url, api_key, api_secret, ca_certificate, "/api/core/firmware/info")


def discover_version(payload):
    """Firmware responses differ across OPNsense releases; accept known fields only."""
    for key in ("product_version", "version", "current_version"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()[:120]
    return ""

"""Pinned-host-key SSH access. Never accept an unknown key during authentication."""

import base64
import hashlib
import ipaddress
import os
import socket
from urllib.parse import urlsplit

import paramiko
from cryptography.fernet import InvalidToken
from .keyring import multifernet


class SshConnectionError(Exception):
    pass


def _fernet():
    key = os.environ.get("SOC_PORTAL_SSH_KEY", "")
    if not key:
        raise SshConnectionError("Falta la clave de cifrado SSH en el servidor.")
    try:
        return multifernet(key)
    except (ValueError, UnicodeError) as exc:
        raise SshConnectionError("La clave de cifrado SSH no es válida.") from exc


def encrypt_password(value):
    if not value or len(value) > 1024 or any(c in value for c in "\r\n"):
        raise SshConnectionError("La contraseña SSH no es válida.")
    return _fernet().encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_password(value):
    try:
        return _fernet().decrypt(value.encode("ascii")).decode("utf-8")
    except (InvalidToken, UnicodeError, ValueError) as exc:
        raise SshConnectionError("No se puede leer la contraseña SSH guardada.") from exc


def validate_host(value):
    value = value.strip()
    if value.startswith("https://") or value.startswith("http://"):
        parsed = urlsplit(value)
        if parsed.path not in ("", "/") or parsed.port or parsed.query or parsed.fragment or parsed.username:
            raise SshConnectionError("Indica solo la IP o el nombre del equipo para SSH.")
        value = parsed.hostname or ""
    if not value or len(value) > 253 or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-" for c in value):
        raise SshConnectionError("Indica una IP o un nombre de equipo válido.")
    if value.startswith("-") or value.endswith("-") or ".." in value:
        raise SshConnectionError("Indica una IP o un nombre de equipo válido.")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return value.lower()
    if address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified:
        raise SshConnectionError("Esa dirección no se puede usar para SSH.")
    return value


def validate_port(value):
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise SshConnectionError("El puerto SSH no es válido.") from exc
    if not 1 <= port <= 65535:
        raise SshConnectionError("El puerto SSH no es válido.")
    return port


def fingerprint(key):
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def probe_host_key(host, port):
    host, port = validate_host(host), validate_port(port)
    sock = None
    transport = None
    try:
        sock = socket.create_connection((host, port), timeout=7)
        transport = paramiko.Transport(sock)
        transport.start_client(timeout=7)
        key = transport.get_remote_server_key()
        # Algoritmo de firma negociado: «ssh-rsa» es RSA con SHA-1 (CVE-2026-44405 de paramiko, sin versión
        # corregida). paramiko prefiere rsa-sha2-*: solo se usa si el equipo no admite otro y se avisa.
        return {"type": key.get_name(), "base64": key.get_base64(), "fingerprint": fingerprint(key),
                "algorithm": str(getattr(transport, "host_key_type", "") or "")}
    except (OSError, paramiko.SSHException) as exc:
        raise SshConnectionError("No se pudo obtener la huella SSH del equipo.") from exc
    finally:
        if transport is not None:
            transport.close()
        elif sock is not None:
            sock.close()


def run_command(connection, command, *, stdin_data=None):
    """Only call with a fixed command owned by the backend, never form data."""
    key_info = probe_host_key(connection.hostname, connection.port)
    if key_info["type"] != connection.host_key_type or key_info["base64"] != connection.host_key_base64:
        raise SshConnectionError("La clave SSH del equipo ha cambiado. Revisa la huella antes de continuar.")
    sock = None
    transport = None
    try:
        sock = socket.create_connection((connection.hostname, connection.port), timeout=7)
        transport = paramiko.Transport(sock)
        transport.start_client(timeout=7)
        remote_key = transport.get_remote_server_key()
        if remote_key.get_name() != connection.host_key_type or remote_key.get_base64() != connection.host_key_base64:
            raise SshConnectionError("La clave SSH del equipo ha cambiado durante la conexión.")
        transport.auth_password(connection.username, decrypt_password(connection.encrypted_password), fallback=False)
        if not transport.is_authenticated():
            raise SshConnectionError("OPNsense rechazó la contraseña SSH.")
        channel = transport.open_session(timeout=8)
        channel.settimeout(20)
        channel.exec_command(command)
        if stdin_data is not None:
            channel.sendall(stdin_data)
        channel.shutdown_write()
        stdout = channel.makefile("rb").read(65537)
        stderr = channel.makefile_stderr("rb").read(65537)
        if len(stdout) > 65536 or len(stderr) > 65536:
            raise SshConnectionError("La respuesta SSH supera el límite permitido.")
        status = channel.recv_exit_status()
        return status, stdout.decode("utf-8", errors="replace"), stderr.decode("utf-8", errors="replace")
    except (OSError, EOFError, paramiko.SSHException) as exc:
        raise SshConnectionError("No se pudo autenticar o ejecutar la operación SSH.") from exc
    finally:
        if transport is not None:
            transport.close()
        elif sock is not None:
            sock.close()


def check_connection(connection):
    status, output, _ = run_command(connection, "opnsense-version -v")
    if "This account is currently not available" in output:
        raise SshConnectionError("La contraseña SSH es válida, pero esta cuenta no tiene shell. Activa una shell en OPNsense y permisos para configurar syslog.")
    if status != 0 or not output.strip():
        raise SshConnectionError("SSH conecta, pero el equipo no ejecuta opnsense-version.")
    uid_status, uid_output, _ = run_command(connection, "id -u")
    if uid_status != 0:
        raise SshConnectionError("SSH conecta, pero no permite consultar los permisos de la cuenta.")
    if uid_output.strip() != "0":
        sudo_status, sudo_output, _ = run_command(connection, "sudo -n id -u")
        if sudo_status != 0 or sudo_output.strip() != "0":
            password = decrypt_password(connection.encrypted_password)
            sudo_status, sudo_output, _ = run_command(
                connection, "sudo -k -S -p '' id -u", stdin_data=(password + "\n").encode("utf-8")
            )
            if sudo_status != 0 or sudo_output.strip() != "0":
                raise SshConnectionError("La cuenta SSH necesita pertenecer a administradores y tener sudo activado para configurar syslog.")
    return output.strip().splitlines()[0][:120]


def check_generic_connection(connection):
    status, output, _ = run_command(connection, "uname -s")
    if status != 0 or not output.strip():
        raise SshConnectionError("SSH conecta, pero el equipo no permite ejecutar comandos.")
    return output.strip().splitlines()[0][:120]

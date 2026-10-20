"""GDMS Networking OAuth probe. Fixed vendor hosts, no configuration writes.

Official protocol: https://doc.grandstream.dev/GWN-API/EN/#api-Token
Tokens exist only in memory; never persist a token or a raw cloud response.
"""
import hashlib
import json
import time
from urllib import request, parse, error
from .ssh_connection import encrypt_password, decrypt_password, SshConnectionError

HOSTS = {'eu': 'https://eu.gwn.cloud', 'us': 'https://www.gwn.cloud'}
MAX_RESPONSE = 65536


class GdmsError(Exception):
    pass


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def encrypt(value):
    try:
        return encrypt_password(value)
    except SshConnectionError:
        raise GdmsError('No se pueden cifrar las credenciales. Revisa la configuración del servidor.') from None


def decrypt(value):
    try:
        return decrypt_password(value)
    except SshConnectionError:
        raise GdmsError('No se pueden leer las credenciales guardadas. Vuelve a introducirlas.') from None


def credential(value, label):
    if not isinstance(value, str) or not value or len(value) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise GdmsError(f'Indica {label} válido, sin saltos de línea.')
    return value


def access_token(region, app_id, secret, restricted=False, username='', password=''):
    if region not in HOSTS:
        raise GdmsError('Selecciona una región admitida de GDMS Networking.')
    params = {'grant_type': 'password' if restricted else 'client_credentials',
              'client_id': credential(app_id, 'un APP ID'), 'client_secret': credential(secret, 'un Secret Key')}
    if restricted:
        params['username'] = credential(username, 'un usuario')
        password = credential(password, 'una contraseña')
        # Grandstream's documented protocol, not a password storage algorithm.
        params['password'] = hashlib.sha256(hashlib.md5(password.encode()).hexdigest().encode('ascii')).hexdigest()
    req = request.Request(HOSTS[region] + '/oauth/token?' + parse.urlencode(params),
                          headers={'Accept': 'application/json'}, method='GET')
    try:
        with request.build_opener(NoRedirect()).open(req, timeout=10) as response:
            if response.headers.get_content_type() != 'application/json':
                raise GdmsError('GDMS no devolvió una respuesta API válida. Comprueba la región.')
            raw = response.read(MAX_RESPONSE + 1)
        if len(raw) > MAX_RESPONSE:
            raise GdmsError('GDMS devolvió una respuesta demasiado grande.')
        payload = json.loads(raw)
    except error.HTTPError as exc:
        code = exc.code
        exc.close()
        if code in (400, 401, 403):
            raise GdmsError('GDMS rechazó las credenciales. Revisa APP ID, Secret Key, región y la restricción por redes.') from None
        if code == 429:
            raise GdmsError('GDMS ha limitado las consultas. Espera antes de volver a comprobar.') from None
        raise GdmsError('No se pudo comprobar GDMS. Comprueba la región y vuelve a intentarlo.') from None
    except (error.URLError, TimeoutError, OSError, ValueError):
        raise GdmsError('No se pudo conectar con GDMS mediante HTTPS o interpretar su respuesta.') from None
    if not isinstance(payload, dict) or payload.get('error'):
        raise GdmsError('GDMS rechazó la autenticación. Revisa las credenciales y sus permisos.')
    token = payload.get('access_token')
    expiry = payload.get('expires_in')
    if (not isinstance(token, str) or not token or len(token) > 8192 or
            str(payload.get('token_type', '')).lower() != 'bearer' or
            isinstance(expiry, bool) or not isinstance(expiry, (int, float)) or not 0 < expiry < 31536000):
        raise GdmsError('GDMS no devolvió una autorización válida.')
    # Authentication alone does not establish a physical device binding or logs.
    return token


def check_connection(region, app_id, secret, restricted=False, username='', password=''):
    access_token(region, app_id, secret, restricted, username, password)
    return True


def read_inventory(region, app_id, secret, token, path, body):
    if region not in HOSTS or path not in ('v1.0.0/inventory/list', 'v2.0.0/ap/info'):
        raise GdmsError('Consulta de inventario GDMS no admitida.')
    raw = json.dumps(body, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    params = {'appID': app_id, 'secretKey': secret, 'timestamp': str(int(time.time() * 1000))}
    # With Authorization: Bearer, token is excluded from signature per vendor spec.
    material = '&' + '&'.join(k + '=' + params[k] for k in sorted(params)) + '&' + hashlib.sha256(raw).hexdigest() + '&'
    query = {'appID': app_id, 'timestamp': params['timestamp'], 'signature': hashlib.sha256(material.encode()).hexdigest()}
    req = request.Request(HOSTS[region] + '/oapi/' + path + '?' + parse.urlencode(query), data=raw,
        headers={'Accept': 'application/json', 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token}, method='POST')
    try:
        with request.build_opener(NoRedirect()).open(req, timeout=10) as response:
            data = response.read(1048577)
        if len(data) > 1048576: raise GdmsError('El inventario GDMS supera el límite de consulta.')
        result = json.loads(data)
    except (error.URLError, TimeoutError, OSError, ValueError):
        raise GdmsError('No se pudo leer el inventario GDMS. Revisa permisos y región.') from None
    if not isinstance(result, dict) or type(result.get('retCode')) is not int or result['retCode'] != 0:
        raise GdmsError('GDMS no confirmó la consulta de inventario.')
    return result.get('data')


def discover_device(connection, mac):
    from .device_identity import normalize_mac
    from django.core.exceptions import ValidationError
    mac = normalize_mac(mac)
    if not mac: raise GdmsError('Registra la MAC del GCC para identificarlo en GDMS.')
    secret = decrypt(connection.encrypted_secret)
    token = access_token(connection.region, connection.app_id, secret, connection.restricted, connection.username,
                         decrypt(connection.encrypted_password) if connection.restricted else '')
    rows = read_inventory(connection.region, connection.app_id, secret, token, 'v1.0.0/inventory/list',
                          {'search': mac, 'pageNum': 1, 'pageSize': 100})
    if isinstance(rows, dict):
        # Current GDMS wraps inventory in a paginated result, unlike older docs.
        page = rows
        rows = page.get('result')
        if (type(page.get('total')) is not int or page['total'] < 0 or
                type(page.get('totalPage')) is not int or page['totalPage'] not in (0, 1) or
                page.get('currentPage') != 1 or not isinstance(rows, list) or page['total'] != len(rows)):
            raise GdmsError('La búsqueda por MAC de GDMS está incompleta. Revisa la identificación del equipo.')
    if not isinstance(rows, list) or len(rows) >= 100:
        raise GdmsError('El inventario no permite identificar una MAC de forma inequívoca.')
    matched = []
    for row in rows:
        if not isinstance(row, dict): raise GdmsError('GDMS devolvió un inventario no válido.')
        try: same = normalize_mac(row.get('mac')) == mac
        except ValidationError: same = False
        if same: matched.append(row)
    if len(matched) != 1:
        raise GdmsError('No hay una coincidencia única con la MAC registrada. Revisa MAC, cuenta y permisos de GDMS.')
    row = matched[0]
    details = {'model': row.get('model'), 'serial_number': row.get('serialNumber')}
    # This endpoint identifies its response by MAC; never select the first device.
    try:
        info = read_inventory(connection.region, connection.app_id, secret, token, 'v2.0.0/ap/info',
                              {'mac': [mac.replace(':', '').lower()]})
        if isinstance(info, dict) and normalize_mac(info.get('mac')) == mac:
            details['software_version'] = info.get('firmwareVersion')
            if info.get('apType'): details['model'] = info['apType']
    except (GdmsError, ValidationError):
        # Inventory identity can still be useful where detail API is unsupported.
        pass
    return details

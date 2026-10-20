"""StoneOS REST login and bounded inventory discovery; no configuration writes.

Protocol: Hillstone REST API testing (5.5R6P9), /rest/login, base64
userName/password. Other firmware profiles require vendor documentation.
"""
import base64
import json
import ssl
from urllib import request, error
from .opnsense_api import validate_api_url, validate_ca_certificate, OpnsenseApiError
from .ssh_connection import encrypt_password, decrypt_password, SshConnectionError

class HillstoneApiError(Exception):
    pass

class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None

def validate_url(value):
    try:
        return validate_api_url(value)
    except OpnsenseApiError:
        raise HillstoneApiError('Indica la dirección HTTPS de Hillstone, sin ruta ni credenciales.') from None

def validate_ca(value):
    try:
        return validate_ca_certificate(value)
    except OpnsenseApiError:
        raise HillstoneApiError('El certificado CA no es válido.') from None

def encrypt(value):
    try:
        return encrypt_password(value)
    except SshConnectionError:
        raise HillstoneApiError('No se pueden guardar las credenciales cifradas. Revisa los datos y la clave de cifrado del servidor.') from None

def decrypt(value):
    try:
        return decrypt_password(value)
    except SshConnectionError:
        raise HillstoneApiError('No se pueden leer las credenciales guardadas.') from None

def username(value):
    value=value.strip()
    if not value or len(value)>120 or any(ord(c)<32 for c in value):
        raise HillstoneApiError('Indica un usuario válido.')
    return value

def inventory(payload):
    if not isinstance(payload,dict) or payload.get('success') is not True:
        raise HillstoneApiError('Hillstone rechazó el acceso o no reconoce el perfil REST. Comprueba usuario, permisos y versión de StoneOS.')
    result=payload.get('result')
    # StoneOS 5.5R10P5 returns one session in a list, without inventory.
    if isinstance(result,list) and len(result)==1:
        result=result[0]
    if not isinstance(result,dict) or not isinstance(result.get('token'),str) or not result['token']:
        raise HillstoneApiError('Hillstone no devolvió una sesión REST válida.')
    info=result.get('sysInfo')
    if info is None:
        return {}
    if not isinstance(info,dict):
        raise HillstoneApiError('La sesión no incluye el inventario esperado. Revisa el perfil de StoneOS.')
    # Allowlist: never persist token, raw payload, or configuration.
    out={}
    for target,source,limit in (('model','hw_platform',120),('software_version','sw_version',120),('serial_number','sn_number',120)):
        value=info.get(source)
        if isinstance(value,str) and value.strip():
            out[target]=''.join(c for c in value.strip() if ord(c)>=32)[:limit]
    if not out:
        raise HillstoneApiError('No se encontraron datos de inventario compatibles en la respuesta REST.')
    return out

def check_connection(api_url, user, password, ca_certificate=''):
    base=validate_url(api_url)
    ca=validate_ca(ca_certificate)
    user=username(user)
    if not password or len(password)>1024:
        raise HillstoneApiError('Indica una contraseña válida.')
    encoded=lambda value: base64.b64encode(value.encode('utf-8')).decode('ascii')
    payload={'lang':'en_US','userName':encoded(user),'password':encoded(password)}
    opener=request.build_opener(request.ProxyHandler({}),request.HTTPSHandler(context=ssl.create_default_context(cadata=ca or None)),NoRedirect())
    req=request.Request(base+'/rest/login',data=json.dumps(payload).encode(),headers={'Accept':'application/json','Content-Type':'application/json'},method='POST')
    try:
        with opener.open(req,timeout=10) as response:
            if 'json' not in response.headers.get('Content-Type','').lower():
                raise HillstoneApiError('El destino no devuelve JSON REST de Hillstone. Revisa la dirección y la versión.')
            body=response.read(262145)
            if len(body)>262144:
                raise HillstoneApiError('La respuesta REST excede el tamaño permitido.')
            return inventory(json.loads(body))
    except error.HTTPError as exc:
        if exc.code in (401,403):
            raise HillstoneApiError('Hillstone rechazó las credenciales o el origen de gestión autorizado.') from None
        raise HillstoneApiError(f'Error HTTP {exc.code}. Revisa el acceso REST y la versión.') from None
    except (error.URLError,TimeoutError,OSError,ValueError):
        raise HillstoneApiError('No se pudo conectar o validar el certificado HTTPS. Revisa ruta, puerto, CA y nombre del certificado.') from None

"""Adjuntos de las solicitudes al SOC: capturas, PDF, registros de texto y correos sospechosos.

- Tipos admitidos por extensión **y** por contenido (cabecera del archivo; los de texto, sin bytes nulos).
  Nada ejecutable, comprimido ni de Office: lo que no se reconoce se rechaza con un mensaje claro.
- Como mucho 3 archivos por mensaje, 20 por solicitud y un tamaño total por mensaje que cabe en el límite
  de Nginx (`client_max_body_size 2m`): `SOC_PORTAL_ATTACHMENTS_MAX_MB`, 1,8 por defecto. Subirlo exige
  subir también ese límite de Nginx en los dos bloques del portal.
- Se guardan cifrados en la base con la bóveda del SOC y se borran con su solicitud (conservación).
- La descarga siempre es un archivo (nunca se abre en el navegador), con la cabecera del tipo genérico,
  `nosniff` y sin caché. El cliente solo descarga los de su solicitud y nunca los de notas internas.
- Antivirus: ClamAV los analiza en segundo plano (`core/antivirus.py`). Con una amenaza, el cliente no puede
  descargarlo y el SOC solo como muestra, confirmándolo (queda en la auditoría).
"""
import hashlib
import os
import re
import unicodedata
from urllib.parse import quote

from django.contrib.auth.decorators import login_required
from django.http import Http404, HttpResponse, HttpResponseForbidden
from django.shortcuts import get_object_or_404
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET

from .models import CustomerRequestAttachment
from .security import audit, vault

MAX_FILES = 3
MAX_PER_REQUEST = 20
DEFAULT_MAX_MB = 1.8
TEXT_KINDS = ('txt', 'log', 'csv', 'eml')
ALLOWED = {
    'png': ('image/png', (b'\x89PNG\r\n\x1a\n',)),
    'jpg': ('image/jpeg', (b'\xff\xd8\xff',)),
    'jpeg': ('image/jpeg', (b'\xff\xd8\xff',)),
    'gif': ('image/gif', (b'GIF87a', b'GIF89a')),
    'webp': ('image/webp', (b'RIFF',)),
    'pdf': ('application/pdf', (b'%PDF-',)),
    'msg': ('application/vnd.ms-outlook', (b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1',)),
    'txt': ('text/plain', ()),
    'log': ('text/plain', ()),
    'csv': ('text/csv', ()),
    'eml': ('message/rfc822', ()),
}
ACCEPT = ','.join('.' + ext for ext in ALLOWED)
CONTROL = re.compile(r'[\x00-\x1f\x7f]')


def max_bytes():
    try:
        value = float(os.environ.get('SOC_PORTAL_ATTACHMENTS_MAX_MB', DEFAULT_MAX_MB))
    except ValueError:
        value = DEFAULT_MAX_MB
    return int(min(max(value, 0.1), 50) * 1024 * 1024)


def limits_text():
    mb = f'{max_bytes() / 1024 / 1024:.1f}'.replace('.', ',').replace(',0', '')
    return f'Hasta {MAX_FILES} archivos y {mb} MB en total: imágenes, PDF, texto o correos (.eml, .msg).'


def safe_name(raw):
    """Nombre para mostrar y para la descarga: sin rutas ni caracteres de control, acotado y con su extensión."""
    name = unicodedata.normalize('NFKC', os.path.basename(str(raw or '').replace('\\', '/')))
    name = CONTROL.sub('', name).strip().strip('.') or 'adjunto'
    stem, dot, ext = name.rpartition('.')
    if dot and len(name) > 120:
        name = stem[:120 - len(ext) - 1] + '.' + ext
    return name[:120]


def _kind(name):
    return name.rpartition('.')[2].lower() if '.' in name else ''


def clean(files, existing=0):
    """Valida los archivos subidos. Devuelve (lista de adjuntos listos, error en español o '')."""
    files = [f for f in files if f]
    if not files:
        return [], ''
    if len(files) > MAX_FILES:
        return [], f'Como máximo {MAX_FILES} archivos por mensaje.'
    if existing + len(files) > MAX_PER_REQUEST:
        return [], f'Esta solicitud ya tiene {existing} adjuntos; el máximo es {MAX_PER_REQUEST}.'
    limit = max_bytes()
    if sum(f.size for f in files) > limit:
        return [], limits_text().replace('Hasta', 'Se admiten hasta')
    ready = []
    for upload in files:
        name = safe_name(upload.name)
        kind = _kind(name)
        if kind not in ALLOWED:
            return [], f'«{name}»: tipo de archivo no admitido. {limits_text()}'
        data = upload.read(limit + 1)
        if not data:
            return [], f'«{name}» está vacío.'
        content_type, signatures = ALLOWED[kind]
        if kind in TEXT_KINDS:
            valid = b'\x00' not in data
        else:
            valid = any(data.startswith(sig) for sig in signatures) and (kind != 'webp' or data[8:12] == b'WEBP')
        if not valid:
            return [], f'«{name}» no parece un archivo .{kind} válido.'
        ready.append({'name': name, 'content_type': content_type, 'size': len(data), 'data': data,
                      'sha256': hashlib.sha256(data).hexdigest()})
    return ready, ''


def store(entry, ready, user):
    """Guarda cifrados los adjuntos validados de un mensaje (dentro de la transacción del mensaje)."""
    box = vault()
    for item in ready:
        CustomerRequestAttachment.objects.create(entry=entry, name=item['name'], content_type=item['content_type'],
                                                 size=item['size'], sha256=item['sha256'],
                                                 encrypted_data=box.encrypt(item['data']), uploaded_by=user)


def _download(item):
    data = vault().decrypt(bytes(item.encrypted_data))
    ascii_name = unicodedata.normalize('NFKD', item.name).encode('ascii', 'ignore').decode() or 'adjunto'
    ascii_name = re.sub(r'[^A-Za-z0-9._ -]', '_', ascii_name)
    response = HttpResponse(data, content_type='application/octet-stream')
    response['Content-Disposition'] = f'attachment; filename="{ascii_name}"; filename*=UTF-8\'\'{quote(item.name)}'
    response['X-Content-Type-Options'] = 'nosniff'
    response['Content-Security-Policy'] = "sandbox; default-src 'none'"
    response['Cache-Control'] = 'no-store, private'
    return response


@login_required
@never_cache
@require_GET
def customer_download(request, pk, attachment):
    from .service_development import customer_client
    client = customer_client(request)
    item = get_object_or_404(CustomerRequestAttachment.objects.select_related('entry__request'), pk=attachment,
                             entry__request_id=pk, entry__request__client=client)
    if item.entry.kind == 'internal':
        raise Http404  # invariante 3: lo interno no existe para el cliente
    if item.scan_status == 'infected':
        return HttpResponseForbidden('El antivirus ha bloqueado este archivo. El equipo SOC ya está avisado.')
    return _download(item)


@login_required
@never_cache
@require_GET
def soc_download(request, pk, attachment):
    item = get_object_or_404(CustomerRequestAttachment.objects.select_related('entry__request'), pk=attachment,
                             entry__request_id=pk)
    if item.scan_status == 'infected':
        if request.GET.get('muestra') != '1':
            return HttpResponseForbidden('Archivo con malware: descárgalo solo como muestra, desde el enlace de la conversación.')
        audit('request.attachment_download', item.entry.request, {'count': 1, 'reason': 'muestra con malware'})
        return _download(item)
    audit('request.attachment_download', item.entry.request, {'count': 1})
    return _download(item)

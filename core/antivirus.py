"""Antivirus de los adjuntos de las solicitudes: ClamAV (`clamd`) en la propia VM, por su socket local.

- El trabajo `attachment_scan` (cada minuto) analiza los adjuntos en cola, como mucho 20 por pasada,
  con el protocolo INSTREAM: el archivo descifrado va al demonio local y no sale del servidor.
- Resultado por adjunto: sin amenazas, amenaza detectada (con la firma) o, si ClamAV no está instalado,
  sin analizar. Los «sin analizar» se analizan en cuanto ClamAV esté disponible.
- Con una amenaza: nota interna en la solicitud, novedad para el equipo SOC (su correo interno) y
  auditoría. El cliente no puede descargar el archivo; el SOC solo como muestra, confirmándolo.
- «Salud del SOC» (`platform:antivirus`): ClamAV configurado o instalado que no responde con adjuntos
  esperando más de 15 minutos, o base de firmas con más de 3 días.

`SOC_PORTAL_CLAMD_SOCKET` indica el socket; por defecto el de Debian/Ubuntu (`/run/clamav/clamd.ctl`).
"""
import os
import socket
import struct
from datetime import datetime, timedelta

from django.db import transaction
from django.utils import timezone

from .models import CustomerRequest, CustomerRequestAttachment, CustomerRequestEntry, OperationalIssue
from .security import audit, vault

DEFAULT_SOCKET = '/run/clamav/clamd.ctl'
ISSUE = 'platform:antivirus'
CHUNK = 64 * 1024
TIMEOUT = 30
PER_RUN = 20
WAIT = timedelta(minutes=15)
DB_MAX_AGE = timedelta(days=3)


class AntivirusError(Exception):
    pass


def socket_path():
    return os.environ.get('SOC_PORTAL_CLAMD_SOCKET', '').strip() or DEFAULT_SOCKET


def configured():
    """Se espera un antivirus: la variable está puesta o el socket existe (ClamAV instalado)."""
    return bool(os.environ.get('SOC_PORTAL_CLAMD_SOCKET', '').strip()) or os.path.exists(DEFAULT_SOCKET)


def _command(payload_writer):
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(TIMEOUT)
            conn.connect(socket_path())
            payload_writer(conn)
            reply = b''
            while not reply.endswith(b'\0') and len(reply) < 4096:
                block = conn.recv(4096)
                if not block:
                    break
                reply += block
    except OSError as exc:
        raise AntivirusError('ClamAV no responde en su socket.') from exc
    return reply.rstrip(b'\0\n').decode('utf-8', 'replace')


def version():
    """«ClamAV 1.0.7/27450/Sun Nov 22 09:29:35 2026»: versión, base de firmas y su fecha."""
    return _command(lambda conn: conn.sendall(b'zVERSION\0'))[:120]


def signatures_date(text):
    parts = text.split('/')
    if len(parts) < 3:
        return None
    try:
        return timezone.make_aware(datetime.strptime(parts[2].strip(), '%a %b %d %H:%M:%S %Y'))
    except ValueError:
        return None


def scan(data):
    """Analiza bytes con INSTREAM. Devuelve ('clean', '') o ('infected', firma); AntivirusError si falla."""
    def send(conn):
        conn.sendall(b'zINSTREAM\0')
        for start in range(0, len(data), CHUNK):
            block = data[start:start + CHUNK]
            conn.sendall(struct.pack('!L', len(block)) + block)
        conn.sendall(struct.pack('!L', 0))
    reply = _command(send)
    if reply.endswith(' OK'):
        return 'clean', ''
    if reply.endswith(' FOUND'):
        return 'infected', reply.split(': ', 1)[-1][:-len(' FOUND')][:200]
    raise AntivirusError('ClamAV no pudo analizar el archivo.')  # p. ej. «INSTREAM size limit exceeded»


def _infected(item, signature, now):
    req = item.entry.request
    with transaction.atomic():
        CustomerRequestEntry.objects.create(
            request=req, kind='internal', author=None, status=req.status, created_at=now,
            text=f'ClamAV ha detectado «{signature}» en el adjunto «{item.name}». El cliente no puede descargarlo; '
                 'el SOC solo como muestra, en un equipo de análisis.')
        CustomerRequest._base_manager.filter(pk=req.pk).update(updated_at=now, soc_notified_at=None)  # novedad para el SOC
        audit('request.attachment_infected', req, {'count': 1})


def scan_pending(now=None):
    """Trabajo `attachment_scan`. Devuelve cuántos adjuntos ha analizado."""
    from .operations import set_issue
    now = now or timezone.now()
    manager = CustomerRequestAttachment._base_manager
    waiting = manager.filter(scan_status__in=('pending', 'unscanned')).select_related('entry__request')
    if not configured():
        # Sin ClamAV: queda constancia en cada adjunto y no hay aviso (es una decisión de instalación).
        manager.filter(scan_status='pending').update(scan_status='unscanned')
        OperationalIssue.objects.filter(key=ISSUE, active=True).update(active=False, resolved_at=now)
        return 0
    try:
        engine = version()
    except AntivirusError:
        oldest = waiting.order_by('created_at').values_list('created_at', flat=True).first()
        if oldest and now - oldest > WAIT:
            set_issue(ISSUE, 'Antivirus de adjuntos sin respuesta', now=now,
                      details='ClamAV no responde en ' + socket_path() + ' y hay adjuntos de solicitudes sin analizar. '
                              'Revisar «systemctl status clamav-daemon» (necesita memoria libre).')
        return 0
    checked = 0
    box = vault()
    for item in list(waiting.order_by('created_at', 'pk')[:PER_RUN]):
        try:
            status, signature = scan(box.decrypt(bytes(item.encrypted_data)))
        except AntivirusError:
            continue  # se reintenta en la próxima pasada
        if manager.filter(pk=item.pk, scan_status=item.scan_status).update(
                scan_status=status, scan_result=signature, scan_engine=engine, scanned_at=now):
            checked += 1
            if status == 'infected':
                _infected(item, signature, now)
    stamp = signatures_date(engine)
    if stamp and now - stamp > DB_MAX_AGE:
        set_issue(ISSUE, 'Antivirus de adjuntos con firmas antiguas', now=now,
                  details=f'La base de firmas de ClamAV es del {timezone.localtime(stamp):%d/%m/%Y}. '
                          'Revisar «systemctl status clamav-freshclam».')
    else:
        OperationalIssue.objects.filter(key=ISSUE, active=True).update(active=False, resolved_at=now)
    return checked

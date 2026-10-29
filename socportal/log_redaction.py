"""Oculta los secretos que viajan en la URL antes de escribirla en un registro.

Tres rutas llevan el secreto en la propia URL, porque quien la abre no puede enviar cabeceras:
- /reports/<token>/ y /reports/<token>/pdf/: el enlace del informe del cliente (90 días, sin login);
- /feeds/bloqueo/<cliente>/<token>/ (y /salida/): la lista que descarga cada firewall cada hora;
- /activate/<usuario>/<token>/: la invitación; con ella se pone la contraseña de una cuenta nueva.

Django usa `RedactingFormatter` (settings.LOGGING); Nginx, las mismas reglas en
deploy/nginx/soc-log-redaction.conf; gunicorn no guarda registro de accesos (deploy/gunicorn.conf.py).
"""
import logging
import re

HIDDEN = '[oculto]'
# Los tokens son largos (≥ 40 caracteres): `{20,}` deja intactas /reports/health/ y /activate/<id>/set-password/.
PATTERNS = (
    re.compile(r'(/reports/)[^/\s"?]{20,}'),
    re.compile(r'(/feeds/bloqueo/\d+/)[^/\s"?]+'),
    re.compile(r'(/activate/\d+/)[^/\s"?]{20,}'),
)


def redact(text):
    for pattern in PATTERNS:
        text = pattern.sub(r'\g<1>' + HIDDEN, text)
    return text


class RedactingFormatter(logging.Formatter):
    """Formatea como siempre (mensaje y traza) y oculta después los secretos de URL."""

    def format(self, record):
        return redact(super().format(record))

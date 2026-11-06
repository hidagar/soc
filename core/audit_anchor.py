"""Anclaje externo de la auditoría (bloque 8): detectar que se borre el final de la cadena.

- **Envío:** una vez al día (trabajo «Conservación y limpieza»), el SOC guarda y envía por correo, fuera de
  la VM, el número del último evento de auditoría, su huella (resumen HMAC de la cadena) y el número de
  eventos hasta él. Destinatario: `SOC_PORTAL_AUDIT_ANCHOR_EMAIL` o, si no hay, la copia de informes
  (NOC). Es un solo intento por día: si falla, el día siguiente va otra ancla.
- **Comprobación automática:** cada ancla enviada debe seguir coincidiendo: el evento existe con la misma
  huella y hay los mismos eventos hasta él. Si no, se abre un aviso crítico en «Salud del SOC».
- **Comprobación a mano:** quien borrase la auditoría podría borrar también las anclas de la base. Por eso
  «Auditoría» permite pegar el número y la huella de un correo y comprobarlos.

La huella no es secreta (no permite firmar eventos); el correo no lleva ningún otro dato de la auditoría.
"""
import os
from datetime import timedelta

from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.template.loader import render_to_string
from django.utils import timezone

from .models import AuditAnchor, AuditEvent, MailSettings, OperationalIssue

EVERY = timedelta(hours=24)
STALE = timedelta(days=3)
ISSUE_BROKEN = 'platform:audit-anchor'
ISSUE_MISSING = 'platform:audit-anchor-missing'


def recipient():
    configured = os.environ.get('SOC_PORTAL_AUDIT_ANCHOR_EMAIL', '').strip()
    config = MailSettings.objects.order_by('pk').first()
    for value in (configured, config.report_copy_email if config else ''):
        try:
            validate_email(value)
            return value
        except ValidationError:
            continue
    return ''


def head():
    """(último evento, número de eventos hasta él) o (None, 0) si la auditoría está vacía."""
    last = AuditEvent.objects.order_by('-pk').first()
    return (last, AuditEvent.objects.filter(pk__lte=last.pk).count()) if last else (None, 0)


def send_anchor(now=None, force=False):
    """Crea y envía el ancla del día. Devuelve el ancla creada o None si aún no toca."""
    from .mail_delivery import MailConfigurationError, MailDeliveryError, send_customer_email
    now = now or timezone.now()
    previous = AuditAnchor.objects.order_by('-created_at').first()
    if not force and previous and now - previous.created_at < EVERY:
        return None
    event, count = head()
    address = recipient()
    if not event or not address:
        return None
    anchor = AuditAnchor.objects.create(created_at=now, event_id=event.pk, digest=event.digest, event_count=count,
                                        recipient=address)
    context = {'anchor': anchor, 'event_at': event.created_at}
    try:
        provider = send_customer_email(address, f'ib-red SOC · Ancla de auditoría · {timezone.localtime(now):%d/%m/%Y}',
                                       render_to_string('audit_anchor_email.txt', context),
                                       render_to_string('audit_anchor_email.html', context),
                                       delivery_context={'kind': 'audit'})
    except MailConfigurationError:
        AuditAnchor.objects.filter(pk=anchor.pk).update(status='failed', error='El correo del SOC no está configurado y probado.')
    except MailDeliveryError:
        AuditAnchor.objects.filter(pk=anchor.pk).update(status='uncertain', error='SendGrid no confirmó la aceptación.')
    except Exception:
        AuditAnchor.objects.filter(pk=anchor.pk).update(status='failed', error='No se pudo preparar el correo.')
    else:
        AuditAnchor.objects.filter(pk=anchor.pk).update(status='accepted', provider_id=str(provider)[:180])
    anchor.refresh_from_db()
    return anchor


def matches(event_id, digest):
    """¿La auditoría conserva ese evento con esa huella? (y, si se conoce, el número de eventos hasta él)."""
    return AuditEvent.objects.filter(pk=event_id, digest=digest).exists()


def broken_anchors():
    """Anclas enviadas que la auditoría actual ya no cumple."""
    bad = []
    for anchor in AuditAnchor.objects.exclude(status='failed').order_by('event_id'):
        if not matches(anchor.event_id, anchor.digest) or AuditEvent.objects.filter(pk__lte=anchor.event_id).count() != anchor.event_count:
            bad.append(anchor)
    return bad


def check(now=None):
    """Trabajo diario: comprueba las anclas, envía la del día y mantiene los avisos al día."""
    from .operations import set_issue
    now = now or timezone.now()
    bad = broken_anchors()
    if bad:
        first = bad[0]
        set_issue(ISSUE_BROKEN, 'La auditoría no coincide con un ancla enviada fuera del SOC', severity='critical', now=now,
                  details=f'El ancla del {timezone.localtime(first.created_at):%d/%m/%Y} fijaba el evento {first.event_id} '
                          f'con {first.event_count} eventos hasta él, y la auditoría actual ya no lo cumple: se han borrado '
                          'o alterado eventos. Revisar el acceso a la base antes de seguir.')
    else:
        OperationalIssue.objects.filter(key=ISSUE_BROKEN, active=True).update(active=False, resolved_at=now)
    anchor = send_anchor(now)
    accepted = AuditAnchor.objects.filter(status='accepted').order_by('-created_at').first()
    if not recipient():
        problem = 'No hay destinatario para el ancla diaria: indica SOC_PORTAL_AUDIT_ANCHOR_EMAIL o la copia de informes en Correo del SOC.'
    elif AuditEvent.objects.exists() and (not accepted or now - accepted.created_at > STALE):
        problem = 'Lleva más de 3 días sin enviarse un ancla de auditoría. Revisar el correo del SOC.'
    else:
        problem = ''
    if problem:
        set_issue(ISSUE_MISSING, 'Ancla externa de auditoría pendiente', now=now, details=problem)
    else:
        OperationalIssue.objects.filter(key=ISSUE_MISSING, active=True).update(active=False, resolved_at=now)
    return anchor

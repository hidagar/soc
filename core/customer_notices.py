"""Avisos por correo al cliente cuando el SOC le asigna, devuelve o valida una actuación (hoja de ruta 6).

- Se encolan al guardar una actuación publicada en el portal (`queue_for_change`), solo si el cliente
  los tiene activados («Avisar por correo de las actuaciones del portal»).
- Los envía el trabajo «Avisos operativos» (`send_pending`). El correo lleva solo el título, la fecha
  acordada y el enlace al portal, donde se entra con MFA: nunca instrucciones, notas internas ni datos
  técnicos (invariante 3).
- La aceptación de SendGrid no acredita la entrega (invariante 6): el estado de entrega se sigue en
  «Entrega y avisos» con su MailDispatch. Un error de red queda «por comprobar» y no se reintenta solo.
"""
from datetime import timedelta

from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils import timezone

from .models import CustomerNotice

SUBJECTS = {'assigned': 'Nueva actuación en el Centro SOC', 'rework': 'Actuación pendiente de completar',
            'accepted': 'Actuación validada por el SOC'}
STATUS_FOR = {'assigned': 'pending', 'rework': 'rework', 'accepted': 'accepted'}


def recipient(client):
    for value in (client.task_email, client.contact_email, client.report_email):
        try:
            validate_email(value)
            return value
        except ValidationError:
            continue
    return ''


def change_kind(before, task):
    """Qué aviso corresponde a un cambio: (estado y visibilidad antes) → tarea guardada."""
    was_status, was_visible = before
    if not task.visible:
        return None
    if task.status == 'pending' and not (was_visible and was_status == 'pending'):
        return 'assigned'
    if task.status in ('rework', 'accepted') and (task.status != was_status or not was_visible):
        return 'rework' if task.status == 'rework' else 'accepted'
    return None


def queue_for_change(before, task):
    client = task.incident.client
    kind = change_kind(before, task)
    address = recipient(client)
    if not kind or not client.task_notices_enabled or not client.active or not address:
        return None
    return CustomerNotice.objects.create(client=client, task=task, kind=kind, recipient=address)


def portal_url(task):
    from .invitations import origin
    return origin() + reverse('customer_task_reply', args=[task.pk])


def send_pending(limit=5, now=None):
    from .mail_delivery import MailConfigurationError, MailDeliveryError, send_customer_email
    now = now or timezone.now()
    # Un proceso cortado a mitad deja «enviando»: puede haber salido, así que no se repite solo.
    CustomerNotice._base_manager.filter(status='sending', attempted_at__lt=now - timedelta(minutes=10)).update(
        status='uncertain', error='El envío se interrumpió; comprobar en «Entrega y avisos» antes de reenviar.')
    sent = 0
    for notice in (CustomerNotice._base_manager.filter(status='queued').select_related('client', 'task__incident')
                   .order_by('created_at', 'pk')[:limit]):
        task = notice.task
        if (not notice.client.active or not notice.client.task_notices_enabled or not task.visible
                or task.status != STATUS_FOR[notice.kind]):
            CustomerNotice._base_manager.filter(pk=notice.pk, status='queued').update(
                status='skipped', error='La actuación cambió antes del envío.')
            continue
        if not CustomerNotice._base_manager.filter(pk=notice.pk, status='queued').update(status='sending', attempted_at=now):
            continue
        try:
            from .invitations import origin
            context = {'client': notice.client, 'task': task, 'kind': notice.kind, 'url': portal_url(task),
                       'logo_url': origin() + '/static/brand/ibred-empresas-color.png'}
            provider = send_customer_email(notice.recipient, SUBJECTS[notice.kind] + ' · ib-red empresas',
                                           render_to_string('task_notice_email.txt', context),
                                           render_to_string('task_notice_email.html', context),
                                           delivery_context={'client': notice.client, 'kind': 'task'})
        except MailConfigurationError:
            CustomerNotice._base_manager.filter(pk=notice.pk).update(status='failed', error='El correo del SOC no está configurado y probado.')
        except MailDeliveryError:
            CustomerNotice._base_manager.filter(pk=notice.pk).update(status='uncertain', error='SendGrid no confirmó la aceptación.')
        except Exception:
            CustomerNotice._base_manager.filter(pk=notice.pk).update(status='failed', error='No se pudo preparar el aviso.')
        else:
            CustomerNotice._base_manager.filter(pk=notice.pk).update(status='accepted', sent_at=now, provider_id=provider[:180], error='')
            sent += 1
    return sent

"""Encrypted SendGrid Web API configuration for customer mail."""

import json
import os
from urllib import error, request

from cryptography.fernet import InvalidToken
from .models import MailSettings
from .keyring import multifernet


class MailConfigurationError(Exception):
    pass


class MailDeliveryError(Exception):
    pass


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _fernet():
    value = os.environ.get("SOC_PORTAL_MAIL_KEY", "")
    if not value:
        raise MailConfigurationError("Falta la clave de cifrado del correo.")
    try:
        return multifernet(value)
    except (ValueError, UnicodeError) as exc:
        raise MailConfigurationError("La clave de cifrado del correo no es válida.") from exc


def encrypt_sendgrid_key(value):
    value = value.strip()
    if not value or any(char in value for char in "\r\n\t "):
        raise MailConfigurationError("La clave API de SendGrid no es válida.")
    return _fernet().encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_sendgrid_key(value):
    if not value:
        raise MailConfigurationError("Falta la clave API de SendGrid.")
    try:
        return _fernet().decrypt(value.encode("ascii")).decode("utf-8")
    except (InvalidToken, UnicodeError, ValueError) as exc:
        raise MailConfigurationError("No se puede leer la clave API de SendGrid guardada.") from exc


def send_via_sendgrid(config, recipient, subject, plain, html, *, copy_to="", delivery_context=None):
    base = {
        MailSettings.Region.GLOBAL: "https://api.sendgrid.com",
        MailSettings.Region.EU: "https://api.eu.sendgrid.com",
    }.get(config.region)
    if not base:
        raise MailConfigurationError("La región de SendGrid no es válida.")
    payload = {
        "personalizations": [{"to": [{"email": recipient}]}],
        "from": {"email": config.from_email, "name": "ib-red empresas · Centro SOC"},
        "subject": subject,
        "content": [
            {"type": "text/plain", "value": plain},
            {"type": "text/html", "value": html},
        ],
    }
    if config.reply_to_email:
        payload["reply_to"] = {"email": config.reply_to_email}
    if copy_to and copy_to.casefold() != recipient.casefold():
        payload["personalizations"][0]["bcc"] = [{"email": copy_to}]
    payload["tracking_settings"] = {"click_tracking": {"enable": False, "enable_text": False}, "open_tracking": {"enable": False}}
    api_key = decrypt_sendgrid_key(config.encrypted_api_key)
    dispatch=None
    if delivery_context:
        import uuid
        from .models import MailDispatch
        dispatch=MailDispatch.objects.create(token=uuid.uuid4(),recipient=recipient,**delivery_context)
        payload['personalizations'][0]['custom_args']={'soc_dispatch':str(dispatch.token)}
    outgoing = request.Request(
        base + "/v3/mail/send",
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Authorization": "Bearer " + api_key, "Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with request.build_opener(_NoRedirect()).open(outgoing, timeout=20) as response:
            if response.status != 202:
                if dispatch:MailDispatch.objects.filter(pk=dispatch.pk,status='sending').update(status='failed')
                raise MailDeliveryError(f"SendGrid respondió HTTP {response.status}.")
            message_id=str(response.headers.get("X-Message-Id") or "")[:180]
            if dispatch:
                MailDispatch.objects.filter(pk=dispatch.pk).update(provider_id=message_id)
                MailDispatch.objects.filter(pk=dispatch.pk,status='sending').update(status='accepted')
            return message_id
    except error.HTTPError as exc:
        if dispatch:MailDispatch.objects.filter(pk=dispatch.pk,status='sending').update(status='failed')
        raise MailDeliveryError(f"SendGrid rechazó el correo: HTTP {exc.code}.") from exc
    except (error.URLError, TimeoutError, OSError) as exc:
        if dispatch:MailDispatch.objects.filter(pk=dispatch.pk,status='sending').update(status='uncertain')
        raise MailDeliveryError("No se pudo conectar con la API de SendGrid.") from exc


def send_test_email(config, recipient):
    return send_via_sendgrid(
        config, recipient, "Prueba de correo · Centro SOC",
        "Esta es una prueba del envío de informes del Centro SOC. No contiene datos de clientes.",
        "<p>Esta es una prueba del envío de informes del Centro SOC. No contiene datos de clientes.</p>",
    )


def send_customer_email(recipient, subject, plain, html, *, report_copy=False, delivery_context=None):
    config = MailSettings.objects.order_by("pk").first()
    if config:
        if not config.enabled or not config.last_test_ok:
            raise MailConfigurationError("El correo del SOC no está configurado y probado.")
        return send_via_sendgrid(config, recipient, subject, plain, html, copy_to=config.report_copy_email if report_copy else "", delivery_context=delivery_context)
    raise MailConfigurationError("El correo del SOC no está configurado y probado.")


def send_report_email(recipient, subject, plain, html, *, report=None):
    context={'report':report,'client':report.client,'kind':'report'} if report else None
    return send_customer_email(recipient, subject, plain, html, report_copy=True,delivery_context=context)

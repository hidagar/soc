"""Revocable report links; anonymous requests never enter internal portal views."""
from datetime import timedelta
from urllib.parse import urlsplit

from django.contrib.auth.decorators import login_required
from django.core import signing
from django.core.exceptions import ValidationError
from django.http import Http404, HttpResponse, HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET, require_POST

from .mail_delivery import MailConfigurationError
from .models import MailSettings, ReportShare, WeeklyReport

SALT = "soc.customer-report.v1"
LINK_DAYS = 90


def validate_public_url(value):
    value = value.strip().rstrip("/")
    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("Indica una URL HTTPS válida, con puerto si es necesario.") from exc
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.path or parsed.query or parsed.fragment or any(char.isspace() for char in value)):
        raise ValueError("Usa solo la dirección base HTTPS, sin ruta, credenciales ni parámetros.")
    return value


def share_path(share, download=False):
    token = signing.dumps({"report": share.report_id, "nonce": str(share.nonce)}, salt=SALT)
    return reverse("customer_report_pdf" if download else "customer_report", args=[token])


def create_report_link(report):
    config = MailSettings.objects.order_by("pk").first()
    if not config or not config.public_reports_url or not config.public_reports_verified:
        raise MailConfigurationError("Configura y comprueba la URL pública HTTPS de informes en Correo del SOC.")
    base = validate_public_url(config.public_reports_url)
    share, created = ReportShare.objects.get_or_create(
        report=report, defaults={"expires_at": timezone.now() + timedelta(days=LINK_DAYS)},
    )
    if not created and (share.revoked or share.expires_at <= timezone.now()):
        raise MailConfigurationError("El enlace de este informe está revocado o caducado. Renueva el enlace desde su ficha.")
    return base + share_path(share)


def resolve_share(token):
    try:
        values = signing.loads(token, salt=SALT, max_age=LINK_DAYS * 86400)
        if not isinstance(values, dict) or type(values.get("report")) is not int or not 0 < values["report"] < 2**63:
            raise ValueError
        share = ReportShare.objects.select_related("report__client").get(
            report_id=values["report"], nonce=values["nonce"], revoked=False,
            report__client__active=True, expires_at__gt=timezone.now(),
        )
    except (signing.BadSignature, ReportShare.DoesNotExist, KeyError, ValueError, TypeError, ValidationError):
        raise Http404("Este enlace no está disponible. Solicita uno nuevo al equipo NOC.")
    return share


def private_headers(response):
    response["Cache-Control"] = "no-store, private"
    response["Referrer-Policy"] = "no-referrer"
    response["X-Robots-Tag"] = "noindex, nofollow, noarchive"
    return response


@require_GET
@never_cache
def customer_report(request, token):
    try:
        share = resolve_share(token)
    except Http404:
        return private_headers(render(request, "report_link_unavailable.html", status=404))
    from .report_versions import published_version, version_page
    version = published_version(share.report)
    return private_headers(version_page(request, version, reverse("customer_report_pdf", args=[token]),
                                        base="customer_report_base.html", expires_at=share.expires_at))


@require_GET
@never_cache
def customer_report_pdf(request, token):
    try:
        share = resolve_share(token)
    except Http404:
        return private_headers(render(request, "report_link_unavailable.html", status=404))
    from .report_versions import published_version, version_pdf
    version = published_version(share.report)
    return private_headers(version_pdf(version, f"informe-seguridad-{share.report.week_start:%Y-%m-%d}-v{version.number}.pdf"))


@require_GET
@never_cache
def report_health(request):
    response = HttpResponse("SOC reports endpoint ready", content_type="text/plain")
    response["X-SOC-Reports"] = "v1"
    return private_headers(response)


@login_required
@require_POST
def verify_public_reports(request):
    from django.contrib import messages
    from urllib import request as http
    from .mail_delivery import _NoRedirect
    if not request.user.has_perm("core.manage_connections"):
        return HttpResponseForbidden("Sin permiso para comprobar la URL de informes.")
    config = get_object_or_404(MailSettings, pk=1)
    config.public_reports_verified = False
    try:
        base = validate_public_url(config.public_reports_url)
        # Explicit configured endpoint only; TLS validation is never bypassed.
        req = http.Request(base + reverse("report_health"), headers={"User-Agent": "SOC-Report-Check/1"})
        with http.build_opener(_NoRedirect()).open(req, timeout=10) as response:
            config.public_reports_verified = response.status == 200 and response.headers.get("X-SOC-Reports") == "v1"
    except Exception:
        pass
    config.save(update_fields=["public_reports_verified"])
    if config.public_reports_verified:
        messages.success(request, "URL HTTPS verificada desde la VM. Comprueba también un informe desde una red externa antes del primer envío.")
    else:
        messages.error(request, "No se pudo verificar la URL pública: revisa acceso, puerto y certificado válido para el dominio o IP. No se enviarán enlaces sin esta comprobación.")
    return redirect("mail_settings")


@login_required
@require_POST
def manage_report_link(request, report_pk):
    from django.contrib import messages
    import uuid
    if not request.user.has_perm("core.manage_connections"):
        return HttpResponseForbidden("Tu cuenta no tiene permiso para gestionar enlaces de informes.")
    report = get_object_or_404(WeeklyReport, pk=report_pk)
    action = request.POST.get("action")
    if action == "revoke":
        ReportShare.objects.filter(report=report).update(revoked=True)
        messages.success(request, "Enlace revocado. El correo ya enviado dejará de dar acceso a este informe.")
    elif action == "renew":
        ReportShare.objects.update_or_create(report=report, defaults={
            "nonce": uuid.uuid4(), "expires_at": timezone.now() + timedelta(days=LINK_DAYS), "revoked": False,
        })
        messages.success(request, "Enlace renovado por 90 días. El anterior deja de funcionar; no se ha enviado ningún correo.")
    elif action == "create":
        try:
            create_report_link(report)
        except (MailConfigurationError, ValueError) as exc:
            messages.error(request, str(exc))
        else:
            messages.success(request, "Enlace de cliente preparado. No se ha enviado ningún correo.")
    return redirect(reverse("weekly_report", args=[report.client_id]) + f"?week={report.week_start.isoformat()}")

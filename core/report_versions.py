"""Versiones publicadas e inmutables de los informes semanales (bloque 6).

El cliente recibe siempre una versión congelada: abrir meses después el enlace de un
informe enviado reproduce lo que se envió, aunque cambien equipos, casos o
publicaciones. Una rectificación crea la versión siguiente con su motivo y conserva
la anterior.
"""
import hashlib

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db import IntegrityError, transaction
from django.db.models import Max
from django.http import HttpResponse, HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils.html import escape
from django.views.decorators.http import require_POST

from .models import ReportVersion, WeeklyReport, WorkerState
from .security import audit

# El enlace al PDF depende del canal (portal o enlace firmado): se sustituye al servir.
PDF_PLACEHOLDER = '__SOC_REPORT_PDF_URL__'


def render_snapshot(report):
    from .report_pdf import render_report_pdf
    from .service_development import customer_report_context
    context = customer_report_context(report)
    html = render_to_string('weekly_report.html', {**context, 'customer_view': True,
                                                   'report_base': 'report_snapshot_base.html',
                                                   'pdf_url': PDF_PLACEHOLDER})
    pdf = render_report_pdf(report, context_override=customer_report_context(report))
    return html, pdf


def freeze(report, user=None, reason=''):
    """Crea la versión siguiente con el contenido actual para el cliente."""
    html, pdf = render_snapshot(report)
    with transaction.atomic():
        WorkerState.reserve('report-versions')
        number = (ReportVersion._base_manager.filter(report=report).aggregate(n=Max('number'))['n'] or 0) + 1
        return ReportVersion._base_manager.create(
            report=report, number=number, html=html, pdf=pdf, reason=reason,
            html_sha256=hashlib.sha256(html.encode()).hexdigest(), pdf_sha256=hashlib.sha256(pdf).hexdigest(),
            created_by=user if user and user.is_authenticated else None)


def published_version(report, number=None):
    """Versión que debe ver el cliente: la pedida, o la última; la primera se congela si falta."""
    versions = ReportVersion._base_manager.filter(report=report)
    if number is not None:
        return versions.filter(number=number).first()
    latest = versions.order_by('-number').first()
    if latest:
        return latest
    try:
        with transaction.atomic():
            if not versions.exists():
                return freeze(report)
    except IntegrityError:
        pass
    return versions.order_by('-number').first()


def version_page(request, version, pdf_url, *, base, versions=(), version_url=None, expires_at=None):
    html = version.html.replace(PDF_PLACEHOLDER, escape(pdf_url))
    return render(request, 'report_version.html', {
        'client': version.report.client, 'report': version.report, 'version': version, 'snapshot_html': html,
        'versions': versions, 'version_url': version_url, 'report_base': base, 'expires_at': expires_at})


def version_pdf(version, filename):
    response = HttpResponse(bytes(version.pdf), content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response


@login_required
@require_POST
def rectify(request, report_pk):
    if not request.user.has_perm('core.manage_connections'):
        return HttpResponseForbidden('Tu cuenta no tiene permiso para rectificar informes publicados.')
    report = get_object_or_404(WeeklyReport, pk=report_pk)
    reason = request.POST.get('reason', '').strip()
    target = reverse('weekly_report', args=[report.client_id]) + f'?week={report.week_start.isoformat()}'
    if not ReportVersion._base_manager.filter(report=report).exists():
        messages.error(request, 'Este informe aún no se ha publicado: no hay versión que rectificar.')
    elif not reason or len(reason) > 2000:
        messages.error(request, 'Indica el motivo de la rectificación (máximo 2000 caracteres); el cliente lo verá.')
    else:
        version = freeze(report, request.user, reason)
        audit('report.rectified', report, {'count': version.number})
        messages.success(request, f'Publicada la versión {version.number}. La anterior se conserva y no se ha enviado ningún correo.')
    return redirect(target)

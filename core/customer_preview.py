"""«Ver como cliente»: el personal del SOC abre el portal de un cliente tal como lo ve él.

Mismo contenido y misma proyección que el portal del cliente (invariante 3): las vistas
reutilizan sus contextos, con enlaces propios y sin acciones de respuesta. Solo lectura
(GET), limitado al ámbito de clientes del usuario y auditado. Las cuentas de cliente no
llegan aquí: el middleware las limita a /cliente/.
"""
from django.contrib.auth.decorators import login_required
from django.http import Http404, JsonResponse
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET

from .customer_portal import detections_context, firewalls_context
from .models import Client, StaffAccess
from .security import audit
from .service_development import (_portal_base, customer_geography, customer_home_context, customer_map_context,
                                  customer_reports_context, customer_tasks_context, customer_version)


def preview_client(request, pk, section):
    access = StaffAccess.objects.filter(user=request.user).first()
    if access and access.role == 'customer':
        raise Http404
    # Client.objects aplica el ámbito del usuario: un cliente fuera de su alcance da 404.
    client = get_object_or_404(Client, pk=pk, active=True)
    if section:
        audit('customer.preview', client, {'status': section})
    return client


def _render(request, template, context):
    context['preview_back'] = reverse('client_detail', args=[context['client'].pk])
    return render(request, template, context)


@login_required
@never_cache
@require_GET
def home(request, pk):
    client = preview_client(request, pk, 'inicio')
    return _render(request, 'customer_home.html', customer_home_context(client, preview=True))


@login_required
@never_cache
@require_GET
def reports(request, pk):
    client = preview_client(request, pk, 'informes')
    return _render(request, 'customer_reports.html', customer_reports_context(client, preview=True))


@login_required
@never_cache
@require_GET
def tasks(request, pk):
    client = preview_client(request, pk, 'actuaciones')
    return _render(request, 'customer_tasks.html', customer_tasks_context(client, preview=True))


@login_required
@never_cache
@require_GET
def firewalls(request, pk):
    client = preview_client(request, pk, 'firewalls')
    if not client.customer_portal_detail_enabled:
        raise Http404
    return _render(request, 'customer_firewalls.html', firewalls_context(client, preview=True))


@login_required
@never_cache
@require_GET
def detections(request, pk):
    client = preview_client(request, pk, 'detecciones')
    if not client.customer_portal_detail_enabled:
        raise Http404
    return _render(request, 'customer_detections.html', detections_context(request, client, preview=True))


@login_required
@never_cache
@require_GET
def threat_map(request, pk):
    client = preview_client(request, pk, 'mapa')
    return _render(request, 'threat_map.html', customer_map_context(request, client, preview=True))


@login_required
@never_cache
@require_GET
def map_data(request, pk):
    return JsonResponse(customer_geography(request, preview_client(request, pk, ''))[1])


@login_required
@never_cache
@require_GET
def report(request, pk, report_pk):
    from .report_versions import version_page
    client = preview_client(request, pk, 'informe')
    version, suffix = customer_version(request, report_pk, client, create=False)
    base = reverse('customer_preview_report', args=[client.pk, report_pk])
    return version_page(request, version, reverse('customer_preview_report_pdf', args=[client.pk, report_pk]) + suffix,
                        base='customer_report_base.html', versions=version.report.versions.all(), version_url=base,
                        extra={**_portal_base(client, True, 'reports'), 'preview_back': reverse('client_detail', args=[client.pk])})


@login_required
@never_cache
@require_GET
def report_pdf(request, pk, report_pk):
    from .report_versions import version_pdf
    client = preview_client(request, pk, '')
    version, _ = customer_version(request, report_pk, client, create=False)
    return version_pdf(version, f'informe-semanal-v{version.number}.pdf')

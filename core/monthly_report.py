"""Informe mensual para dirección (bloque 6): resumen del mes publicado al cliente con versión inmutable.

- **Datos:** proyección explícita para el cliente (invariante 3), hecha solo con lo que ya se le publica:
  - cifras de los informes semanales cuyas semanas empiezan en el mes, para que coincidan con lo que
    recibió cada semana;
  - comunicaciones publicadas;
  - actuaciones del portal;
  - recomendaciones de los hallazgos semanales;
  - cifras agregadas del bloqueo proactivo;
  - la valoración que escribe el SOC al publicar.
  Nunca incidencias sin publicar, notas internas ni acciones internas.
- **Publicación:** manual, cuando todas sus semanas han terminado y se pueden publicar. Congela HTML y PDF
  (versión 1). Una rectificación añade la versión siguiente con su motivo.
- **Correo opcional por cliente:** bandeja con un único intento, enviada por el trabajo «Avisos operativos».
  Un resultado dudoso queda «por comprobar» y no se reintenta solo (invariante 6). El correo solo lleva el
  enlace firmado, revocable y con caducidad, en /reports/mensual-<token>/, que los registros ocultan
  como los del informe semanal.
"""
import hashlib
from datetime import datetime, time, timedelta

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core import signing
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.db import transaction
from django.db.models import Max
from django.http import Http404, HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET, require_POST

from .models import (Client, CustomerPublication, CustomerTask, MonthlyReport, MonthlyReportShare, MonthlyReportVersion,
                     WeeklyReport, WorkerState)
from .report_versions import PDF_PLACEHOLDER
from .security import audit

SALT = 'soc.monthly-report.v1'
LINK_DAYS = 90
MAX_SUMMARY = 4000
MONTHS = ('enero', 'febrero', 'marzo', 'abril', 'mayo', 'junio', 'julio', 'agosto', 'septiembre', 'octubre',
          'noviembre', 'diciembre')
REMIND_AFTER = timedelta(days=3)  # tras poder publicarse, se avisa en «Salud del SOC» si sigue sin publicar


def month_label(month):
    return f'{MONTHS[month.month - 1]} de {month.year}'


def bounds(month):
    """(primer día, primer día del mes siguiente) como fechas."""
    first = month.replace(day=1)
    return first, (first.replace(day=28) + timedelta(days=4)).replace(day=1)


def mondays(month):
    """Semanas del informe: las que empiezan (lunes) dentro del mes."""
    first, following = bounds(month)
    day = first + timedelta(days=(7 - first.weekday()) % 7)
    while day < following:
        yield day
        day += timedelta(days=7)


def available_from(month):
    """Primer día en que el mes se puede publicar: cuando terminan el mes y su última semana."""
    weeks = list(mondays(month))
    return max(bounds(month)[1], weeks[-1] + timedelta(days=7))


def parse_month(value):
    try:
        month = datetime.strptime(value or '', '%Y-%m').date()
    except ValueError:
        raise Http404('Mes no válido.') from None
    if month.year < 2020 or month > timezone.localdate().replace(day=1):
        raise Http404('Mes no válido.')
    return month


def _weekly(client, month):
    return {w.week_start: w for w in WeeklyReport.objects.filter(client=client, week_start__in=list(mondays(month)))}


def _totals(weeks):
    totals = {key: sum(w[key] for w in weeks) for key in ('security', 'blocked', 'allowed', 'unknown', 'availability')}
    totals['weeks'] = len(weeks)
    return totals


def _week_row(monday, report):
    if not report:
        return {'start': monday, 'end': monday + timedelta(days=6), 'missing': True, 'security': 0, 'blocked': 0,
                'allowed': 0, 'unknown': 0, 'availability': 0, 'observed': 0, 'devices': 0}
    coverage = report.coverage or {}
    return {'start': monday, 'end': monday + timedelta(days=6), 'missing': False, 'security': report.security_count,
            'blocked': report.blocked_count, 'allowed': report.allowed_count,
            'unknown': max(0, report.security_count - report.allowed_count - report.blocked_count),
            'availability': report.availability_count, 'observed': coverage.get('observed_devices', 0),
            'devices': len(coverage.get('devices') or [])}


def _summary(totals, previous, has_sources):
    if not has_sources:
        return ('Visibilidad pendiente', 'No hay una fuente de eventos verificada en las semanas del mes; las cifras no '
                'permiten valorar la seguridad del periodo.')
    if totals['allowed']:
        title, text = 'Revisión prioritaria', (f"Durante el mes se registraron {totals['allowed']} detecciones de seguridad "
                                               'permitidas. Conviene completar las recomendaciones de este informe.')
    elif totals['blocked']:
        title, text = 'Bloqueos registrados', (f"Los firewalls bloquearon {totals['blocked']} detecciones de seguridad durante "
                                               'el mes y no se registraron detecciones permitidas.')
    elif totals['security']:
        title, text = 'Detecciones con acción sin confirmar', (f"Se recibieron {totals['security']} detecciones de seguridad "
                                                               'sin que los registros confirmen si se bloquearon.')
    else:
        title, text = 'Sin detecciones recibidas', ('No se recibieron detecciones de seguridad durante el mes. Esto no '
                                                    'confirma que no hubiera actividad.')
    if previous and previous['security']:
        change = round((totals['security'] - previous['security']) * 100 / previous['security'])
        if change:
            text += (f" Respecto al mes anterior, las detecciones {'aumentaron' if change > 0 else 'disminuyeron'} un "
                     f"{abs(change)} % (de {previous['security']} a {totals['security']}).")
        else:
            text += ' El volumen de detecciones es similar al del mes anterior.'
    return title, text


def _recommendations(reports):
    """Recomendaciones de los hallazgos semanales (ya publicados al cliente), agrupadas y por frecuencia."""
    found = {}
    for report in reports:
        for finding in report.findings or []:
            for text in (finding.get('recommendations') or [])[:1]:
                item = found.setdefault(text, {'text': text, 'assets': set(), 'weeks': set()})
                item['assets'].add(finding.get('asset_name') or 'Equipo por identificar')
                item['weeks'].add(report.week_start)
    rows = sorted(found.values(), key=lambda r: (-len(r['weeks']), -len(r['assets']), r['text']))[:5]
    return [{'text': r['text'], 'assets': sorted(r['assets'])[:6], 'more_assets': max(0, len(r['assets']) - 6),
             'weeks': len(r['weeks'])} for r in rows]


def customer_context(client, month, report=None):
    """Contexto del informe para el cliente: solo datos ya publicables (invariante 3)."""
    from .blocklist_efficacy import client_protection
    from .service_development import OPEN_TASK_STATUSES
    first, following = bounds(month)
    weekly = _weekly(client, month)
    weeks = [_week_row(monday, weekly.get(monday)) for monday in mondays(month)]
    present = [w for w in weeks if not w['missing']]
    totals = _totals(present)
    previous_month = (first - timedelta(days=1)).replace(day=1)
    previous_weekly = _weekly(client, previous_month)
    previous = (_totals([_week_row(m, previous_weekly[m]) for m in mondays(previous_month)])
                if all(m in previous_weekly for m in mondays(previous_month)) else None)
    title, text = _summary(totals, previous, any(r.sources for r in weekly.values()))
    start = timezone.make_aware(datetime.combine(first, time.min))
    end = timezone.make_aware(datetime.combine(following, time.min))
    publications = list(CustomerPublication.objects.filter(client=client, visible=True, incident__observed_at__gte=start,
                                                           incident__observed_at__lt=end).order_by('incident__observed_at'))
    tasks = CustomerTask.objects.filter(incident__client=client, visible=True)
    return {
        'client': client, 'month': first, 'month_label': month_label(first),
        'period_start': weeks[0]['start'], 'period_end': weeks[-1]['end'],
        'weeks': weeks, 'totals': totals, 'previous': previous, 'summary_title': title, 'summary_text': text,
        'missing_weeks': [w for w in weeks if w['missing']],
        'devices': max([w['devices'] for w in present] + [0]), 'observed_min': min([w['observed'] for w in present] or [0]),
        'publications': [{'title': p.title, 'status': p.get_status_display(), 'resolved': p.status == 'resolved'}
                         for p in publications],
        'validated_tasks': [{'title': t.title} for t in tasks.filter(status='accepted', reviewed_at__gte=start, reviewed_at__lt=end)],
        'pending_tasks': [{'title': t.title, 'status': t.get_status_display(), 'due_at': t.due_at}
                          for t in tasks.filter(status__in=OPEN_TASK_STATUSES).order_by('due_at', 'pk')],
        'recommendations': _recommendations(sorted(weekly.values(), key=lambda r: r.week_start)),
        'proactive': client_protection(client, first, following - timedelta(days=1)),
        'soc_summary': report.soc_summary if report else '', 'customer_view': True,
        **_index(client, first, following),
        'connectivity': _connectivity(client, first, following),
        'service': _service(client, start, end),
    }


def _service(client, start, end):
    """Lo que el SOC ha hecho con el cliente en el mes: vulnerabilidades avisadas, solicitudes y cambios.

    Solo lo que el cliente ya ve en su portal (invariante 3): avisos publicados, sus propias solicitudes y
    los cambios que se le ofrecieron, con el título que se le mostró.
    """
    from .models import CustomerRequest, DeviceExposure, PolicyProposal
    published = DeviceExposure.objects.filter(client=client, advisory__client=client, dismissed_at__isnull=True)
    advised = published.filter(advisory__published_at__gte=start, advisory__published_at__lt=end)
    fixed = published.filter(resolved_at__gte=start, resolved_at__lt=end)
    pending = published.filter(resolved_at__isnull=True)
    vulnerabilities = {
        'advised': advised.values('record__cve_id').distinct().count(), 'advised_firewalls': advised.values('device').distinct().count(),
        'fixed': fixed.values('record__cve_id').distinct().count(), 'pending': pending.values('record__cve_id').distinct().count(),
        'pending_firewalls': sorted(set(pending.values_list('device__name', flat=True))),
        'exploited': pending.filter(record__kev_added__isnull=False).exists(),
    }
    requests = CustomerRequest.objects.filter(client=client)
    opened = requests.filter(created_at__gte=start, created_at__lt=end)
    answered = [r for r in opened if r.first_response_at]
    hours = sorted((r.first_response_at - r.created_at).total_seconds() / 3600 for r in answered)
    request_data = {
        'opened': opened.count(), 'resolved': requests.filter(resolved_at__gte=start, resolved_at__lt=end).count(),
        'open': requests.exclude(status='resolved').count(),
        'median_response_hours': round(hours[len(hours) // 2], 1) if hours else None,
    }
    policies = PolicyProposal.objects.filter(client=client, offered_at__isnull=False).exclude(status__in=('proposed', 'obsolete', 'dismissed'))

    def titles(queryset):
        return [p.customer_title or p.title for p in queryset.order_by('offered_at')]
    policy_data = {
        'offered': policies.filter(offered_at__gte=start, offered_at__lt=end).count(),
        'applied': titles(policies.filter(applied_at__gte=start, applied_at__lt=end)),
        'verified': titles(policies.filter(status='verified', verified_at__gte=start, verified_at__lt=end)),
        'awaiting': titles(policies.filter(status='offered')),
    }
    data = {'vulnerabilities': vulnerabilities, 'requests': request_data, 'policies': policy_data}
    data['any'] = bool(vulnerabilities['advised'] or vulnerabilities['fixed'] or vulnerabilities['pending'] or request_data['opened']
                       or request_data['resolved'] or request_data['open'] or policy_data['offered'] or policy_data['applied']
                       or policy_data['verified'] or policy_data['awaiting'])
    return data


def _connectivity(client, first, following):
    from .connectivity import month as month_connectivity
    data = month_connectivity(client, first, following)
    # Solo datos agregados por sede y firewall; la lista de eventos no se publica en el informe.
    return {'rows': data['rows'], 'total': data['total'], 'reporting': data['reporting'], 'firewalls': data['firewalls']}


def _index(client, first, following):
    """Índice de seguridad al cierre del mes y al cierre del anterior (fotos diarias guardadas)."""
    from .security_score import at, level_of
    end = at(client, following - timedelta(days=1))
    if not end or end.day < first:
        return {'index': None}
    before = at(client, first - timedelta(days=1))
    weak = [f for f in end.factors if f.get('state') != 'ok'][:3]
    return {'index': {'score': end.score, 'level': end.level, 'label': level_of(end.score)[1], 'day': end.day,
                      'previous': before.score if before else None, 'weak': weak}}


def release_problem(client, month, now=None):
    """Por qué el mes aún no se puede publicar; cadena vacía si se puede."""
    from .service_development import publishable
    from .reporting import release_problem as week_problem
    today = timezone.localdate(now or timezone.now())
    if today < available_from(month):
        return f'sus semanas terminan el {available_from(month) - timedelta(days=1):%d/%m/%Y}.'
    weekly = _weekly(client, month)
    missing = [m for m in mondays(month) if m not in weekly]
    if missing:
        return 'faltan los datos de la semana del ' + ', '.join(f'{m:%d/%m}' for m in missing) + '.'
    for monday, report in sorted(weekly.items()):
        if not publishable(report):
            return f'la semana del {monday:%d/%m} no está lista: {week_problem(report)}'
    return ''


def render_snapshot(report):
    from .monthly_pdf import render_monthly_pdf
    context = customer_context(report.client, report.month, report)
    html = render_to_string('monthly_report.html', {**context, 'report_base': 'report_snapshot_base.html',
                                                    'pdf_url': PDF_PLACEHOLDER})
    return html, render_monthly_pdf(context)


def freeze(report, user=None, reason=''):
    html, pdf = render_snapshot(report)
    with transaction.atomic():
        WorkerState.reserve('report-versions')
        number = (MonthlyReportVersion._base_manager.filter(report=report).aggregate(n=Max('number'))['n'] or 0) + 1
        return MonthlyReportVersion._base_manager.create(
            report=report, number=number, html=html, pdf=pdf, reason=reason,
            html_sha256=hashlib.sha256(html.encode()).hexdigest(), pdf_sha256=hashlib.sha256(pdf).hexdigest(),
            created_by=user if user and user.is_authenticated else None)


def recipient(client):
    for value in (client.monthly_email, client.report_email):
        try:
            validate_email(value)
            return value
        except ValidationError:
            continue
    return ''


def queue_send(report, address):
    """Deja el envío en la bandeja; no hace nada si ya está en cola o saliendo."""
    return MonthlyReport._base_manager.filter(pk=report.pk).exclude(send_status__in=('queued', 'sending')).update(
        send_status='queued', send_error='', sent_to=address, provider_id='')


def _summary_text(request):
    value = request.POST.get('soc_summary', '').strip()
    if len(value) > MAX_SUMMARY:
        messages.error(request, f'La valoración del SOC admite como máximo {MAX_SUMMARY} caracteres.')
        return None
    return value


def _target(client, month):
    return reverse('monthly_summary', args=[client.pk]) + f'?month={month:%Y-%m}'


def staff_context(client, month, user):
    report = MonthlyReport.objects.filter(client=client, month=month).first()
    share = getattr(report, 'share', None) if report else None
    return {'publication': report if report and report.published_at else None,
            'versions': list(report.versions.all()) if report else [],
            'release_problem': release_problem(client, month), 'monthly_recipient': recipient(client),
            'share': share, 'share_active': bool(share and not share.revoked and share.expires_at > timezone.now()),
            'can_publish': user.has_perm('core.change_incident'), 'can_rectify': user.has_perm('core.manage_connections')}


@login_required
@require_GET
def preview(request, client_pk):
    """Vista previa para el SOC con los datos de hoy; no publica ni congela nada."""
    client = get_object_or_404(Client, pk=client_pk)
    month = parse_month(request.GET.get('month'))
    report = MonthlyReport.objects.filter(client=client, month=month).first()
    return render(request, 'monthly_report.html', {**customer_context(client, month, report), 'report_base': 'base.html',
                                                   'staff_preview': True, 'pdf_url': ''})


@login_required
@require_POST
def publish(request, client_pk):
    client = get_object_or_404(Client, pk=client_pk)
    if not request.user.has_perm('core.change_incident'):
        return HttpResponseForbidden('Tu cuenta no tiene permiso para publicar informes al cliente.')
    month = parse_month(request.POST.get('month'))
    summary = _summary_text(request)
    problem = release_problem(client, month)
    if summary is None:
        return redirect(_target(client, month))
    if problem:
        messages.error(request, 'Este mes aún no puede publicarse: ' + problem)
        return redirect(_target(client, month))
    now = timezone.now()
    with transaction.atomic():
        WorkerState.reserve('monthly-reports')
        report, _ = MonthlyReport._base_manager.get_or_create(client=client, month=month)
        claimed = MonthlyReport._base_manager.filter(pk=report.pk, published_at=None).update(
            published_at=now, published_by=request.user, soc_summary=summary)
    if not claimed:
        messages.error(request, 'Este informe ya está publicado. Para cambiarlo, publica una versión rectificada.')
        return redirect(_target(client, month))
    report.refresh_from_db()
    try:
        version = freeze(report, request.user)
    except Exception:
        MonthlyReport._base_manager.filter(pk=report.pk).update(published_at=None, published_by=None)
        raise
    audit('report.monthly_published', report, {'count': version.number})
    address = recipient(client)
    if request.POST.get('send') and client.monthly_reports_enabled and address:
        queue_send(report, address)
        messages.success(request, f'Informe de {month_label(month)} publicado en el portal. El correo a {address} sale en el próximo minuto.')
    else:
        messages.success(request, f'Informe de {month_label(month)} publicado en el portal. No se ha enviado ningún correo.')
    return redirect(_target(client, month))


@login_required
@require_POST
def rectify(request, report_pk):
    if not request.user.has_perm('core.manage_connections'):
        return HttpResponseForbidden('Tu cuenta no tiene permiso para rectificar informes publicados.')
    report = get_object_or_404(MonthlyReport, pk=report_pk, published_at__isnull=False)
    reason = request.POST.get('reason', '').strip()
    summary = _summary_text(request)
    if summary is not None and (not reason or len(reason) > 2000):
        messages.error(request, 'Indica el motivo de la rectificación (máximo 2000 caracteres); el cliente lo verá.')
    elif summary is not None:
        MonthlyReport._base_manager.filter(pk=report.pk).update(soc_summary=summary)
        report.soc_summary = summary
        version = freeze(report, request.user, reason)
        audit('report.monthly_rectified', report, {'count': version.number})
        messages.success(request, f'Publicada la versión {version.number}. La anterior se conserva y no se ha enviado ningún correo.')
    return redirect(_target(report.client, report.month))


@login_required
@require_POST
def send(request, report_pk):
    """Envío (o reenvío consciente) por correo. Un envío dudoso solo se repite si alguien lo pide aquí."""
    if not request.user.has_perm('core.change_incident'):
        return HttpResponseForbidden('Tu cuenta no tiene permiso para enviar informes.')
    report = get_object_or_404(MonthlyReport, pk=report_pk, published_at__isnull=False)
    address = recipient(report.client)
    if not report.client.monthly_reports_enabled or not address:
        messages.error(request, 'Activa el envío del informe mensual e indica el correo en la ficha del cliente.')
    elif report.send_status == 'uncertain' and request.POST.get('confirm') != '1':
        messages.error(request, 'El envío anterior quedó por comprobar. Revisa «Entrega y avisos» y confirma el reenvío.')
    elif queue_send(report, address):
        audit('report.monthly_send', report, {'status': 'queued'})
        messages.success(request, f'Correo en cola para {address}.')
    else:
        messages.info(request, 'El correo ya está en cola o saliendo.')
    return redirect(_target(report.client, report.month))


@login_required
@require_POST
def manage_link(request, report_pk):
    import uuid
    if not request.user.has_perm('core.manage_connections'):
        return HttpResponseForbidden('Tu cuenta no tiene permiso para gestionar enlaces de informes.')
    report = get_object_or_404(MonthlyReport, pk=report_pk, published_at__isnull=False)
    action = request.POST.get('action')
    if action == 'revoke':
        MonthlyReportShare.objects.filter(report=report).update(revoked=True)
        audit('report.monthly_link', report, {'status': 'revoked'})
        messages.success(request, 'Enlace revocado. El correo enviado deja de dar acceso a este informe.')
    elif action == 'renew':
        MonthlyReportShare.objects.update_or_create(report=report, defaults={
            'nonce': uuid.uuid4(), 'expires_at': timezone.now() + timedelta(days=LINK_DAYS), 'revoked': False})
        audit('report.monthly_link', report, {'status': 'renewed'})
        messages.success(request, 'Enlace renovado por 90 días. El anterior deja de funcionar; no se ha enviado ningún correo.')
    return redirect(_target(report.client, report.month))


def latest_version(report, raw=''):
    versions = MonthlyReportVersion._base_manager.filter(report=report)
    version = versions.filter(number=int(raw)).first() if raw.isdigit() and len(raw) < 6 else versions.order_by('-number').first()
    if not version:
        raise Http404
    return version


def _filename(version):
    return f'informe-mensual-{version.report.month:%Y-%m}-v{version.number}.pdf'


def _customer_report(request, pk, client=None):
    from .service_development import customer_client
    client = client or customer_client(request)
    return get_object_or_404(MonthlyReport, pk=pk, client=client, published_at__isnull=False)


@login_required
@require_GET
def customer_monthly(request, pk):
    from .report_versions import version_page
    from .service_development import _portal_base
    report = _customer_report(request, pk)
    raw = request.GET.get('version', '')
    version = latest_version(report, raw)
    suffix = '?version=' + str(version.number) if raw else ''
    return version_page(request, version, reverse('customer_monthly_pdf', args=[pk]) + suffix, base='customer_report_base.html',
                        versions=report.versions.all(), version_url=reverse('customer_monthly', args=[pk]),
                        extra={**_portal_base(report.client, False, 'reports'), 'report_title': 'Informe mensual'})


@login_required
@require_GET
def customer_monthly_pdf(request, pk):
    from .report_versions import version_pdf
    version = latest_version(_customer_report(request, pk), request.GET.get('version', ''))
    return version_pdf(version, _filename(version))


def share_url(report):
    """Enlace público firmado del informe (lo crea o lo renueva si caducó o se revocó)."""
    import uuid
    from .mail_delivery import MailConfigurationError
    from .models import MailSettings
    from .report_sharing import validate_public_url
    config = MailSettings.objects.order_by('pk').first()
    if not config or not config.public_reports_url or not config.public_reports_verified:
        raise MailConfigurationError('Configura y comprueba la URL pública HTTPS de informes en Correo del SOC.')
    base = validate_public_url(config.public_reports_url)
    share, created = MonthlyReportShare.objects.get_or_create(
        report=report, defaults={'expires_at': timezone.now() + timedelta(days=LINK_DAYS)})
    if not created and (share.revoked or share.expires_at <= timezone.now()):
        share.nonce, share.expires_at, share.revoked = uuid.uuid4(), timezone.now() + timedelta(days=LINK_DAYS), False
        share.save(update_fields=['nonce', 'expires_at', 'revoked'])
    token = signing.dumps({'report': share.report_id, 'nonce': str(share.nonce)}, salt=SALT)
    return base + reverse('monthly_public', args=[token]), share.expires_at


def resolve_share(token):
    try:
        values = signing.loads(token, salt=SALT, max_age=LINK_DAYS * 86400)
        if not isinstance(values, dict) or type(values.get('report')) is not int or not 0 < values['report'] < 2**63:
            raise ValueError
        return MonthlyReportShare.objects.select_related('report__client').get(
            report_id=values['report'], nonce=values['nonce'], revoked=False, report__published_at__isnull=False,
            report__client__active=True, expires_at__gt=timezone.now())
    except (signing.BadSignature, MonthlyReportShare.DoesNotExist, KeyError, ValueError, TypeError, ValidationError):
        raise Http404 from None


@require_GET
@never_cache
def public_monthly(request, token):
    from .report_sharing import private_headers
    from .report_versions import version_page
    try:
        share = resolve_share(token)
    except Http404:
        return private_headers(render(request, 'report_link_unavailable.html', status=404))
    version = latest_version(share.report)
    return private_headers(version_page(request, version, reverse('monthly_public_pdf', args=[token]),
                                        base='customer_report_base.html', expires_at=share.expires_at,
                                        extra={'report_title': 'Informe mensual'}))


@require_GET
@never_cache
def public_monthly_pdf(request, token):
    from .report_sharing import private_headers
    from .report_versions import version_pdf
    try:
        share = resolve_share(token)
    except Http404:
        return private_headers(render(request, 'report_link_unavailable.html', status=404))
    return private_headers(version_pdf(latest_version(share.report), _filename(latest_version(share.report))))


def send_pending(limit=5, now=None):
    """Trabajo «Avisos operativos»: un único intento por envío en cola."""
    from .mail_delivery import MailConfigurationError, MailDeliveryError, send_customer_email
    from .models import MailSettings
    now = now or timezone.now()
    MonthlyReport._base_manager.filter(send_status='sending', attempted_at__lt=now - timedelta(minutes=10)).update(
        send_status='uncertain', send_error='El envío se interrumpió; comprobar en «Entrega y avisos» antes de reenviar.')
    sent = 0
    for report in MonthlyReport._base_manager.filter(send_status='queued').select_related('client').order_by('pk')[:limit]:
        client = report.client
        if not client.active or not client.monthly_reports_enabled or not report.published_at:
            MonthlyReport._base_manager.filter(pk=report.pk, send_status='queued').update(
                send_status='failed', send_error='El envío se desactivó antes de salir.')
            continue
        if not MonthlyReport._base_manager.filter(pk=report.pk, send_status='queued').update(send_status='sending', attempted_at=now):
            continue
        try:
            url, expires_at = share_url(report)
            config = MailSettings.objects.order_by('pk').first()
            from .invitations import origin
            context = {'client': client, 'month_label': month_label(report.month), 'url': url, 'expires_at': expires_at,
                       'logo_url': origin() + '/static/brand/ibred-empresas-color.png',
                       'reply_address': config.reply_to_email or config.from_email}
            provider = send_customer_email(report.sent_to, f'ib-red · Informe mensual de seguridad · {client.name} · {month_label(report.month)}',
                                           render_to_string('monthly_email.txt', context), render_to_string('monthly_email.html', context),
                                           report_copy=True, delivery_context={'client': client, 'kind': 'monthly'})
        except MailConfigurationError as exc:
            MonthlyReport._base_manager.filter(pk=report.pk).update(send_status='failed', send_error=str(exc)[:240])
        except MailDeliveryError:
            MonthlyReport._base_manager.filter(pk=report.pk).update(send_status='uncertain', send_error='SendGrid no confirmó la aceptación.')
        except Exception:
            MonthlyReport._base_manager.filter(pk=report.pk).update(send_status='failed', send_error='No se pudo preparar el correo.')
        else:
            MonthlyReport._base_manager.filter(pk=report.pk).update(send_status='accepted', sent_at=now, provider_id=provider[:180], send_error='')
            sent += 1
    return sent


def check_pending(now=None):
    """Aviso en «Salud del SOC» si el informe del mes anterior de un cliente con envío mensual sigue sin publicar."""
    from .models import OperationalIssue
    from .operations import set_issue
    now = now or timezone.now()
    today = timezone.localdate(now)
    month = (today.replace(day=1) - timedelta(days=1)).replace(day=1)
    if today < available_from(month):
        month = (month - timedelta(days=1)).replace(day=1)
    due = today >= available_from(month) + REMIND_AFTER
    published = set(MonthlyReport._base_manager.filter(month=month, published_at__isnull=False).values_list('client_id', flat=True))
    wanted = set()
    for client in Client._base_manager.filter(active=True, monthly_reports_enabled=True):
        key = f'report:monthly:{client.pk}'
        if due and client.pk not in published:
            wanted.add(key)
            set_issue(key, f'Informe mensual sin publicar · {client.name}', now=now,
                      details=f'El informe de {month_label(month)} ya puede publicarse. Revísalo y publícalo desde el resumen mensual del cliente.')
    OperationalIssue._base_manager.filter(key__startswith='report:monthly:', active=True).exclude(key__in=wanted).update(
        active=False, resolved_at=now)
    return len(wanted)

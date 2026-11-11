"""Línea de tiempo de un cliente: todo lo que ha pasado con él, en un solo sitio y por orden.

Reúne incidencias, avisos urgentes, solicitudes, vulnerabilidades, cambios propuestos, actuaciones,
comunicaciones, informes, caídas de Internet y cambios en firewalls. Es una vista interna del SOC, de
solo lectura: cada entrada enlaza a su página. El cliente (`Client.objects`) y cada consulta pasan por
el ámbito del usuario.
"""
from datetime import timedelta

from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET

from .models import (ChangePlan, Client, ConnectivityEvent, CustomerPublication, CustomerRequest, CustomerTask, DeviceExposure,
                     Incident, MonthlyReport, PolicyProposal, UrgentAlert, VulnerabilityAdvisory, WeeklyReport)

CATEGORIES = [('incident', 'Incidencias'), ('alert', 'Avisos urgentes'), ('request', 'Solicitudes'),
              ('vulnerability', 'Vulnerabilidades'), ('policy', 'Cambios propuestos'), ('task', 'Actuaciones y comunicaciones'),
              ('report', 'Informes'), ('connectivity', 'Conexión a Internet'), ('change', 'Cambios en firewalls')]
PERIODS = [(30, '30 días'), (90, '90 días'), (365, '1 año')]
LIMIT = 300
PER_SOURCE = 200


def events(client, since, categories=None):
    """Entradas {'at', 'category', 'tone', 'title', 'detail', 'url'} desde `since`, la más reciente primero."""
    wanted = set(categories or dict(CATEGORIES))
    rows = []

    def add(at, category, title, detail='', url='', tone=''):
        if at and at >= since:
            rows.append({'at': at, 'category': category, 'tone': tone, 'title': title, 'detail': detail, 'url': url})

    if 'incident' in wanted:
        for i in Incident.objects.filter(client=client).order_by('-observed_at')[:PER_SOURCE]:
            url = reverse('incident_detail', args=[i.pk])
            add(i.observed_at, 'incident', f'Incidencia abierta: {i.title}', f'Gravedad {i.get_severity_display().lower()}', url,
                'alert' if i.severity in ('high', 'critical') else 'warn')
            add(i.resolved_at, 'incident', f'Incidencia resuelta: {i.title}', '', url, 'ok')
    if 'alert' in wanted:
        for a in UrgentAlert.objects.filter(client=client, observed_at__gte=since)[:PER_SOURCE]:
            add(a.observed_at, 'alert', f'Aviso urgente: {a.get_kind_display()}',
                f'{a.asset_name or "Equipo sin identificar"} · {a.get_status_display()}', reverse('urgent_alert_list') + f'?client={client.pk}', 'alert')
    if 'request' in wanted:
        for r in CustomerRequest.objects.filter(client=client)[:PER_SOURCE]:
            url = reverse('request_detail', args=[r.pk])
            add(r.created_at, 'request', f'Solicitud del cliente: {r.subject}', f'{r.reference} · {r.get_kind_display()}' + (' · urgente' if r.urgent else ''),
                url, 'alert' if r.urgent else 'warn')
            add(r.resolved_at, 'request', f'Solicitud resuelta: {r.subject}', r.reference, url, 'ok')
    if 'vulnerability' in wanted:
        vulnerabilities = reverse('vulnerabilities') + '?state=all'
        for a in VulnerabilityAdvisory.objects.filter(client=client, published_at__gte=since)[:PER_SOURCE]:
            add(a.published_at, 'vulnerability', f'Vulnerabilidad avisada al cliente: {a.cve_id}', '', vulnerabilities, 'warn')
        for e in (DeviceExposure.objects.filter(client=client, first_seen__gte=since).select_related('record', 'device')[:PER_SOURCE]):
            add(e.first_seen, 'vulnerability', f'Vulnerabilidad detectada: {e.record.cve_id} en {e.device.name}',
                f'Versión {e.version} · {e.record.get_severity_display()}', vulnerabilities, 'alert' if e.record.kev_added else 'warn')
        for e in (DeviceExposure.objects.filter(client=client, resolved_at__gte=since).select_related('record', 'device')[:PER_SOURCE]):
            add(e.resolved_at, 'vulnerability', f'Vulnerabilidad corregida: {e.record.cve_id} en {e.device.name}',
                f'Versión {e.resolved_version}' if e.resolved_version else '', vulnerabilities, 'ok')
    if 'policy' in wanted:
        policies = reverse('policies') + '?state=all'
        for p in PolicyProposal.objects.filter(client=client).exclude(status__in=('proposed', 'obsolete', 'dismissed'))[:PER_SOURCE]:
            add(p.offered_at, 'policy', f'Cambio propuesto al cliente: {p.title}', p.reference, policies)
            if p.decided_at and p.decided_by_id:
                rejected = p.status == 'rejected'
                add(p.decided_at, 'policy', f'Cambio {"rechazado" if rejected else "aprobado"} por el cliente: {p.title}', p.reference, policies,
                    '' if rejected else 'warn')
            add(p.applied_at, 'policy', f'Cambio aplicado: {p.title}', p.applied_note, policies)
            add(p.verified_at, 'policy', f'Cambio {"verificado" if p.status == "verified" else "sin efecto comprobado"}: {p.title}',
                (p.verification or {}).get('text', ''), policies, 'ok' if p.status == 'verified' else 'alert')
    if 'task' in wanted:
        for t in CustomerTask.objects.filter(incident__client=client, visible=True).select_related('incident')[:PER_SOURCE]:
            url = reverse('incident_detail', args=[t.incident_id])
            add(t.submitted_at, 'task', f'Respuesta del cliente a la actuación: {t.title}', '', url, 'warn')
            add(t.reviewed_at, 'task', f'Actuación revisada por el SOC: {t.title}', t.get_status_display(), url,
                'ok' if t.status == 'accepted' else '')
        for c in CustomerPublication.objects.filter(client=client, visible=True, created_at__gte=since)[:PER_SOURCE]:
            add(c.created_at, 'task', f'Comunicación publicada: {c.title}', c.get_status_display(), reverse('customer_publish', args=[client.pk]))
    if 'report' in wanted:
        for w in WeeklyReport.objects.filter(client=client, sent_at__gte=since)[:PER_SOURCE]:
            add(w.sent_at, 'report', f'Informe semanal enviado (semana del {w.week_start:%d/%m/%Y})', w.sent_to,
                reverse('weekly_report', args=[client.pk]) + f'?week={w.week_start:%Y-%m-%d}')
        for m in MonthlyReport.objects.filter(client=client, published_at__gte=since)[:PER_SOURCE]:
            add(m.published_at, 'report', f'Informe mensual publicado ({m.month:%m/%Y})', '',
                reverse('monthly_summary', args=[client.pk]) + f'?month={m.month:%Y-%m}')
    if 'connectivity' in wanted:
        for c in ConnectivityEvent.objects.filter(client=client, observed_at__gte=since).select_related('device')[:PER_SOURCE]:
            add(c.observed_at, 'connectivity', c.get_kind_display(), c.device.name if c.device else '',
                reverse('device_detail', args=[c.device_id]) if c.device_id else '', 'warn')
    if 'change' in wanted:
        for plan in (ChangePlan.objects.filter(device__site__client=client, created_at__gte=since).exclude(status='draft')
                     .select_related('device')[:PER_SOURCE]):
            add(plan.created_at, 'change', f'Cambio en {plan.device.name}: {plan.title}', plan.status_label, reverse('change_detail', args=[plan.pk]))
    rows.sort(key=lambda r: r['at'], reverse=True)
    return rows


@login_required
@never_cache
@require_GET
def timeline(request, pk):
    client = get_object_or_404(Client, pk=pk)
    days = request.GET.get('days', '90')
    days = int(days) if days.isdigit() and int(days) in dict(PERIODS) else 90
    category = request.GET.get('type', '')
    category = category if category in dict(CATEGORIES) else ''
    rows = events(client, timezone.now() - timedelta(days=days), [category] if category else None)
    labels = dict(CATEGORIES)
    shown = rows[:LIMIT]
    for row in shown:
        row['category_label'] = labels[row['category']]
        row['day'] = timezone.localdate(row['at'])  # el día es el de Madrid, no el de UTC
    return render(request, 'client_timeline.html', {
        'client': client, 'rows': shown, 'total': len(rows), 'limit': LIMIT, 'days': days, 'category': category,
        'categories': CATEGORIES, 'periods': PERIODS,
    })

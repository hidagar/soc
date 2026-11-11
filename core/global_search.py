"""Buscador global del SOC: clientes, sedes, firewalls, incidencias, solicitudes, políticas, CVE e IPs.

Todo pasa por los gestores con ámbito: un usuario solo encuentra lo de sus clientes. Una referencia
exacta (`SOL-00012`, `POL-00003`, una IP) lleva directamente a su página.
"""
import ipaddress
import re

from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.shortcuts import redirect, render
from django.urls import reverse
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET

from .models import Client, CustomerRequest, Device, DeviceExposure, Incident, PolicyProposal, Site

LIMIT = 8
REFERENCE = re.compile(r'^(SOL|POL)-0*(\d{1,9})$', re.I)
CVE = re.compile(r'^CVE-\d{4}-\d{4,}$', re.I)


def _ip(text):
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return ''


def search(query):
    """Lista de grupos {'title', 'rows': [{'label', 'detail', 'url'}], 'more'} para el texto buscado."""
    groups = []

    def add(title, queryset, row):
        rows = list(queryset[:LIMIT + 1])
        if rows:
            groups.append({'title': title, 'rows': [row(r) for r in rows[:LIMIT]], 'more': len(rows) > LIMIT})

    add('Clientes', Client.objects.filter(Q(name__icontains=query) | Q(code__icontains=query) | Q(contact_email__icontains=query)),
        lambda c: {'label': c.name, 'detail': '' if c.active else 'Inactivo', 'url': reverse('client_detail', args=[c.pk])})
    add('Sedes', Site.objects.filter(Q(name__icontains=query) | Q(address__icontains=query)).select_related('client'),
        lambda s: {'label': s.name, 'detail': s.client.name, 'url': reverse('site_detail', args=[s.pk])})
    device_filter = (Q(name__icontains=query) | Q(model__icontains=query) | Q(serial_number__icontains=query)
                     | Q(management_address__icontains=query) | Q(mac_address__icontains=query))
    add('Firewalls', Device.objects.filter(device_filter).select_related('site__client'),
        lambda d: {'label': d.name, 'detail': f'{d.site.client.name} · {d.site.name} · {d.model or d.get_vendor_display()}',
                   'url': reverse('device_detail', args=[d.pk])})
    incident_filter = Q(title__icontains=query)
    if query.isdigit():
        incident_filter |= Q(pk=int(query))
    add('Incidencias', Incident.objects.filter(incident_filter).select_related('client').order_by('-observed_at'),
        lambda i: {'label': i.title, 'detail': f'{i.client.name} · {i.get_status_display()}', 'url': reverse('incident_detail', args=[i.pk])})
    add('Solicitudes de clientes', CustomerRequest.objects.filter(subject__icontains=query).select_related('client'),
        lambda r: {'label': r.subject, 'detail': f'{r.reference} · {r.client.name} · {r.get_status_display()}',
                   'url': reverse('request_detail', args=[r.pk])})
    add('Políticas propuestas', PolicyProposal.objects.filter(title__icontains=query).select_related('client'),
        lambda p: {'label': p.title, 'detail': f'{p.reference} · {p.client.name} · {p.get_status_display()}',
                   'url': reverse('policies') + '?state=all'})
    if query.upper().startswith('CVE'):
        add('Vulnerabilidades', DeviceExposure.objects.filter(record__cve_id__icontains=query).select_related('record', 'device', 'client'),
            lambda e: {'label': f'{e.record.cve_id} · {e.device.name}',
                       'detail': f'{e.client.name} · versión {e.version} · ' + ('resuelta' if e.resolved_at else 'descartada' if e.dismissed_at else 'pendiente'),
                       'url': reverse('vulnerabilities') + '?state=all'})
    return groups


@login_required
@never_cache
@require_GET
def results(request):
    query = ' '.join(request.GET.get('q', '').split())[:80]
    context = {'query': query, 'groups': [], 'ip': '', 'short': False}
    if not query:
        return render(request, 'search.html', context)
    reference = REFERENCE.match(query)
    if reference:
        model, name = (CustomerRequest, 'request_detail') if reference[1].upper() == 'SOL' else (PolicyProposal, 'policies')
        row = model.objects.filter(pk=int(reference[2])).first()
        if row:
            return redirect(reverse(name, args=[row.pk]) if name == 'request_detail' else reverse(name) + '?state=all')
    address = _ip(query)
    if address:
        context['ip'] = address
    if len(query) < 2 and not query.isdigit():
        context['short'] = True
        return render(request, 'search.html', context)
    context['groups'] = search(query)
    rows = [r for g in context['groups'] for r in g['rows']]
    if address and not rows:
        return redirect(reverse('ip_investigation') + '?ip=' + address)
    if len(rows) == 1 and not address and not CVE.match(query):
        return redirect(rows[0]['url'])
    return render(request, 'search.html', context)

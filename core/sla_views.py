"""Configuración de los plazos de atención: activación, valores globales por gravedad y excepciones por cliente."""
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.http import HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_http_methods

from . import sla
from .models import Client, SlaPolicy, SlaSettings
from .security import audit
from .sla_models import SEVERITIES

FIELDS = (('acknowledge', 'acknowledge_minutes', 'Acuse'), ('investigate', 'investigate_minutes', 'Diagnóstico'),
          ('resolve', 'resolve_minutes', 'Resolución'))


REQUEST_FIELDS = ('request_response_minutes', 'request_resolve_minutes', 'request_urgent_response_minutes',
                  'request_urgent_resolve_minutes')


def global_access(user):
    access = getattr(user, 'soc_access', None)
    return user.is_superuser or bool(access and access.all_clients and access.role != 'customer')


def read_table(post, allow_blank):
    """{gravedad: (acuse, diagnóstico, resolución) o None} desde el formulario. ValueError con el motivo."""
    result = {}
    for severity, label in SEVERITIES:
        texts = [post.get(f'{severity}_{key}', '').strip() for key, _, _ in FIELDS]
        if allow_blank and not any(texts):
            result[severity] = None
            continue
        if not all(texts):
            raise ValueError(f'Gravedad {label.lower()}: indica los tres plazos o deja los tres en blanco.')
        values = tuple(sla.parse_duration(text) for text in texts)
        if not values[0] <= values[1] <= values[2]:
            raise ValueError(f'Gravedad {label.lower()}: el acuse no puede ser posterior al diagnóstico ni este a la resolución.')
        result[severity] = values
    return result


def rows_for(table, client=None, overrides=None):
    rows = []
    for severity, label in SEVERITIES:
        values = (overrides or {}).get(severity) if client else table[(None, severity)]
        base = table[(None, severity)]
        rows.append({'severity': severity, 'label': label,
                     'fields': [{'name': f'{severity}_{key}', 'label': text,
                                 'value': sla.duration(values[i]) if values else '',
                                 'placeholder': sla.duration(base[i])} for i, (key, _, text) in enumerate(FIELDS)]})
    return rows


@login_required
@require_http_methods(['GET', 'POST'])
def settings_view(request):
    if not (global_access(request.user) and request.user.has_perm('core.manage_operations')):
        return HttpResponseForbidden('Configurar los plazos requiere acceso global y permiso de operaciones.')
    config, _ = SlaSettings.objects.get_or_create(pk=1)
    client = None
    raw = request.GET.get('client', '') or request.POST.get('client', '')
    if raw:
        client = get_object_or_404(Client, pk=int(raw) if raw.isdigit() else 0)
    error = ''
    if request.method == 'POST':
        action = request.POST.get('action', '')
        try:
            with transaction.atomic():
                if action == 'global':
                    values = read_table(request.POST, allow_blank=False)
                    for severity, (ack, inv, res) in values.items():
                        SlaPolicy.objects.update_or_create(client=None, severity=severity, defaults={
                            'acknowledge_minutes': ack, 'investigate_minutes': inv, 'resolve_minutes': res})
                    enabled = request.POST.get('enabled') == 'on'
                    if enabled and not config.enabled:
                        config.enabled_at = timezone.now()  # solo cuentan los casos nuevos
                    config.enabled = enabled
                    config.save()
                    audit('sla.settings', config, {'status': 'enabled' if enabled else 'disabled'})
                    messages.success(request, 'Plazos guardados.' + (' Cuentan para los casos que entren desde ahora.'
                                                                     if enabled else ' Los plazos están desactivados.'))
                elif action == 'requests':
                    values = {name: sla.parse_duration(request.POST.get(name, '')) for name in REQUEST_FIELDS}
                    for prefix in ('request_', 'request_urgent_'):
                        if values[prefix + 'response_minutes'] > values[prefix + 'resolve_minutes']:
                            raise ValueError('La primera respuesta no puede tener más plazo que la resolución.')
                    for name, minutes in values.items():
                        setattr(config, name, minutes)
                    enabled = request.POST.get('requests_enabled') == 'on'
                    if enabled and not config.requests_enabled:
                        config.requests_enabled_at = timezone.now()  # solo cuentan las solicitudes nuevas
                    config.requests_enabled = enabled
                    config.requests_visible = enabled and request.POST.get('requests_visible') == 'on'
                    config.save()
                    audit('sla.requests', config, {'status': 'enabled' if enabled else 'disabled'})
                    messages.success(request, 'Plazos de las solicitudes guardados.' + (' Cuentan para las que entren desde ahora.'
                                                                                      if enabled else ' Están desactivados.'))
                elif action == 'hours':
                    from . import business_hours
                    enabled = request.POST.get('business_hours_enabled') == 'on'
                    days = business_hours.parse_days(request.POST.getlist('business_days'))
                    start = business_hours.parse_time(request.POST.get('business_start'), 'Inicio de la jornada')
                    end = business_hours.parse_time(request.POST.get('business_end'), 'Fin de la jornada')
                    if start >= end:
                        raise ValueError('El fin de la jornada debe ser posterior al inicio.')
                    holidays = business_hours.parse_holidays(request.POST.get('business_holidays', ''))
                    config.business_hours_enabled = enabled
                    config.business_days = ','.join(str(d) for d in sorted(days))
                    config.business_start, config.business_end = start, end
                    config.business_holidays = [d.isoformat() for d in holidays]
                    config.business_urgent_requests = request.POST.get('business_urgent_requests') == 'on'
                    config.business_minor_incidents = request.POST.get('business_minor_incidents') == 'on'
                    config.save()
                    audit('sla.hours', config, {'status': 'enabled' if enabled else 'disabled', 'count': len(holidays)})
                    messages.success(request, 'Horario laboral guardado.' + (' Los plazos abiertos se recalculan con él.' if enabled else ' Desactivado: los plazos corren en tiempo natural.'))
                elif action == 'client' and client:
                    values = read_table(request.POST, allow_blank=True)
                    for severity, triple in values.items():
                        if triple is None:
                            SlaPolicy.objects.filter(client=client, severity=severity).delete()
                        else:
                            SlaPolicy.objects.update_or_create(client=client, severity=severity, defaults={
                                'acknowledge_minutes': triple[0], 'investigate_minutes': triple[1],
                                'resolve_minutes': triple[2]})
                    audit('sla.client', client, {'count': sum(1 for v in values.values() if v)})
                    messages.success(request, f'Plazos propios de {client.name} guardados. En blanco, se usan los globales.')
                else:
                    raise ValueError('Acción no válida.')
        except ValueError as exc:
            error = str(exc)
        else:
            return redirect(reverse('sla_settings') + (f'?client={client.pk}' if client and action == 'client' else ''))
    table = sla.policies()
    overrides = {}
    if client:
        overrides = {row.severity: (row.acknowledge_minutes, row.investigate_minutes, row.resolve_minutes)
                     for row in SlaPolicy.objects.filter(client=client)}
    with_overrides = Client.objects.filter(sla_policies__isnull=False).distinct().order_by('name')
    return render(request, 'sla_settings.html', {
        'config': config, 'global_rows': rows_for(table), 'client': client, 'error': error,
        'weekdays': [(n, label, str(n) in str(config.business_days).split(',')) for n, label in
                     enumerate(('Lunes', 'Martes', 'Miércoles', 'Jueves', 'Viernes', 'Sábado', 'Domingo'))],
        'holidays_text': '\n'.join(f'{d[8:10]}/{d[5:7]}/{d[:4]}' for d in config.business_holidays),
        'request_rows': [{'label': label, 'fields': [{'name': prefix + key, 'label': text,
                                                      'value': request.POST.get(prefix + key) if error and request.POST.get('action') == 'requests'
                                                      else sla.duration(getattr(config, prefix + key))}
                                                     for key, text in (('response_minutes', 'Primera respuesta'), ('resolve_minutes', 'Resolución'))]}
                         for prefix, label in (('request_', 'Normales'), ('request_urgent_', 'Urgentes o sospecha de incidente'))],
        'client_rows': rows_for(table, client, overrides) if client else None,
        'clients': Client.objects.filter(active=True).order_by('name'), 'with_overrides': with_overrides})

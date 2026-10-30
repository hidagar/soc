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
        'client_rows': rows_for(table, client, overrides) if client else None,
        'clients': Client.objects.filter(active=True).order_by('name'), 'with_overrides': with_overrides})

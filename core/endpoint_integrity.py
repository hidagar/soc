"""Integridad de archivos de los equipos de los clientes (FIM, `syscheck` de Wazuh).

- Entrada: las alertas `syscheck` de los agentes de PC y servidores (`endpoints.observe`, desde `alerts.json`) y su
  recuperación desde el indexador. Solo de equipos asignados y desde su asignación (invariante 2). Una fila por
  alerta, única por equipo e identificador: releer o recuperar no duplica nada.
- El agente de Wazuh vigila por defecto los directorios del sistema (Windows: System32 y claves del registro; Linux:
  /etc, /bin, /sbin, /usr/bin, /usr/sbin, /boot) cada 12 horas. `deploy/wazuh/agente_integridad.conf.example` añade,
  por grupo de cliente, vigilancia en tiempo real de los puntos de arranque automático y de acceso.
- Clasificación por ruta: arranque automático (Run, servicios, tareas programadas, carpeta Inicio, cron, systemd),
  usuarios y permisos (passwd, shadow, sudoers, claves SSH, PAM), resolución de nombres (hosts), configuración,
  programas del sistema y otros. Las tres primeras son «sensibles»: se revisan una a una. El resto se resume por
  equipo y día: una actualización de Windows cambia miles de archivos del sistema.
- Un cambio no prueba una intrusión: la mayoría son instalaciones y actualizaciones (invariante 4). El cliente ve
  el equipo, el tipo de cambio y si el SOC lo ha revisado; nunca la ruta, el usuario ni el proceso (invariante 3).
"""
import re
from datetime import timedelta

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db import IntegrityError, transaction
from django.db.models import Count
from django.db.models.functions import TruncDate
from django.http import HttpResponseForbidden
from django.shortcuts import redirect, render
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_http_methods

from .models import Client, EndpointFileChange, Incident, IncidentUpdate
from .security import audit

EVENTS = {'added': 'added', 'modified': 'modified', 'deleted': 'deleted'}
SENSITIVE = ('persistence', 'identity', 'network')
MAX_AGE = timedelta(days=25)
SUMMARY_DAYS = 7
PORTAL_DAYS = 30
UPDATE_HINT = 50  # tantos programas del sistema en un día en un equipo: probablemente una actualización

# Por orden: la primera que encaja. Rutas en minúsculas, con «/» y sin unidad.
RULES = [
    ('persistence', (r'\\currentversion\\run', r'\\currentversion\\policies\\explorer\\run', r'\\currentcontrolset\\services\\',
                     r'\\currentversion\\winlogon', r'\\image file execution options', r'\\currentversion\\explorer\\shell folders',
                     r'/start menu/programs/startup', r'/system32/tasks/', r'/windows/tasks/', r'/etc/cron', r'/var/spool/cron',
                     r'/etc/systemd/system', r'/lib/systemd/system', r'/usr/lib/systemd/system', r'/etc/init\.d/',
                     r'/etc/rc\.local', r'/etc/rc\d\.d/', r'/etc/ld\.so\.preload', r'/etc/profile\.d/', r'/etc/xdg/autostart/')),
    ('identity', (r'^/etc/(passwd|shadow|group|gshadow)$', r'^/etc/sudoers', r'/\.ssh/authorized_keys', r'^/etc/ssh/sshd_config',
                  r'^/etc/pam\.d/', r'^/etc/security/', r'\\control\\lsa', r'\\sam\\sam\\domains')),
    ('network', (r'/drivers/etc/hosts$', r'^/etc/hosts$', r'^/etc/resolv\.conf$', r'^/etc/nsswitch\.conf$')),
    ('binary', (r'^/(usr/)?s?bin/', r'^/boot/', r'^/usr/local/s?bin/', r'/windows/(system32|syswow64|winsxs)/',
                r'\.(exe|dll|sys|ocx|scr|msi|ps1|bat|cmd|vbs|so)$')),
    ('config', (r'^/etc/', r'^hkey_local_machine\\', r'/windows/')),
]
COMPILED = [(name, [re.compile(p) for p in patterns]) for name, patterns in RULES]


def _clean(value, size):
    from .endpoints import _clean as clean
    return clean(value, size)


def category(path):
    """Categoría de una ruta de archivo o de una clave del registro."""
    text = str(path or '').strip().lower()
    if not text.startswith('hkey_'):
        text = re.sub(r'^[a-z]:', '', text.replace('\\', '/'))
    for name, patterns in COMPILED:
        if any(p.search(text) for p in patterns):
            return name
    return 'other'


def fim_event(source):
    """El bloque `syscheck` si es una alerta de integridad; si no, None."""
    rule = source.get('rule') if isinstance(source.get('rule'), dict) else {}
    groups = rule.get('groups') if isinstance(rule.get('groups'), list) else []
    syscheck = source.get('syscheck') if isinstance(source.get('syscheck'), dict) else None
    if syscheck is None or 'syscheck' not in groups:
        return None
    return syscheck


def record(endpoint, syscheck, stamp, now, source):
    """Guarda un cambio de un equipo asignado. Llamada desde `endpoints.observe` dentro del lote."""
    ident = _clean(source.get('id'), 64)
    path = _clean(syscheck.get('path'), 500)
    event = EVENTS.get(str(syscheck.get('event') or '').strip().lower())
    if not ident or not path or not event or now - stamp > MAX_AGE:
        return
    rule = source.get('rule') if isinstance(source.get('rule'), dict) else {}
    groups = rule.get('groups') if isinstance(rule.get('groups'), list) else []
    audit_data = syscheck.get('audit') if isinstance(syscheck.get('audit'), dict) else {}
    user = audit_data.get('user') if isinstance(audit_data.get('user'), dict) else {}
    process = audit_data.get('process') if isinstance(audit_data.get('process'), dict) else {}
    changed = syscheck.get('changed_attributes')
    kind = category(path)
    try:
        with transaction.atomic():
            EndpointFileChange._base_manager.create(
                agent=endpoint, client_scope_id=endpoint.client_id, event_id=ident, observed_at=stamp, path=path,
                value_name=_clean(syscheck.get('value_name'), 200),
                registry=path.upper().startswith('HKEY_') or any('registry' in str(g) for g in groups),
                event=event, category=kind, sensitive=kind in SENSITIVE, mode=_clean(syscheck.get('mode'), 12),
                changed=[_clean(a, 30) for a in changed[:20]] if isinstance(changed, list) else [],
                sha256=_clean(syscheck.get('sha256_after'), 64) if re.fullmatch(r'[0-9a-fA-F]{64}', str(syscheck.get('sha256_after') or '')) else '',
                actor=_clean(user.get('name'), 120), process=_clean(process.get('name'), 260),
                review='pending' if kind in SENSITIVE else 'reviewed')
    except IntegrityError:
        return  # ya guardado (relectura o recuperación)


# --- SOC ---------------------------------------------------------------------------------------

def review_queue(client_id=None):
    rows = EndpointFileChange.objects.filter(sensitive=True, review='pending').select_related('agent__client')
    if client_id:
        rows = rows.filter(client_scope_id=client_id)
    return list(rows.order_by('-observed_at')[:200])


def badge():
    return EndpointFileChange.objects.filter(sensitive=True, review='pending').count(), False


def daily_summary(changes, now):
    """Cambios no sensibles por equipo, día y categoría en los últimos días, con unas rutas de ejemplo."""
    since = now - timedelta(days=SUMMARY_DAYS)
    rows = list(changes.filter(sensitive=False, observed_at__gte=since)
                .annotate(day=TruncDate('observed_at')).values('agent_id', 'agent__name', 'client_scope_id', 'day', 'category')
                .annotate(count=Count('pk')).order_by('-day', '-count')[:300])
    labels = dict(EndpointFileChange.CATEGORIES)
    for row in rows:
        row['label'] = labels[row['category']]
        row['update'] = row['category'] == 'binary' and row['count'] >= UPDATE_HINT
        row['samples'] = list(changes.filter(agent_id=row['agent_id'], category=row['category'], sensitive=False,
                                             observed_at__date=row['day']).order_by('path')
                              .values_list('path', flat=True).distinct()[:5])
    return rows


@login_required
@never_cache
@require_http_methods(['GET', 'POST'])
def overview(request):
    if not request.user.has_perm('core.manage_operations'):
        return HttpResponseForbidden('Permiso de operaciones requerido.')
    now = timezone.now()
    if request.method == 'POST':
        response = _action(request, now)
        return response if response is not None else redirect(request.get_full_path())
    selected = request.GET.get('client', '')
    shown = request.GET.get('show', 'pending')
    changes = EndpointFileChange.objects.filter(agent__status='assigned')
    if selected.isdigit():
        changes = changes.filter(client_scope_id=int(selected))
    week = changes.filter(observed_at__gte=now - timedelta(days=SUMMARY_DAYS))
    kpis = {'pending': changes.filter(sensitive=True, review='pending').count(),
            'sensitive': week.filter(sensitive=True).count(), 'total': week.count(),
            'devices': week.values('agent').distinct().count()}
    sensitive = changes.filter(sensitive=True).select_related('agent', 'incident')
    if shown == 'pending':
        sensitive = sensitive.filter(review='pending')
    sensitive = list(sensitive.order_by('-observed_at')[:300])
    clients = {c.pk: c for c in Client.objects.all()}
    for row in sensitive:
        row.client = clients.get(row.client_scope_id)
    summary = daily_summary(changes, now)
    for row in summary:
        row['client'] = clients.get(row['client_scope_id'])
    return render(request, 'endpoint_integrity.html', {
        'rows': sensitive, 'summary': summary, 'kpis': kpis, 'clients': Client.objects.filter(active=True),
        'selected_client': selected, 'show': shown, 'can_open_incident': request.user.has_perm('core.add_incident'),
        'summary_days': SUMMARY_DAYS, 'update_hint': UPDATE_HINT})


def _action(request, now):
    action = request.POST.get('action', '')
    if action == 'reviewed_all':
        rows = EndpointFileChange.objects.filter(sensitive=True, review='pending')
        selected = request.POST.get('client', '')
        if selected.isdigit():
            rows = rows.filter(client_scope_id=int(selected))
        agent = request.POST.get('agent', '')
        if agent.isdigit():
            rows = rows.filter(agent_id=int(agent))
        count = rows.update(review='reviewed', reviewed_by=request.user, reviewed_at=now)
        audit('endpoint.file_change_reviewed', None, {'count': count})
        messages.success(request, f'{count} cambio{"s" if count != 1 else ""} marcado{"s" if count != 1 else ""} como revisado{"s" if count != 1 else ""}.')
        return None
    if action not in ('reviewed', 'incident'):
        return HttpResponseForbidden('Acción no válida.')
    pk = request.POST.get('change', '')
    row = EndpointFileChange.objects.filter(pk=int(pk) if pk.isdigit() else 0).select_related('agent__site').first()
    if row is None:
        messages.error(request, 'Ese cambio ya no existe o no está en tu ámbito.')
        return None
    if action == 'reviewed':
        EndpointFileChange.objects.filter(pk=row.pk).update(review='reviewed', reviewed_by=request.user, reviewed_at=now)
        audit('endpoint.file_change_reviewed', row.agent, {'count': 1, 'category': row.category})
        messages.success(request, 'Cambio marcado como revisado.')
        return None
    if not request.user.has_perm('core.add_incident'):
        return HttpResponseForbidden('Tu cuenta no puede abrir incidencias.')
    if row.incident_id:
        return redirect('incident_detail', pk=row.incident_id)
    client = Client.objects.filter(pk=row.client_scope_id).first()
    if client is None:
        return HttpResponseForbidden('Cliente no disponible.')
    target = row.path + (f' (valor {row.value_name})' if row.value_name else '')
    lines = [f'{row.get_event_display()} en {row.get_category_display().lower()} del equipo {row.agent.name} '
             f'(agente Wazuh {row.agent.agent_id}) el {timezone.localtime(row.observed_at):%d/%m/%Y a las %H:%M}: {target}.',
             f'Usuario: {row.actor or "sin dato (activar whodata para saberlo)"} · proceso: {row.process or "sin dato"} · '
             f'modo: {row.mode or "sin indicar"}' + (f' · SHA-256: {row.sha256}' if row.sha256 else '') + '.',
             'Comprobar con el cliente si fue una instalación o un cambio previsto. Un cambio no prueba una intrusión.']
    with transaction.atomic():
        incident = Incident.objects.create(
            client=client, site=row.agent.site, title=f'Cambio en {row.get_category_display().lower()} de {row.agent.name}'[:220],
            description='\n\n'.join(lines), observed_at=row.observed_at, owner=request.user, severity='high')
        IncidentUpdate.objects.create(incident=incident, author=request.user, text='Abierta desde «Integridad de archivos».')
        EndpointFileChange.objects.filter(pk=row.pk).update(review='incident', incident=incident, reviewed_by=request.user,
                                                            reviewed_at=now)
        audit('endpoint.file_change_incident', row.agent, {'incident_id': incident.pk})
    messages.success(request, 'Incidencia interna abierta. El cliente no la ve hasta que se publique.')
    return redirect('incident_detail', pk=incident.pk)


# --- Portal del cliente (proyección explícita, invariante 3) -----------------------------------

PORTAL_LABELS = {'persistence': 'Programas que se ejecutan al arrancar', 'identity': 'Usuarios, contraseñas y permisos',
                 'network': 'Resolución de nombres (archivo hosts o DNS del equipo)'}
PORTAL_EVENTS = {'added': 'Añadido', 'modified': 'Modificado', 'deleted': 'Eliminado'}


def customer_rows(client, now=None):
    """Cambios sensibles de 30 días: fecha, equipo, sede, qué tipo de cambio y si el SOC lo revisó.
    Sin ruta, usuario, proceso ni huella."""
    now = now or timezone.now()
    rows = []
    for row in (EndpointFileChange.objects.filter(client_scope_id=client.pk, sensitive=True,
                                                  observed_at__gte=now - timedelta(days=PORTAL_DAYS))
                .select_related('agent__site').order_by('-observed_at')[:100]):
        rows.append({'observed_at': row.observed_at, 'device': row.agent.name,
                     'site': row.agent.site.name if row.agent.site else '', 'what': PORTAL_LABELS[row.category],
                     'event': PORTAL_EVENTS[row.event],
                     'state': 'El SOC lo revisa' if row.review == 'pending' else 'Revisado por el SOC'})
    return rows


# --- Recuperación desde el indexador -----------------------------------------------------------

def recovery_filter():
    """Alertas que recupera `endpoints.reconcile` (flujo «fim»)."""
    return {'term': {'rule.groups': 'syscheck'}}

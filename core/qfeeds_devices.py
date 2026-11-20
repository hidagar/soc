"""Q-Feeds, plan B: licencia del cliente en su propio firewall OPNsense, vendida y gestionada por ib-red.

- El titular de la licencia es el cliente (EULA de Q-Feeds: uso interno del usuario final, una licencia por
  firewall). ib-red la vende como revendedor y guarda aquí la ficha: plan, usuarios, caducidad, coste,
  precio y la clave del cliente cifrada. La clave nunca se muestra ni se registra.
- La activación usa el plugin oficial `os-q-feeds-connector` (se instala desde la consola del firewall) y el
  control de cambios: el SOC escribe la clave en el plugin, comprueba que descarga las listas de la licencia
  y prepara dos reglas **desactivadas** contra su tabla `__qfeeds_malware_ip` (entrada y salida por WAN).
  Activarlas exige la aprobación, el punto de recuperación y la confirmación de siempre.
- El trabajo `qfeeds_devices` (cada hora) lee las estadísticas del plugin y avisa en «Salud del SOC» si la
  licencia caduca en 30 días o menos, si ya caducó o si el plugin deja de cargar listas con la regla activa.
"""
import re
from datetime import timedelta

from django import forms
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.http import Http404, HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_http_methods

from .models import ChangePlan, Device, OperationalIssue, QFeedsLicense
from .security import audit, decrypt, encrypt

TEMPLATE = 'qfeeds'
VERSION = '1.0'
TITLE = 'Q-Feeds en el firewall (licencia del cliente)'
FEED = 'malware_ip'
TABLE = '__qfeeds_' + FEED  # tabla que crea el plugin con las IPs de la licencia
SETTINGS = '/api/q_feeds/settings/'
RENEWAL_NOTICE = timedelta(days=30)
VENDOR_EVERY = timedelta(hours=24)
EXPIRY_MISMATCH = timedelta(days=7)
KEY = re.compile(r'^[A-Za-z0-9._~+/=-]{16,200}$')


class PublicError(ValueError):
    """Error con un mensaje apto para la página del cambio (sin datos del fabricante ni la clave)."""


def issue_key(device):
    return f'qfeeds-license:{device.pk}'


def candidate_devices():
    """Firewalls OPNsense activos, dentro del ámbito del usuario."""
    return Device.objects.filter(active=True, vendor=Device.Vendor.OPNSENSE).select_related('site__client').order_by(
        'site__client__name', 'name')


class LicenseForm(forms.ModelForm):
    key = forms.CharField(label='Clave de API de la licencia', required=False, strip=True,
                          widget=forms.PasswordInput(attrs={'autocomplete': 'off'}),
                          help_text='La del portal de Q-Feeds del cliente. Se guarda cifrada y no se vuelve a mostrar; '
                                    'déjala vacía al editar para conservarla.')

    class Meta:
        model = QFeedsLicense
        fields = ['device', 'plan', 'users_band', 'starts_on', 'expires_on', 'purchase_price', 'sale_price', 'reference']
        widgets = {'starts_on': forms.DateInput(attrs={'type': 'date'}, format='%Y-%m-%d'),
                   'expires_on': forms.DateInput(attrs={'type': 'date'}, format='%Y-%m-%d')}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        used = QFeedsLicense.objects.exclude(pk=self.instance.pk).values_list('device_id', flat=True)
        self.fields['device'].queryset = candidate_devices().exclude(pk__in=used)
        self.fields['device'].label_from_instance = lambda d: f'{d.site.client.name} · {d.name}'
        self.fields['device'].label = 'Firewall'
        if self.instance.pk:
            self.fields['device'].disabled = True
        for field in self.fields.values():
            field.widget.attrs.setdefault('class', 'input')

    def clean_key(self):
        value = self.cleaned_data.get('key', '')
        if not value and not self.instance.pk:
            raise forms.ValidationError('Indica la clave de la licencia.')
        if value and not KEY.match(value):
            raise forms.ValidationError('La clave no tiene un formato válido.')
        return value

    def clean(self):
        data = super().clean()
        if data.get('starts_on') and data.get('expires_on') and data['expires_on'] <= data['starts_on']:
            self.add_error('expires_on', 'La caducidad debe ser posterior al inicio.')
        return data

    def save(self, commit=True):
        instance = super().save(commit=False)
        if self.cleaned_data.get('key'):
            instance.encrypted_key = encrypt(self.cleaned_data['key'])
            instance.key_hint = self.cleaned_data['key'][-4:]
            instance.vendor_status, instance.vendor_checked_at = {}, None  # se comprueba en la siguiente pasada
        if commit:
            instance.save()
        return instance


def state(item, today=None):
    """(código, texto) del estado comercial de una licencia."""
    today = today or timezone.localdate()
    if item.expires_on < today:
        return 'expired', 'Caducada'
    if item.expires_on - today <= RENEWAL_NOTICE:
        return 'renew', f'Renovar antes del {item.expires_on:%d/%m/%Y}'
    if item.starts_on > today:
        return 'future', 'Aún no empieza'
    return 'active', 'Vigente'


def plan_preview(item):
    device = item.device
    return {'profile': TITLE, 'version': VERSION, 'networks': [], 'interface': 'wan',
            'summary': (f'El SOC configura la clave de la licencia del cliente en el plugin oficial de Q-Feeds de {device.name}, '
                        f'comprueba que descarga la lista «{FEED}» y prepara dos reglas desactivadas contra su tabla {TABLE}: '
                        'entrada y salida por WAN.'),
            'license': item.pk,
            'rules': [{'enabled': '0', 'sequence': '1', 'action': 'block', 'quick': '1', 'interface': 'wan', 'direction': 'in',
                       'ipprotocol': 'inet46', 'protocol': 'any', 'source_net': TABLE, 'destination_net': 'any',
                       'destination_port': '', 'log': '1'},
                      {'enabled': '0', 'sequence': '1', 'action': 'block', 'quick': '1', 'interface': 'wan', 'direction': 'out',
                       'ipprotocol': 'inet46', 'protocol': 'any', 'source_net': 'any', 'destination_net': TABLE,
                       'destination_port': '', 'log': '1'}],
            'checks': ['Instalar antes el plugin os-q-feeds-connector en Sistema › Firmware › Plugins del firewall.',
                       'La cuenta API del SOC necesita el privilegio «Services: QFeeds» además de los de reglas de firewall.',
                       'Si el plugin ya tiene otra clave, la preparación se detiene: revisar en su consola de quién es.',
                       'Las reglas bloquean las IPs de la licencia en entrada y salida por WAN. Revisar excepciones del cliente '
                       '(proveedores, servicios en la nube) en la consola del plugin antes de activar.',
                       'El bloqueo por DNS (Unbound) del plugin no se activa desde el SOC.'],
            'zenarmor': [], 'suricata': []}


def stage_plugin(plan, api, connection, completed):
    """Escribe la clave en el plugin y comprueba que la licencia descarga la lista. Registra el objeto para revertir."""
    item = QFeedsLicense._base_manager.filter(pk=plan.preview.get('license'), device=plan.device).first()
    if item is None:
        raise PublicError('La licencia de Q-Feeds ya no está asociada a este firewall.')
    try:
        current = api(connection, SETTINGS + 'get')
    except Exception:
        raise PublicError('El firewall no responde a la API del plugin de Q-Feeds: instala os-q-feeds-connector y '
                          'da a la cuenta API el privilegio «Services: QFeeds».') from None
    general = ((current.get('connect') or {}).get('general') or {}) if isinstance(current, dict) else {}
    present = str(general.get('apikey') or '')
    key = decrypt(item.encrypted_key)
    if present and present != key:
        raise PublicError('El plugin de Q-Feeds de este firewall ya tiene otra clave. Revisar en su consola antes de continuar.')
    description = f'SOC PLAN {plan.pk} qfeeds'
    if not present:
        response = api(connection, SETTINGS + 'set', {'connect': {'general': {'apikey': key, 'enable_unbound_bl': '0'}}})
        if response.get('result') != 'saved':
            raise PublicError('El plugin de Q-Feeds no aceptó la clave.')
    if not any(o.get('kind') == 'qfeeds' for o in plan.remote_objects):
        # Solo se retira al revertir si la puso el SOC; nunca se guarda la clave en el plan.
        plan.remote_objects.append({'kind': 'qfeeds', 'uuid': f'license-{item.pk}',
                                    'rule': {'description': description, 'set_by_soc': not present, 'license': item.pk}})
        plan.save(update_fields=['remote_objects'])
    if not completed(api(connection, SETTINGS + 'reconfigure', {})):
        raise PublicError('El plugin de Q-Feeds no confirmó la descarga de las listas.')
    rows = api(connection, SETTINGS + 'search_feeds').get('rows') or []
    if not any(r.get('feed_type') == FEED and str(r.get('licensed')) == '1' for r in rows if isinstance(r, dict)):
        raise PublicError(f'La licencia no incluye la lista «{FEED}» o Q-Feeds la ha rechazado.')


def rollback_plugin(obj, api, connection, delete):
    """Retira la clave solo si la puso el SOC y sigue siendo la de la licencia; si no, intervención manual."""
    if not delete or not obj['rule'].get('set_by_soc'):
        return
    item = QFeedsLicense._base_manager.filter(pk=obj['rule'].get('license')).first()
    current = api(connection, SETTINGS + 'get')
    present = str((((current.get('connect') or {}).get('general') or {}).get('apikey')) or '')
    if present and (item is None or present != decrypt(item.encrypted_key)):
        raise ValueError('La clave del plugin de Q-Feeds cambió fuera del panel; intervención manual requerida.')
    if present:
        response = api(connection, SETTINGS + 'set', {'connect': {'general': {'apikey': ''}}})
        if response.get('result') != 'saved':
            raise ValueError('No se pudo retirar la clave del plugin de Q-Feeds.')
        api(connection, SETTINGS + 'reconfigure', {})


def _read_plugin(item):
    from .change_control import api
    connection = item.device.opnsense_api
    stats = api(connection, SETTINGS + 'stats')
    totals = stats.get('totals') if isinstance(stats.get('totals'), dict) else {}
    license_info = stats.get('license') if isinstance(stats.get('license'), dict) else {}

    def number(value):
        return int(value) if isinstance(value, int) or (isinstance(value, str) and value.isdigit()) else 0
    return {'entries': number(totals.get('entries')), 'packets_blocked': number(totals.get('packets_blocked')),
            'addresses_blocked': number(totals.get('addresses_blocked')),
            'feeds': [str(f.get('name'))[:40] for f in stats.get('feeds') or [] if isinstance(f, dict)][:10],
            'license_expiry': str(license_info.get('expiry_date') or '')[:32]}


def vendor_check(item, now):
    """Comprueba la clave del cliente en Q-Feeds (`licenses.php`): si la acepta, su caducidad y si incluye la lista.

    Solo se descarga el índice de la licencia: no se envía ninguna IP ni dato del cliente.
    """
    from .threat_intel import MAX_INDEX, FeedError, _get, _iso
    try:
        index = _get('/licenses.php', None, decrypt(item.encrypted_key), MAX_INDEX)
    except FeedError as exc:
        status = {'ok': False, 'error': {401: 'Q-Feeds rechaza la clave.', 403: 'Q-Feeds rechaza la clave o ha caducado.'}.get(
            exc.status, 'Sin respuesta de Q-Feeds.'), 'rejected': exc.status in (401, 403)}
    else:
        company = index.get('company_info') if isinstance(index, dict) and isinstance(index.get('company_info'), dict) else {}
        feeds = index.get('feeds') if isinstance(index, dict) and isinstance(index.get('feeds'), list) else []
        status = {'ok': True, 'expires': _iso(company.get('token_expiration')), 'premium': bool(company.get('premium_access')),
                  'feeds': sorted(str(f.get('feed_type'))[:40] for f in feeds if isinstance(f, dict) and f.get('licensed'))[:10]}
    QFeedsLicense._base_manager.filter(pk=item.pk).update(vendor_status=status, vendor_checked_at=now)
    return status


def vendor_problem(item, status):
    """Texto del problema que muestra la comprobación en Q-Feeds, o ''."""
    from django.utils.dateparse import parse_datetime
    if not status:
        return ''
    if status.get('rejected'):
        return status.get('error') or 'Q-Feeds rechaza la clave.'
    if not status.get('ok'):
        return ''  # sin respuesta: se reintenta, no es un problema de la licencia
    if FEED not in (status.get('feeds') or []):
        return f'Según Q-Feeds, la licencia no incluye la lista «{FEED}».'
    expires = parse_datetime(status.get('expires') or '')
    if expires and abs(timezone.localdate(expires) - item.expires_on) > EXPIRY_MISMATCH:
        return (f'Q-Feeds indica que la licencia caduca el {timezone.localtime(expires):%d/%m/%Y}; en la ficha consta el '
                f'{item.expires_on:%d/%m/%Y}. Revisar la ficha.')
    return ''


def check(now=None):
    """Trabajo `qfeeds_devices`: lee el plugin de cada firewall con licencia y avisa de caducidades y fallos."""
    from .operations import set_issue
    now = now or timezone.now()
    today = timezone.localdate(now)
    checked = 0
    for item in QFeedsLicense._base_manager.select_related('device__site__client', 'device__opnsense_api'):
        device = item.device
        active_rule = ChangePlan._base_manager.filter(device=device, template=TEMPLATE, status='active').exists()
        status = dict(item.plugin_status or {})
        if device.vendor == Device.Vendor.OPNSENSE and hasattr(device, 'opnsense_api') and (
                active_rule or ChangePlan._base_manager.filter(device=device, template=TEMPLATE, status='staged').exists()):
            try:
                status = _read_plugin(item)
            except Exception:
                status = {'error': 'Sin respuesta del plugin de Q-Feeds por la API.'}
            QFeedsLicense._base_manager.filter(pk=item.pk).update(plugin_status=status, checked_at=now)
            checked += 1
        vendor = item.vendor_status or {}
        if not item.vendor_checked_at or now - item.vendor_checked_at >= VENDOR_EVERY:
            vendor = vendor_check(item, now)
        code, label = state(item, today)
        problem, severity = '', 'warning'
        mismatch = vendor_problem(item, vendor)
        if code == 'expired':
            problem, severity = f'La licencia de Q-Feeds de {device.name} caducó el {item.expires_on:%d/%m/%Y}.', 'critical'
        elif active_rule and status.get('error'):
            problem = 'El plugin de Q-Feeds no responde por la API y la regla está activa.'
        elif active_rule and not status.get('entries'):
            problem = 'La regla de Q-Feeds está activa, pero el plugin no tiene ninguna IP cargada (licencia o descarga).'
        elif mismatch:
            problem, severity = mismatch, ('critical' if vendor.get('rejected') and active_rule else 'warning')
        elif code == 'renew':
            problem = f'La licencia de Q-Feeds de {device.name} caduca el {item.expires_on:%d/%m/%Y}: renovarla con el cliente.'
        if problem:
            set_issue(issue_key(device), 'Licencia de Q-Feeds', device=device, details=problem, severity=severity, now=now)
        else:
            OperationalIssue.objects.filter(key=issue_key(device), active=True).update(active=False, resolved_at=now)
    return checked


@login_required
@require_http_methods(['GET', 'POST'])
def licenses(request):
    """Licencias de Q-Feeds por firewall: alta, edición, baja y preparación con el control de cambios."""
    from .security import mfa_fresh
    if not request.user.has_perm('core.manage_operations'):
        return HttpResponseForbidden('Permiso de operaciones requerido.')
    editing = None
    form = None
    if request.method == 'POST' or request.GET.get('edit') or request.GET.get('new'):
        if not request.user.has_perm('core.manage_connections'):
            return HttpResponseForbidden('Permiso de conexiones requerido.')
        if not mfa_fresh(request):
            return redirect('mfa_challenge')
        pk = request.POST.get('license') or request.GET.get('edit') or ''
        if pk:
            if not str(pk).isdigit():
                raise Http404
            editing = get_object_or_404(QFeedsLicense.objects.select_related('device__site__client'), pk=int(pk))
        action = request.POST.get('action', 'save')
        if request.method == 'POST' and action == 'delete' and editing:
            if ChangePlan.objects.filter(device=editing.device, template=TEMPLATE,
                                         status__in=['staged', 'apply_queued', 'applying', 'awaiting_confirmation',
                                                     'confirm_queued', 'active']).exists():
                messages.error(request, 'Revierte antes el cambio de Q-Feeds de este firewall.')
                return redirect('qfeeds_licenses')
            with transaction.atomic():
                audit('qfeeds.license_deleted', editing.device)
                OperationalIssue.objects.filter(key=issue_key(editing.device), active=True).update(
                    active=False, resolved_at=timezone.now())
                editing.delete()
            messages.success(request, 'Licencia retirada de la ficha. La clave sigue en el plugin del firewall si se configuró.')
            return redirect('qfeeds_licenses')
        if request.method == 'POST' and action == 'plan' and editing:
            device = editing.device
            if device.management_method != Device.ManagementMethod.API or not hasattr(device, 'opnsense_api'):
                messages.error(request, 'Este firewall no tiene la conexión API de OPNsense: configura el plugin desde su consola.')
                return redirect('qfeeds_licenses')
            if state(editing)[0] == 'expired':
                messages.error(request, 'La licencia está caducada.')
                return redirect('qfeeds_licenses')
            plan = ChangePlan.objects.create(device=device, template=TEMPLATE, template_version=VERSION, title=TITLE,
                                             parameters={'client': device.site.client_id, 'license': editing.pk},
                                             preview=plan_preview(editing), requested_by=request.user)
            audit('change.draft', plan, {'template': TEMPLATE})
            return redirect('change_detail', pk=plan.pk)
        form = LicenseForm(request.POST or None, instance=editing)
        if request.method == 'POST' and form.is_valid():
            with transaction.atomic():
                item = form.save(commit=False)
                if not item.pk:
                    item.created_by = request.user
                item.save()
                audit('qfeeds.license_saved', item.device, {'fields': sorted(f for f in form.changed_data if f != 'key')})
            messages.success(request, 'Licencia guardada.')
            return redirect('qfeeds_licenses')
    today = timezone.localdate()
    rows = list(QFeedsLicense.objects.select_related('device__site__client'))
    plans = {}
    for plan in ChangePlan.objects.filter(template=TEMPLATE).order_by('pk'):
        plans[plan.device_id] = plan
    totals = {'count': len(rows), 'sale': 0, 'cost': 0, 'renew': 0}
    for item in rows:
        item.state_code, item.state_label = state(item, today)
        item.vendor_problem = vendor_problem(item, item.vendor_status)
        item.plan_row = plans.get(item.device_id)
        totals['sale'] += item.sale_price or 0
        totals['cost'] += item.purchase_price or 0
        totals['renew'] += item.state_code in ('renew', 'expired')
    totals['margin'] = totals['sale'] - totals['cost']
    return render(request, 'qfeeds_licenses.html', {
        'rows': rows, 'form': form, 'editing': editing, 'totals': totals,
        'can_manage': request.user.has_perm('core.manage_connections')})

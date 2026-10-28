"""Small, persistent wizard. Credentials use the existing encrypted connection forms."""
import ipaddress
import uuid

from django import forms
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.http import Http404, HttpResponseForbidden, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET, require_http_methods

from .forms import SiteForm, StyledModelForm
from .models import Client, Device, ExportConfiguration, FirewallOnboarding, Site, OpnsenseConnection, SshConnection, UnifiCloudConnection
from .provisioning import available_destinations, PORT


class EquipmentForm(StyledModelForm):
    vendor = forms.ChoiceField(label='Fabricante / solución', choices=[
        ('', 'Elige el firewall'), ('opnsense', 'OPNsense'),
        ('opnsense_zenarmor', 'OPNsense + Zenarmor'), ('unifi', 'UniFi'),
        ('hillstone', 'Hillstone'), ('grandstream_gcc', 'Grandstream GCC'), ('other', 'Otro'),
    ])

    class Meta:
        model = Device
        fields = ['name', 'vendor', 'mac_address']

    def clean_vendor(self):
        choice = self.cleaned_data['vendor']
        self.with_zenarmor = choice == 'opnsense_zenarmor'
        return 'opnsense' if self.with_zenarmor else choice

    def save(self, commit=True):
        device = super().save(commit=False)
        device.zenarmor_enabled = self.with_zenarmor
        if commit:
            device.save()
        return device


class MethodForm(forms.Form):
    method = forms.ChoiceField(label='¿Cómo quieres conectarlo?', widget=forms.RadioSelect)

    def __init__(self, *args, device, can_manage, **kwargs):
        super().__init__(*args, **kwargs)
        # Primero lo recomendado: si el panel puede configurarlo solo, mejor que a mano.
        choices = []
        if can_manage and device.vendor in ('unifi', 'opnsense'):
            choices.append(('api', 'API · el panel configura el envío por ti (recomendado)'))
        if can_manage and device.vendor == 'opnsense':
            choices.append(('ssh', 'SSH · el panel configura el envío por ti'))
        if can_manage:
            choices.append(('https', 'IP dinámica · envío por HTTPS con clave del equipo, sin VPN'))
        choices.append(('manual', 'Manual · el envío ya está configurado en el equipo o lo configuras tú'))
        self.fields['method'].choices = choices
        if self.initial.get('method') not in [value for value, _ in choices]:
            self.initial['method'] = choices[0][0]
        if device.vendor == 'opnsense':
            self.fields['profile'] = forms.ChoiceField(
                label='Solución del firewall', required=False,
                choices=[('opnsense', 'OPNsense'), ('opnsense_zenarmor', 'OPNsense + Zenarmor')],
                initial='opnsense_zenarmor' if device.zenarmor_enabled else 'opnsense',
                widget=forms.Select(attrs={'class': 'input'}),
            )


def source_conflict(source, device):
    # A shared NAT source cannot prove which individual firewall sent the event.
    return ExportConfiguration.objects.filter(
        source_ip=source, device__active=True, device__site__active=True,
    ).exclude(device=device).exists()


class ExportForm(forms.Form):
    destination = forms.ChoiceField(label='Destino de los logs', widget=forms.Select(attrs={'class': 'input'}))
    source_ip = forms.GenericIPAddressField(
        label='IP de origen que llegará al SOC', protocol='IPv4',
        widget=forms.TextInput(attrs={'class': 'input', 'placeholder': 'IP de salida del firewall o del NAT'}),
        help_text='Por Internet suele ser la IP pública de salida. Por enlace privado o VPN, la IP usada en esa ruta. No es necesariamente la IP de gestión.',
    )
    configured = forms.BooleanField(label='He guardado el envío de logs en el firewall', required=False)

    def __init__(self, *args, device, method, **kwargs):
        super().__init__(*args, **kwargs)
        self.device = device
        self.method = method
        self.fields['source_ip'].required = method == FirewallOnboarding.Method.MANUAL
        if method != FirewallOnboarding.Method.MANUAL:
            self.fields['source_ip'].help_text += ' Puedes dejarla vacía al configurar la conexión: si la API la descubre, aparecerá al volver. Confírmala antes de comprobar la recepción.'
        addresses = available_destinations()
        current_public = addresses[-1]
        choices = [(current_public, f'{current_public} · soc.ibred.es · acceso público' if len(addresses) > 1 else f'{current_public} · red privada')]
        choices.extend((ip, f'{ip} · red privada' if index == 0 else f'{ip} · dirección anterior')
                       for index, ip in enumerate(addresses) if ip != current_public)
        self.fields['destination'].choices = choices
        self.fields['configured'].required = method == FirewallOnboarding.Method.MANUAL
        if method != FirewallOnboarding.Method.MANUAL:
            self.fields.pop('configured')
        if device.zenarmor_enabled:
            self.fields['zenarmor_configured'] = forms.BooleanField(
                label='He guardado la exportación Syslog de Zenarmor con Alerts', required=False,
            )

    def clean(self):
        values = super().clean()
        if self.data.get('action') != 'connection':
            if not values.get('source_ip'):
                self.add_error('source_ip', 'Confirma la IP de origen de los logs antes de comprobar la recepción.')
            if self.device.zenarmor_enabled and not values.get('zenarmor_configured'):
                self.add_error('zenarmor_configured', 'Configura la exportación de Zenarmor antes de verificar ambas fuentes. Si no está disponible en tu edición, puedes elegir OPNsense en el paso anterior.')
        return values

    def clean_source_ip(self):
        value = self.cleaned_data['source_ip']
        if not value:
            return None
        ip = ipaddress.ip_address(value)
        if ip.is_unspecified or ip.is_multicast or ip.is_loopback or str(ip) == '255.255.255.255':
            raise forms.ValidationError('Indica una IP de origen de un equipo, no una dirección de difusión o local.')
        if source_conflict(value, self.device):
            raise forms.ValidationError('Esta IP ya pertenece a otro equipo. Usa un origen distinto (por ejemplo una IP propia por VPN) para identificar este firewall sin mezclar los datos.')
        return value


def _nonce(request, key):
    tokens = request.session.get('onboarding_tokens', {})
    if key not in tokens:
        tokens[key] = {'token': uuid.uuid4().hex}
        request.session['onboarding_tokens'] = dict(list(tokens.items())[-20:])
    return tokens[key]


def _consume_nonce(request, key, url):
    tokens = request.session['onboarding_tokens']
    tokens[key]['url'] = url
    request.session['onboarding_tokens'] = tokens


def _nonce_error(request, nonce, form):
    if request.POST.get('creation_token') != nonce['token']:
        form.add_error(None, 'Este formulario ha caducado. Recarga la página antes de continuar.')
        return True
    return False


@login_required
@never_cache
@require_http_methods(['GET', 'POST'])
def new_site(request):
    client_id = request.GET.get('client', '')
    selected = None
    if client_id:
        if not client_id.isascii() or not client_id.isdecimal() or len(client_id) > 18:
            raise Http404('Cliente no válido')
        selected = get_object_or_404(Client, pk=int(client_id))
    form = SiteForm(request.POST or None, selected_client=selected)
    form.fields['code'].label = 'Identificador (opcional)'
    key = f'site:{selected.pk if selected else "any"}'
    nonce = _nonce(request, key)
    if request.method == 'GET' and nonce.get('url'):
        tokens = request.session['onboarding_tokens']
        tokens.pop(key)
        request.session['onboarding_tokens'] = tokens
        nonce = _nonce(request, key)
    if request.method == 'POST' and form.is_valid() and not _nonce_error(request, nonce, form):
        if nonce.get('url'):
            return redirect(nonce['url'])
        site = form.save()
        url = reverse('onboarding_add_device', args=[site.pk])
        _consume_nonce(request, key, url)
        return redirect(url)
    cancel = reverse('client_detail', args=[selected.pk]) if selected else reverse('client_list')
    return render(request, 'onboarding.html', {'step': 1, 'form': form, 'selected_client': selected,
                                             'cancel_url': cancel, 'creation_token': nonce['token']})


@login_required
@never_cache
@require_http_methods(['GET', 'POST'])
def add_device(request, site_pk):
    site = get_object_or_404(Site.objects.select_related('client'), pk=site_pk)
    form = EquipmentForm(request.POST or None)
    key = f'device:{site.pk}'
    nonce = _nonce(request, key)
    if request.method == 'GET' and nonce.get('url'):
        tokens = request.session['onboarding_tokens']
        tokens.pop(key)
        request.session['onboarding_tokens'] = tokens
        nonce = _nonce(request, key)
    if request.method == 'POST' and form.is_valid() and not _nonce_error(request, nonce, form):
        if nonce.get('url'):
            return redirect(nonce['url'])
        from django.db import IntegrityError
        try:
            with transaction.atomic():
                device = form.save(commit=False)
                device.site = site
                device.save()
                FirewallOnboarding.objects.create(device=device)
        except IntegrityError:
            mac = form.cleaned_data.get('mac_address')
            if not mac or not Device._base_manager.filter(mac_address=mac).exists():
                raise
            form.add_error('mac_address', 'Esta MAC ya está registrada en otro equipo.')
        else:
            url = reverse('device_onboarding', args=[device.pk])
            _consume_nonce(request, key, url)
            return redirect(url)
    return render(request, 'onboarding.html', {'step': 2, 'site': site, 'form': form,
                                             'cancel_url': reverse('site_detail', args=[site.pk]),
                                             'creation_token': nonce['token']})


def _connection_url(device, method):
    if method == 'api':
        return reverse('unifi_cloud' if device.vendor == 'unifi' else 'opnsense_api', args=[device.pk])
    return reverse('ssh_connection', args=[device.pk])


def _config(device):
    return ExportConfiguration.objects.filter(device=device).first()


def _automatic_ready(device, method):
    if method in ('manual','https'):
        return True
    model = SshConnection if method == 'ssh' else UnifiCloudConnection if device.vendor == 'unifi' else OpnsenseConnection
    return model.objects.filter(device=device, last_ok=True).exists()


@login_required
@never_cache
@require_http_methods(['GET', 'POST'])
def device_wizard(request, pk):
    device = get_object_or_404(Device.objects.select_related('site__client'), pk=pk)
    row = FirewallOnboarding.objects.filter(device=device).first()
    # GET may show the wizard for a legacy device; it never creates records or changes its export.
    row = row or FirewallOnboarding(device=device)
    step = row.step
    requested = request.GET.get('step')
    if requested in ('3', '4') and int(requested) <= step and not row.verified_at:
        step = int(requested)
    can_manage = request.user.has_perm('core.manage_connections')
    config = _config(device)
    automatic_ready = _automatic_ready(device, row.method)
    error = ''
    form = None
    if step == 3:
        form = MethodForm(request.POST or None, device=device, can_manage=can_manage, initial={'method': row.method if config or row.pk and row.method != 'manual' else None})
        if request.method == 'POST' and form.is_valid():
            if config is not None and not can_manage:
                return HttpResponseForbidden('Tu cuenta necesita permiso de conexiones para cambiar una integración existente.')
            method = form.cleaned_data['method']
            with transaction.atomic():
                row.method, row.step = method, 4
                row.verification_started_at = row.verified_at = row.event_at = None
                row.zenarmor_event_at = None
                row.event_decoder = row.event_rule = row.verification_error = ''
                row.save()
                if method!='https':device.management_method = 'none' if method=='manual' else method
                if device.vendor == 'opnsense' and form.cleaned_data.get('profile'):
                    device.zenarmor_enabled = form.cleaned_data['profile'] == 'opnsense_zenarmor'
                device.integration = Device.Integration.PENDING
                device.save(update_fields=['management_method', 'integration', 'zenarmor_enabled'])
                if config:
                    config.receiver_ready = False
                    config.save(update_fields=['receiver_ready'])
            return redirect('device_onboarding', pk=pk)
    elif step == 4:
        if row.method=='https':return redirect('secure_log_setup',pk=pk)
        form = ExportForm(request.POST or None, device=device, method=row.method, initial={
            'destination': config.destination if config else available_destinations()[-1],
            'source_ip': config.source_ip if config else '',
        })
        if request.method == 'POST':
            if not can_manage:
                return HttpResponseForbidden('Tu cuenta necesita permiso para gestionar conexiones y autorizar un origen de logs.')
            if form.is_valid():
                action = request.POST.get('action', 'verify')
                if action not in ('connection', 'verify'):
                    form.add_error(None, 'Acción no válida.')
                elif row.method == 'manual' and action == 'connection':
                    form.add_error(None, 'La configuración manual no necesita API ni SSH.')
                else:
                    # serialize the uniqueness check with all wizard registrations
                    with transaction.atomic():
                        if source_conflict(form.cleaned_data['source_ip'], device):
                            form.add_error('source_ip', 'Esta IP acaba de registrarse en otro equipo. Elige un origen distinto.')
                        else:
                            config, _ = ExportConfiguration.objects.get_or_create(device=device)
                            chosen_source = form.cleaned_data['source_ip'] or config.source_ip
                            changed = config.destination != form.cleaned_data['destination'] or config.source_ip != chosen_source
                            config.destination = form.cleaned_data['destination']
                            config.source_ip = chosen_source
                            config.port = PORT
                            if changed:
                                config.receiver_ready = False
                                config.status = ExportConfiguration.Status.PENDING
                            if row.method == 'manual':
                                config.status = ExportConfiguration.Status.CONFIGURED
                                config.configured_at = timezone.now()
                                config.last_error = ''
                            config.save()
                            if action == 'connection':
                                return redirect(_connection_url(device, row.method))
                            if config.status != ExportConfiguration.Status.CONFIGURED or not automatic_ready:
                                form.add_error(None, 'Completa y verifica primero la conexión automática, o vuelve al paso anterior y elige «Solo envío de logs».')
                            else:
                                row.step = 5
                                row.verification_started_at = timezone.now()
                                row.verified_at = row.event_at = None
                                row.zenarmor_event_at = None
                                row.event_decoder = row.event_rule = row.verification_error = ''
                                row.save()
                                device.log_method = Device.LogMethod.SYSLOG
                                device.integration = Device.Integration.PENDING
                                device.save(update_fields=['log_method', 'integration'])
                                messages.info(request, 'Comprobación iniciada. El SOC preparará el receptor y buscará un evento nuevo de este equipo.')
                                return redirect('device_onboarding', pk=pk)
    else:
        step = 5
        if request.method == 'POST':
            return HttpResponseForbidden('El estado activo solo se confirma al recibir un evento real.')
    return render(request, 'onboarding.html', {
        'step': step, 'form': form, 'device': device, 'site': device.site, 'onboarding': row,
        'export': config, 'can_manage': can_manage, 'error_message': error,
        'destination': (form['destination'].value() if form and step == 4 else config.destination if config else available_destinations()[-1]),
        'port': PORT, 'cancel_url': reverse('site_detail', args=[device.site_id]),
        'status_url': reverse('onboarding_status', args=[pk]),
        'automatic_ready': automatic_ready,
        'auto': row.method not in ('manual', 'https'),
        'ready': bool(config and config.status == ExportConfiguration.Status.CONFIGURED and automatic_ready),
    })


@login_required
@never_cache
@require_GET
def status(request, pk):
    device = get_object_or_404(Device, pk=pk)
    row = get_object_or_404(FirewallOnboarding.objects.select_related('device'), device=device)
    config = _config(row.device)
    return JsonResponse({
        'receiver_ready': bool(config and config.receiver_ready),
        'verified': bool(row.verified_at),
        'event_at': timezone.localtime(row.event_at).strftime('%d/%m/%Y %H:%M:%S') if row.event_at else '',
        'decoder': row.event_decoder, 'rule': row.event_rule,
        'error': row.verification_error,
        'checked_at': timezone.localtime(row.checked_at).strftime('%H:%M:%S') if row.checked_at else '',
        'opnsense_received': bool(row.event_at),
        'zenarmor_required': row.device.zenarmor_enabled,
        'zenarmor_received': bool(row.zenarmor_event_at),
    })

from datetime import timedelta
from django import forms
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_http_methods
from .models import Client, Device, DeviceHealth, NetworkCoverage
from .network_coverage import snapshot
from .security import audit


class NetworkForm(forms.ModelForm):
    class Meta:
        model = NetworkCoverage
        fields = ['scope', 'require_ips', 'require_zenarmor', 'review_note', 'review_until']
        widgets = {'review_note': forms.Textarea(attrs={'rows': 3}),
            'review_until': forms.DateTimeInput(attrs={'type': 'datetime-local'}, format='%Y-%m-%dT%H:%M')}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance.device.vendor != 'opnsense':
            self.fields.pop('require_zenarmor')
        self.fields['review_note'].max_length = 4000
        for field in self.fields.values():
            field.widget.attrs['class'] = 'input'

    def clean(self):
        values = super().clean()
        if values.get('scope') == 'excluded':
            if not (values.get('review_note') or '').strip():
                self.add_error('review_note', 'Explica por qué esta red queda excluida del servicio.')
            until = values.get('review_until')
            if not until or not timezone.now() < until <= timezone.now() + timedelta(days=180):
                self.add_error('review_until', 'Define una fecha futura de revisión, como máximo a 180 días.')
        elif values.get('review_until'):
            self.add_error('review_until', 'La fecha de revisión se utiliza para una exclusión documentada.')
        return values


@login_required
@require_http_methods(['GET', 'POST'])
def coverage(request, pk=None):
    device = get_object_or_404(Device.objects.select_related('site__client'), pk=pk) if pk else None
    selected = request.GET.get('client', '')
    if selected and not selected.isdigit():
        selected = ''
    if selected:
        get_object_or_404(Client, pk=selected)
    if request.method == 'POST':
        if not device or not request.user.has_perm('core.manage_operations'):
            return HttpResponseForbidden()
        health, _ = DeviceHealth.objects.get_or_create(device=device)
        health.checked_at = None
        health.save(update_fields=['checked_at', 'updated_at'])
        audit('network.recheck_requested', device)
        messages.success(request, 'Consulta de lectura solicitada al monitor. Conservamos los datos anteriores hasta completarla.')
        return redirect('device_coverage', pk=device.pk)
    devices = Device.objects.filter(active=True, site__active=True, site__client__active=True).select_related('site__client', 'network_check', 'health')
    networks = NetworkCoverage.objects.select_related('device__site__client', 'device__health', 'device__network_check')
    if device:
        devices = devices.filter(pk=device.pk)
        networks = networks.filter(device=device)
    elif selected:
        devices = devices.filter(site__client_id=selected)
        networks = networks.filter(device__site__client_id=selected)
    else:
        networks = networks.filter(device__active=True, device__site__active=True, device__site__client__active=True)
    mode = request.GET.get('view', 'current')
    networks = networks.filter(present=mode != 'removed')
    from .zenarmor_scope import device_snapshot
    return render(request, 'network_coverage.html', {'device': device,
        'rows': [snapshot(n) for n in networks[:500]], 'devices': devices,
        'clients': Client.objects.all(), 'selected_client': selected, 'view': mode,
        'zenarmor_devices': [device_snapshot(d) for d in devices if d.vendor == 'opnsense' and d.zenarmor_enabled],
        'count': networks.count()})


@login_required
@require_http_methods(['GET', 'POST'])
def requirements(request, pk):
    network = get_object_or_404(NetworkCoverage.objects.select_related('device__site__client'), pk=pk)
    if not request.user.has_perm('core.manage_operations'):
        return HttpResponseForbidden()
    form = NetworkForm(request.POST or None, instance=network)
    if request.method == 'POST' and form.is_valid():
        form.save()
        audit('network.requirements', network, {'fields': form.changed_data})
        messages.success(request, 'Ámbito y requisitos guardados. No se ha cambiado la configuración del firewall.')
        return redirect('device_coverage', pk=network.device_id)
    return render(request, 'network_requirements.html', {'form': form, 'network': network})

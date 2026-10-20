from datetime import timedelta
from django import forms
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.http import HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.debug import sensitive_post_parameters
from django.views.decorators.http import require_http_methods
from .models import Device, GdmsConnection
from .security import audit
from . import gdms_api as api


class ConnectionForm(forms.Form):
    region = forms.ChoiceField(label='Región de GDMS Networking', choices=[('eu', 'Europa'), ('us', 'Estados Unidos')])
    app_id = forms.CharField(label='APP ID', max_length=120)
    secret = forms.CharField(label='Secret Key', max_length=4096, required=False, strip=False, widget=forms.PasswordInput)
    restricted = forms.BooleanField(label='En GDMS tengo activado «Restrict APIs to specific networks»', required=False)
    username = forms.CharField(label='Usuario o correo de GDMS (solo con restricción por redes)', max_length=254, required=False)
    password = forms.CharField(label='Contraseña de GDMS (solo con restricción por redes)', max_length=4096, required=False, strip=False, widget=forms.PasswordInput)

    def __init__(self, *args, connection=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.connection = connection
        for field in self.fields.values():
            if not isinstance(field.widget, forms.CheckboxInput): field.widget.attrs['class'] = 'input'
        for name in ('secret', 'password'):
            self.fields[name].widget.attrs['autocomplete'] = 'new-password'
            self.fields[name].help_text = 'Déjalo vacío para conservar el valor guardado si no cambias la identidad de la conexión.'

    def clean(self):
        values = super().clean()
        previous = self.connection
        same = previous and all(values.get(k) == getattr(previous, k) for k in ('region', 'app_id', 'restricted', 'username'))
        if not values.get('restricted'):
            values['username'] = ''
            values['password'] = ''
        if not values.get('secret') and not same:
            self.add_error('secret', 'Introduce Secret Key al crear la conexión o cambiar sus datos.')
        if values.get('restricted'):
            if not values.get('username'): self.add_error('username', 'Indica el usuario de GDMS.')
            if not values.get('password') and not (same and previous.encrypted_password):
                self.add_error('password', 'Introduce la contraseña de GDMS para esta conexión restringida.')
        try:
            for key in ('app_id', 'secret', 'username', 'password'):
                if values.get(key): api.credential(values[key], self.fields[key].label)
        except api.GdmsError as exc:
            raise forms.ValidationError(str(exc)) from None
        return values


@login_required
@never_cache
@sensitive_post_parameters('secret', 'password')
@require_http_methods(['GET', 'POST'])
def gdms_cloud(request, pk):
    if not request.user.has_perm('core.manage_connections'):
        return HttpResponseForbidden('Tu cuenta no tiene permiso para gestionar conexiones.')
    device = get_object_or_404(Device.objects.select_related('site__client'), pk=pk, vendor=Device.Vendor.GRANDSTREAM_GCC)
    stored = GdmsConnection.objects.filter(device=device).first()
    connection = stored if stored and stored.client_scope_id == device.site.client_id else None
    initial = {k: getattr(connection, k) for k in ('region', 'app_id', 'restricted', 'username')} if connection else {'region': 'eu'}
    form = ConnectionForm(request.POST if request.method == 'POST' and request.POST.get('action') == 'save' else None,
                          initial=initial, connection=connection)
    error_message = ''
    if request.method == 'POST':
        action = request.POST.get('action')
        try:
            if action == 'remove':
                with transaction.atomic():
                    if stored: stored.delete()
                    if device.management_method == Device.ManagementMethod.API:
                        device.management_method = Device.ManagementMethod.NONE
                        device.save(update_fields=['management_method'])
                    audit('gdms.credentials_removed', device)
                messages.success(request, 'Credenciales retiradas del panel. Revócalas en GDMS si ya no se utilizarán.')
                return redirect('gdms_cloud', pk=pk)
            if action == 'save':
                if form.is_valid():
                    values = form.cleaned_data
                    secret = api.encrypt(values['secret']) if values['secret'] else connection.encrypted_secret
                    password = (api.encrypt(values['password']) if values['password'] else connection.encrypted_password if connection else '') if values['restricted'] else ''
                    with transaction.atomic():
                        GdmsConnection.objects.update_or_create(device=device, defaults={
                            **{k: values[k] for k in ('region', 'app_id', 'restricted', 'username')},
                            'client_scope_id': device.site.client_id, 'encrypted_secret': secret,
                            'encrypted_password': password, 'last_ok': False, 'last_checked_at': None})
                        audit('gdms.credentials_saved', device)
                    messages.success(request, 'Conexión GDMS guardada con credenciales cifradas. Comprueba el acceso.')
                    return redirect('gdms_cloud', pk=pk)
            elif action == 'test' and connection:
                now = timezone.now()
                claim = GdmsConnection.objects.filter(pk=connection.pk, encrypted_secret=connection.encrypted_secret,
                    last_checked_at=connection.last_checked_at)
                if connection.last_checked_at and now - connection.last_checked_at < timedelta(seconds=60):
                    raise api.GdmsError('Espera un minuto entre comprobaciones.')
                if not claim.update(last_checked_at=now, last_ok=False):
                    raise api.GdmsError('La conexión ha cambiado. Recarga la página.')
                connection.last_checked_at = now
                connection.last_ok = False
                api.check_connection(connection.region, connection.app_id, api.decrypt(connection.encrypted_secret),
                    connection.restricted, connection.username,
                    api.decrypt(connection.encrypted_password) if connection.restricted else '')
                with transaction.atomic():
                    current = get_object_or_404(Device.objects.select_related('site'), pk=pk, vendor=Device.Vendor.GRANDSTREAM_GCC)
                    if current.site.client_id != connection.client_scope_id or not GdmsConnection.objects.filter(
                        pk=connection.pk, last_checked_at=now, encrypted_secret=connection.encrypted_secret).update(last_ok=True):
                        raise api.GdmsError('La conexión o el cliente ha cambiado. Vuelve a guardarla.')
                    audit('gdms.auth_verified', device)
                connection.last_ok = True
                from .device_inventory import queue
                queue(device)
                messages.success(request, 'Autenticación GDMS correcta. Se consultará el inventario por la MAC registrada; verifica los logs en el asistente de envío.')
            else:
                raise api.GdmsError('Guarda primero una conexión válida para el cliente actual.')
        except api.GdmsError as exc:
            error_message = str(exc)
    return render(request, 'gdms_cloud.html', {'device': device, 'connection': connection, 'form': form,
                  'error_message': error_message, 'previous_client': bool(stored and not connection)})

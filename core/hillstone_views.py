from datetime import timedelta
from django import forms
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden
from django.shortcuts import get_object_or_404, render, redirect
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_http_methods
from .models import Device, HillstoneConnection
from . import hillstone_api as api

class ConnectionForm(forms.Form):
    api_url=forms.CharField(label='Dirección HTTPS de Hillstone',max_length=255)
    username=forms.CharField(label='Usuario REST',max_length=120)
    password=forms.CharField(label='Contraseña',required=False,strip=False,widget=forms.PasswordInput)
    ca_certificate=forms.CharField(label='Certificado CA (PEM, si usa una CA privada)',required=False,widget=forms.Textarea(attrs={'rows':5}))
    def __init__(self,*args,connection=None,**kwargs):
        super().__init__(*args,**kwargs)
        self.connection=connection
        for field in self.fields.values(): field.widget.attrs['class']='input'
        self.fields['password'].widget.attrs['autocomplete']='new-password'
        self.fields['password'].help_text='Déjala vacía para conservar la contraseña guardada.' if connection else ''
    def clean(self):
        values=super().clean()
        try:
            values['api_url']=api.validate_url(values.get('api_url',''))
            values['ca_certificate']=api.validate_ca(values.get('ca_certificate',''))
            values['username']=api.username(values.get('username',''))
            if not values.get('password') and (not self.connection or values['api_url']!=self.connection.api_url or values['username']!=self.connection.username):
                raise api.HillstoneApiError('Introduce la contraseña al crear la conexión o cambiar la dirección o el usuario.')
        except api.HillstoneApiError as exc:
            raise forms.ValidationError(str(exc)) from None
        return values

@login_required
@never_cache
@require_http_methods(['GET','POST'])
def hillstone_api(request,pk):
    if not request.user.has_perm('core.manage_connections'):
        return HttpResponseForbidden('Tu cuenta no tiene permiso para gestionar conexiones.')
    device=get_object_or_404(Device.objects.select_related('site__client'),pk=pk,vendor=Device.Vendor.HILLSTONE)
    connection=HillstoneConnection.objects.filter(device=device).first()
    initial={k:getattr(connection,k) for k in ('api_url','username','ca_certificate')} if connection else {'api_url':device.management_address}
    form=ConnectionForm(request.POST if request.method=='POST' and request.POST.get('action')=='save' else None,connection=connection,initial=initial)
    error_message=''
    if request.method=='POST':
        action=request.POST.get('action')
        try:
            if action=='remove':
                if connection: connection.delete()
                device.management_method=Device.ManagementMethod.NONE
                device.save(update_fields=['management_method'])
                messages.success(request,'Credenciales retiradas del panel. Revoca el usuario REST en Hillstone si ya no se usará.')
                return redirect('hillstone_api',pk=pk)
            if action=='save':
                if not form.is_valid():
                    return render(request,'hillstone_api.html',{'device':device,'connection':connection,'form':form})
                values=form.cleaned_data
                cipher=api.encrypt(values['password']) if values['password'] else connection.encrypted_password
                connection,_=HillstoneConnection.objects.update_or_create(device=device,defaults={
                    'api_url':values['api_url'],'username':values['username'],'encrypted_password':cipher,
                    'ca_certificate':values['ca_certificate'],'last_ok':False,'last_checked_at':None})
                messages.success(request,'Conexión guardada con contraseña cifrada.')
                return redirect('hillstone_api',pk=pk)
            if action!='test' or not connection:
                raise api.HillstoneApiError('Guarda primero una conexión válida.')
            if connection.last_checked_at and timezone.now()-connection.last_checked_at<timedelta(seconds=60):
                raise api.HillstoneApiError('Espera un minuto entre comprobaciones para evitar bloquear la cuenta en el firewall.')
            connection.last_ok=False
            connection.last_checked_at=timezone.now()
            connection.save(update_fields=['last_ok','last_checked_at'])
            details=api.check_connection(connection.api_url,connection.username,api.decrypt(connection.encrypted_password),connection.ca_certificate)
            for field,value in details.items(): setattr(device,field,value)
            device.management_method=Device.ManagementMethod.API
            device.management_address=connection.api_url
            device.save(update_fields=[*details,'management_method','management_address'])
            connection.last_ok=True
            connection.save(update_fields=['last_ok'])
            from .device_inventory import queue
            queue(device)
            messages.success(request,'Acceso REST verificado. '+('Inventario actualizado. ' if details else 'Esta versión no incluye inventario en el inicio de sesión. ')+'Continúa en el asistente para configurar y comprobar los logs.')
        except api.HillstoneApiError as exc:
            error_message=str(exc)
    return render(request,'hillstone_api.html',{'device':device,'connection':connection,'form':form,'error_message':error_message})

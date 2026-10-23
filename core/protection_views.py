from django import forms
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.http import HttpResponseForbidden
from django.shortcuts import get_object_or_404,redirect,render
from django.views.decorators.http import require_http_methods
from .models import Client,Site,Device,DeviceHealth,ProtectionPolicy,Incident,IncidentUpdate
from .protection import snapshot,incident_key
from .security import audit
from .forms import ScopedModelForm

class PolicyForm(ScopedModelForm):
    class Meta:
        model=ProtectionPolicy
        fields=['require_ips','require_zenarmor','require_clamav','notes']
        widgets={'notes':forms.Textarea(attrs={'rows':3})}
    def __init__(self,*args,device,**kwargs):
        self.device=device
        super().__init__(*args,**kwargs)
        for field in self.fields.values():field.widget.attrs['class']='input'
        self.fields['notes'].max_length=4000
        if device.vendor!='opnsense':
            self.fields.pop('require_zenarmor');self.fields.pop('require_clamav')
    def clean_notes(self):
        value=self.cleaned_data.get('notes','')
        if len(value)>4000:raise forms.ValidationError('Usa como máximo 4000 caracteres.')
        return value

@login_required
def protection_list(request):
    selected=request.GET.get('client','')
    if selected and not selected.isdigit():selected=''
    if selected:get_object_or_404(Client,pk=selected)
    sites=Site.objects.filter(active=True,client__active=True).select_related('client')
    devices=Device.objects.filter(active=True,site__active=True,site__client__active=True).select_related('site__client','health','protection_policy').prefetch_related('feeds')
    if selected:sites=sites.filter(client_id=selected);devices=devices.filter(site__client_id=selected)
    rows=[snapshot(d) for d in devices];groups=[]
    for site in sites:
        items=[r for r in rows if r['device'].site_id==site.pk]
        groups.append({'site':site,'rows':items,'attention':sum(r['status']=='attention' for r in items),'pending':sum(r['status']=='partial' for r in items)})
    return render(request,'protection_list.html',{'groups':groups,'clients':Client.objects.all(),'selected_client':selected,'devices_count':len(rows),
        'attention_count':sum(r['status']=='attention' for r in rows),'pending_count':sum(r['status']=='partial' for r in rows),
        'observed_count':sum(r['status']=='observed' for r in rows)})

@login_required
@require_http_methods(['GET','POST'])
def protection_device(request,pk):
    device=get_object_or_404(Device.objects.select_related('site__client','health','protection_policy').prefetch_related('feeds'),pk=pk)
    item=snapshot(device)
    policy=getattr(device,'protection_policy',None)
    form=PolicyForm(request.POST or None,instance=policy or ProtectionPolicy(device=device),device=device)
    if request.method=='POST':
        if not request.user.has_perm('core.manage_operations'):return HttpResponseForbidden('Permiso de gestión del SOC requerido.')
        action=request.POST.get('action','policy')
        if action=='configure_zenarmor':
            if not request.user.has_perm('core.manage_connections'):return HttpResponseForbidden('Permiso de gestión de conexiones requerido.')
            from django.conf import settings
            from .security import mfa_fresh
            if settings.SOC_MFA_REQUIRED and not mfa_fresh(request):
                return HttpResponseForbidden('Verifica de nuevo el segundo factor antes de solicitar cambios de exportación.')
            from .zenarmor_export import queue,ExportError
            try:
                queue(device,request.user)
                messages.success(request,'Solicitud registrada. El backend comprobará la licencia y configurará Alerts sin sustituir un destino ajeno al SOC.')
            except ExportError as error:messages.error(request,str(error))
            return redirect('protection_device',pk=pk)
        if action=='recheck':
            health,_=DeviceHealth.objects.get_or_create(device=device)
            health.checked_at=None;health.save(update_fields=['checked_at','updated_at'])
            audit('protection.recheck',device)
            messages.success(request,'Comprobación de lectura solicitada al monitor.')
            return redirect('protection_device',pk=pk)
        if action=='incident':
            if not request.user.has_perm('core.add_incident'):return HttpResponseForbidden('Permiso para crear incidencias requerido.')
            if request.POST.get('fingerprint')!=item['fingerprint']:
                messages.error(request,'Las comprobaciones han cambiado. Revisa el resultado actual.')
                return redirect('protection_device',pk=pk)
            gap=next((g for g in item['gaps'] if g['code']==request.POST.get('code')),None)
            if not gap:
                messages.error(request,'El problema ya no aparece o el equipo está pausado/en mantenimiento.')
                return redirect('protection_device',pk=pk)
            with transaction.atomic():
                incident,created=Incident.objects.get_or_create(fingerprint=incident_key(device,gap['code']),defaults={
                    'client':device.site.client,'site':device.site,'device':device,'title':gap['title'],'severity':gap['severity'],
                    'description':gap['details']+'\nActuación propuesta: '+gap['recommendation']+'\nRegistrado desde Estado de protección. No es una detección de ataque.'})
                if created:
                    IncidentUpdate.objects.create(incident=incident,author=request.user,text='Revisión de protección creada. Asignar responsable y fecha límite en el plan de acciones.')
                elif incident.status=='resolved':
                    incident.status='investigating';incident.resolved_at=None;incident.save(update_fields=['status','resolved_at','updated_at'])
                    IncidentUpdate.objects.create(incident=incident,author=request.user,text='Reabierta explícitamente: la comprobación vuelve a mostrar el problema. '+gap['details'])
                audit('protection.incident',device,{'incident_id':incident.pk,'code':gap['code']})
            return redirect('incident_detail',pk=incident.pk)
        if action=='policy' and form.is_valid():
            policy=form.save(commit=False);policy.device=device;policy.save()
            audit('protection.requirements',policy,{'fields':form.changed_data})
            messages.success(request,'Requisitos guardados. El panel los comparará con las próximas comprobaciones.')
            return redirect('protection_device',pk=pk)
    return render(request,'protection_device.html',{'item':item,'device':device,'form':form})

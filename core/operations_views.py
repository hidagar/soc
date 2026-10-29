from datetime import timedelta
from django import forms
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import Group
from django.db import transaction
from django.db.models import Q
from django.http import HttpResponseForbidden
from django.shortcuts import get_object_or_404,redirect,render
from django.utils import timezone
from django.views.decorators.http import require_http_methods
from .models import (Asset,AuditEvent,Client,Device,DeviceHealth,Incident,IncidentUpdate,
    OperationalIssue,StaffAccess,WorkerState)
from .release import deployed_release
from .security import audit,audit_status,mfa_fresh
from .forms import ScopedModelForm

def permitted(request,permission):
    return request.user.has_perm('core.'+permission)

class AssetForm(ScopedModelForm):
    confirm_identity=forms.BooleanField(label='Confirmo la identidad actual tras revisar la IP y la MAC',required=False)
    def clean(self):
        values=super().clean()
        if self.instance.identity_conflict and not values.get('confirm_identity'):
            self.add_error('confirm_identity','Revisa la identidad del dispositivo antes de guardar.')
        return values
    def save(self,commit=True):
        item=super().save(commit=False)
        if item.name and 'name' in self.changed_data:item.identified_at=timezone.now()
        if self.cleaned_data.get('confirm_identity'):item.identity_conflict=False;item.identified_at=timezone.now()
        if commit:item.save()
        return item
    class Meta:
        model=Asset
        fields=['name','function','owner_contact','vlan','critical']

class HealthForm(ScopedModelForm):
    class Meta:
        model=DeviceHealth
        fields=['expected_silence_minutes','maintenance_until']
        labels={'expected_silence_minutes':'Umbral de silencio (minutos)','maintenance_until':'En mantenimiento hasta'}
        widgets={'maintenance_until':forms.DateTimeInput(attrs={'type':'datetime-local'},format='%Y-%m-%dT%H:%M')}
    def clean_expected_silence_minutes(self):
        value=self.cleaned_data['expected_silence_minutes']
        if value and not 15 <= value <= 10080:
            raise forms.ValidationError('Usa 0 para adaptar al historial o entre 15 minutos y una semana.')
        return value

class StaffForm(forms.Form):
    username=forms.CharField(label='Nombre de la persona',max_length=150,help_text='Nombre visible en el panel y en la auditoría. El acceso se realiza con el correo.')
    email=forms.EmailField(label='Correo electrónico de acceso',required=True,help_text='También se utiliza para enviar la invitación. Debe ser único.')
    role=forms.ChoiceField(label='Perfil',choices=[('reader','Consulta'),('operator','Operador'),('manager','Administrador SOC'),('customer','Cliente: portal privado')])
    all_clients=forms.BooleanField(label='Todos los clientes',required=False)
    clients=forms.ModelMultipleChoiceField(label='Clientes asignados',queryset=Client.objects.none(),required=False)
    active=forms.BooleanField(label='Cuenta activa',initial=True,required=False)
    def __init__(self,*args,instance=None,**kwargs):
        self.instance=instance
        super().__init__(*args,**kwargs)
        self.fields['clients'].queryset=Client.objects.all()
        if instance:
            from .email_auth import LEGACY_USERNAMES
            if instance.username in LEGACY_USERNAMES and not instance.email:
                self.fields['email'].required=False
                self.fields['email'].help_text='Cuenta anterior: conserva el acceso por usuario mientras el correo esté vacío.'
            a=getattr(instance,'soc_access',None)
            self.initial.update({'username':instance.username,'email':instance.email,'active':instance.is_active,
                'role':a.role if a else 'reader','all_clients':a.all_clients if a else False,'clients':list(a.clients.all()) if a else []})
    def clean(self):
        values=super().clean()
        User=get_user_model()
        if User.objects.filter(username=values.get('username')).exclude(pk=self.instance.pk if self.instance else None).exists():
            self.add_error('username','El usuario ya existe.')
        if not values.get('all_clients') and not values.get('clients'):
            self.add_error('clients','Selecciona al menos un cliente o Todos los clientes.')
        if values.get('role')=='customer' and (values.get('all_clients') or len(values.get('clients', []))!=1):
            self.add_error('clients','El portal del cliente exige exactamente un cliente y no permite acceso global.')
        if self.instance and self.instance.is_superuser and values.get('role')=='customer':
            self.add_error('role','Un superusuario no puede convertirse en cuenta de cliente.')
        email=values.get('email','').strip().lower()
        if email:
            from django.db.models.functions import Lower, Trim
            if User.objects.annotate(login_email=Lower(Trim('email'))).filter(login_email=email).exclude(pk=self.instance.pk if self.instance else None).exists():
                self.add_error('email','Este correo ya pertenece a otra cuenta.')
        values['email']=email
        return values

@login_required
def health_list(request):
    devices=Device.objects.filter(active=True).select_related('site__client','health')
    issues=OperationalIssue.objects.filter(active=True).select_related('device__site__client')
    client=request.GET.get('client','')
    if client.isdigit():
        selected=get_object_or_404(Client,pk=client)
        devices=devices.filter(site__client=selected)
        issues=issues.filter(device__site__client=selected)
    rows=[]
    labels={'pending':'Pendiente','receiving':'Recibiendo datos','verified':'Detección recibida','degraded':'Requiere atención','maintenance':'Mantenimiento','paused':'Pausado'}
    for d in devices:
        h=getattr(d,'health',None)
        rows.append({'device':d,'health':h,'label':labels.get(h.status if h else 'pending','Pendiente'),
            'cursor':WorkerState.objects.filter(pk=f'source-reconciliation:{d.pk}').first()})
    state=WorkerState.objects.filter(name='operations').first()
    reconciliation=WorkerState.objects.filter(name='security-reconciliation').first()
    access=getattr(request.user,'soc_access',None)
    global_access=request.user.is_superuser or bool(access and access.all_clients and access.role!='customer')
    from .background_jobs import JOBS
    workers=[]
    if global_access:
        for name,(_,label) in JOBS.items():
            workers.append({'label':label,'state':WorkerState.objects.filter(pk='job:'+name).first()})
    now=timezone.now()
    stale=now-timedelta(hours=2)
    for r in rows:
        last=r['health'].last_log_at if r['health'] else None
        r['silent']=not last or last<stale
    summary={'devices':len(rows),'receiving':sum(not r['silent'] for r in rows),'silent':sum(r['silent'] for r in rows),
        'api_errors':sum(bool(r['health'] and r['health'].api_ok is False) for r in rows),
        'job_errors':sum(bool(w['state'] and w['state'].error) for w in workers)}
    return render(request,'operations_health.html',{'rows':rows,'clients':Client.objects.all(),'selected_client':client,'summary':summary,
        'issues':issues.order_by('severity','opened_at')[:100],
        'monitor':state,'reconciliation':reconciliation,'workers':workers,
        'receipt_metrics':WorkerState.objects.filter(pk='receipts').first() if global_access else None,
        'release':deployed_release() if global_access else None,
        'monitor_stale':not state or not state.last_success_at or timezone.now()-state.last_success_at>timedelta(minutes=5)})

@login_required
@require_http_methods(['GET','POST'])
def health_device(request,pk):
    device=get_object_or_404(Device,pk=pk)
    health,_=DeviceHealth.objects.get_or_create(device=device)
    form=HealthForm(request.POST or None,instance=health)
    if request.method=='POST':
        if not permitted(request,'manage_operations'): return HttpResponseForbidden('Permiso de gestión del SOC requerido.')
        if request.POST.get('action')=='recheck':
            health.checked_at=None
            health.save(update_fields=['checked_at','updated_at'])
            audit('health.recheck',health)
            messages.success(request,'Comprobación solicitada. El monitor revisará el equipo en su próxima pasada.')
            return redirect('health_device',pk=pk)
        if form.is_valid():
            form.save()
            audit('health.settings',health,{'fields':form.changed_data})
            messages.success(request,'Umbral y mantenimiento guardados.')
            return redirect('health_device',pk=pk)
    return render(request,'operations_device.html',{'device':device,'health':health,'form':form,
        'feeds':device.feeds.all(),'assets':device.assets.all()[:100],'events':device.security_events.select_related('asset','incident')[:30]})

@login_required
def inventory(request):
    assets=Asset.objects.select_related('device__site__client')
    client=request.GET.get('client','')
    query=request.GET.get('q','').strip()[:160]
    if client.isdigit(): assets=assets.filter(device__site__client_id=client)
    if query: assets=assets.filter(Q(name__icontains=query)|Q(discovered_name__icontains=query)|Q(ip__icontains=query)|Q(mac__icontains=query))
    return render(request,'operations_inventory.html',{'assets':assets[:500],'clients':Client.objects.all(),'query':query,'selected_client':client})

@login_required
@require_http_methods(['GET','POST'])
def asset_edit(request,pk):
    asset=get_object_or_404(Asset,pk=pk)
    if not permitted(request,'manage_operations'): return HttpResponseForbidden('Permiso de gestión del SOC requerido.')
    form=AssetForm(request.POST or None,instance=asset)
    if request.method=='POST' and form.is_valid():
        form.save()
        audit('asset.identity',asset,{'fields':form.changed_data})
        messages.success(request,'Identidad guardada. Se conservará en futuras consultas automáticas.')
        return redirect('inventory')
    return render(request,'object_form.html',{'form':form,'title':'Identificar equipo: '+asset.ip,'cancel_url':'/operations/inventory/','is_edit':True})

@login_required
@require_http_methods(['POST'])
def incident_note(request,pk):
    incident=get_object_or_404(Incident,pk=pk)
    if not request.user.has_perm('core.change_incident'): return HttpResponseForbidden('Permiso de gestión de incidencias requerido.')
    text=request.POST.get('text','').strip()
    if text and len(text)<=10000:
        IncidentUpdate.objects.create(incident=incident,author=request.user,text=text)
        audit('incident.note',incident)
        messages.success(request,'Seguimiento añadido.')
    else: messages.error(request,'Escribe una nota de hasta 10.000 caracteres.')
    return redirect('incident_detail',pk=pk)

@login_required
@require_http_methods(['GET','POST'])
def staff(request,pk=None):
    access=getattr(request.user,'soc_access',None)
    if not permitted(request,'manage_security') or (not request.user.is_superuser and not (access and access.all_clients)):
        return HttpResponseForbidden('Se requiere administración global de seguridad.')
    User=get_user_model()
    member=get_object_or_404(User,pk=pk) if pk else None
    if member and member.is_superuser and not request.user.is_superuser:
        return HttpResponseForbidden('Una cuenta SOC no puede modificar a un superusuario.')
    form=StaffForm(request.POST or None,instance=member)
    if request.method=='POST':
        if not mfa_fresh(request): return redirect('mfa_challenge')
        if request.POST.get('action')=='invite' and member:
            from .invitations import queue
            if member.has_usable_password():messages.error(request,'Esta cuenta ya ha establecido su contraseña.')
            elif member.is_active and member.email:
                queue(member);messages.success(request,'Invitación en cola. El enlace anterior queda invalidado.')
            else:messages.error(request,'Activa la cuenta y guarda un correo válido antes de invitar.')
            return redirect('staff_edit',pk=member.pk)
        if form.is_valid():
            v=form.cleaned_data
            if member==request.user and (not v['active'] or v['role']!='manager' or not v['all_clients']):
                form.add_error(None,'No puedes retirar tu propio acceso de administración desde esta pantalla.')
            else:
                with transaction.atomic():
                    created=member is None
                    before={} if created else {'email':member.email,'active':member.is_active}
                    member=member or User()
                    member.username,member.email,member.is_active=v['username'],v['email'],v['active']
                    member.is_staff=v['role']=='manager'
                    if created:member.set_unusable_password()
                    member.save()
                    a,_=StaffAccess.objects.get_or_create(user=member)
                    a.role,a.all_clients=v['role'],v['all_clients']
                    a.save(); a.clients.set(v['clients'])
                    names=['SOC Consulta','SOC Operador','SOC Administrador']
                    member.groups.remove(*Group.objects.filter(name__in=names))
                    if v['role']=='customer':
                        member.groups.clear();member.user_permissions.clear()
                    else:
                        member.groups.add(Group.objects.get(name=names[['reader','operator','manager'].index(v['role'])]))
                    if v['role']!='manager':
                        member.user_permissions.remove(*member.user_permissions.filter(codename__in=['manage_connections','manage_security','apply_changes','manage_recovery','view_all_clients']))
                        member.groups.remove(*member.groups.exclude(name__in=names))
                    # Qué cambió de la cuenta (sin guardar el correo en la auditoría).
                    changed=[k for k,old in before.items() if old!=v[k]]
                    audit('staff.access',member,{'role':v['role'],'clients':[c.pk for c in v['clients']],'all_clients':v['all_clients'],
                                                 'active':v['active'],'fields':changed})
                    if created:
                        from .invitations import queue
                        queue(member)
                messages.success(request,'Usuario y permisos guardados. Las nuevas cuentas reciben un enlace para elegir su contraseña y después configurar su autenticador.')
                return redirect('staff')
    return render(request,'operations_staff.html',{'members':User.objects.select_related('soc_access').order_by('username'),'form':form,'editing':member})

@login_required
def audit_log(request):
    if not permitted(request,'manage_security'): return HttpResponseForbidden('Permiso de seguridad requerido.')
    from .audit_presentation import present
    events=AuditEvent.objects.select_related('actor')[:300]
    return render(request,'operations_audit.html',{'rows':present(events),'integrity':audit_status()})

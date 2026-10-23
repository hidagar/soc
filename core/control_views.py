from django import forms
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.http import Http404,HttpResponse,HttpResponseForbidden
from django.shortcuts import get_object_or_404,redirect,render
from django.views.decorators.http import require_http_methods
from .models import BackupRun,ChangePlan,Device,RecoverySettings,Site,VpnPeer
from .security import audit,encrypt,mfa_fresh
from .change_control import PROFILES,VERSION,preview

def global_permission(request,codename):
    access=getattr(request.user,'soc_access',None)
    return request.user.has_perm('core.'+codename) and (request.user.is_superuser or access and access.all_clients)

class TemplateForm(forms.Form):
    device=forms.ModelChoiceField(label='Firewall',queryset=Device.objects.none())
    profile=forms.ChoiceField(label='Plantilla',choices=list(PROFILES.items()))
    networks=forms.CharField(label='Redes protegidas (CIDR separadas por comas)',max_length=300)
    interface=forms.CharField(label='Interfaces internas de OPNsense',initial='lan',max_length=100)
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        self.fields['device'].queryset=Device.objects.filter(active=True)
    def clean(self):
        values=super().clean()
        if all(values.get(k) for k in ('profile','networks','interface')):
            try: values['preview']=preview(values['profile'],values['networks'],values['interface'])
            except ValueError as exc: raise forms.ValidationError(str(exc))
        return values

@login_required
@require_http_methods(['GET','POST'])
def changes(request):
    if not request.user.has_perm('core.manage_operations'): return HttpResponseForbidden('Permiso de operaciones requerido.')
    form=TemplateForm(request.POST or None)
    if request.method=='POST' and form.is_valid():
        v=form.cleaned_data
        plan=ChangePlan.objects.create(device=v['device'],template=v['profile'],template_version=VERSION,
            title=PROFILES[v['profile']],parameters={k:v[k] for k in ('networks','interface')},preview=v['preview'],requested_by=request.user)
        audit('change.draft',plan,{'template':plan.template})
        return redirect('change_detail',pk=plan.pk)
    return render(request,'operations_changes.html',{'form':form,'plans':ChangePlan.objects.select_related('device__site__client').order_by('-pk')[:100]})

@login_required
@require_http_methods(['GET','POST'])
def change_detail(request,pk):
    plan=get_object_or_404(ChangePlan.objects.select_related('device__site__client'),pk=pk)
    if request.method=='POST':
        if not request.user.has_perm('core.apply_changes'): return HttpResponseForbidden('Permiso de aprobación requerido.')
        if not mfa_fresh(request): return redirect('mfa_challenge')
        if request.POST.get('device_name')!=plan.device.name or request.POST.get('reviewed')!='yes':
            messages.error(request,'Confirma la revisión y escribe el nombre exacto del equipo.')
        else:
            action=request.POST.get('action')
            if action=='apply' and ChangePlan.objects.filter(device=plan.device,status__in=['apply_queued','applying','awaiting_confirmation','confirm_queued','rollback_queued']).exclude(pk=plan.pk).exists():
                messages.error(request,'Ya hay un cambio de este equipo en curso. Termina su verificación antes de activar otro.')
                return redirect('change_detail',pk=pk)
            transitions={('draft','stage'):'stage_queued',('staged','apply'):'apply_queued',
                ('active','rollback'):'rollback_queued',('staged','rollback'):'rollback_queued',
                ('awaiting_confirmation','confirm'):'confirm_queued',('awaiting_confirmation','rollback'):'rollback_queued'}
            status=transitions.get((plan.status,action))
            if status:
                with transaction.atomic():
                    if ChangePlan.objects.filter(pk=plan.pk,status=plan.status).update(status=status,approved_by=request.user):
                        audit('change.'+action+'.approved',plan,{'status':status})
                        messages.success(request,'Operación en cola. Se mostrará el resultado de la comprobación.')
                return redirect('change_detail',pk=pk)
            messages.error(request,'La operación no corresponde al estado actual. Actualiza la página.')
    return render(request,'operations_change.html',{'plan':plan})

@login_required
@require_http_methods(['GET','POST'])
def vpn_sites(request,pk=None):
    if not request.user.has_perm('core.manage_connections'): return HttpResponseForbidden('Permiso de conexiones requerido.')
    if request.method=='POST':
        if not mfa_fresh(request): return redirect('mfa_challenge')
        site_pk=request.POST.get('site','')
        if not site_pk.isdigit(): raise Http404
        site=get_object_or_404(Site,pk=int(site_pk))
        from .vpn import create_peer
        peer=create_peer(site)
        action=request.POST.get('action')
        if action in ('enable','disable'):
            if peer.enabled!=(action=='enable'):
                peer.transport={};peer.handshake_at=None
            peer.enabled=action=='enable'; peer.status='queued'; peer.save(update_fields=['enabled','status','transport','handshake_at'])
            audit('vpn.'+action,peer)
        messages.success(request,'Configuración VPN preparada. El túnel se considera conectado solo tras recibir un handshake real.')
        return redirect('vpn_sites')
    from .vpn import transport_snapshot
    return render(request,'operations_vpn.html',{'sites':Site.objects.filter(active=True).select_related('client','vpn_peer'),'peers':[transport_snapshot(p) for p in VpnPeer.objects.select_related('site__client')]})

@login_required
def vpn_download(request,pk):
    if not request.user.has_perm('core.manage_connections'): return HttpResponseForbidden('Permiso de conexiones requerido.')
    if not mfa_fresh(request): return redirect('mfa_challenge')
    peer=get_object_or_404(VpnPeer,pk=pk)
    from .vpn import client_config
    try: content=client_config(peer)
    except (OSError,ValueError):
        messages.error(request,'El servidor VPN aún no tiene preparada su clave pública.'); return redirect('vpn_sites')
    audit('vpn.config.download',peer)
    response=HttpResponse(content,content_type='application/octet-stream')
    response['Content-Disposition']=f'attachment; filename="soc-sede-{peer.site_id}.conf"'
    response['Cache-Control']='no-store'
    return response

class RecoveryForm(forms.Form):
    transport=forms.ChoiceField(label='Cómo se realiza la copia externa',choices=[('vm','Copia completa de VM gestionada externamente'),('sftp','Copia cifrada del SOC por SFTP')])
    vm_platform=forms.CharField(label='Plataforma de copias de VM',max_length=100,required=False)
    vm_storage=forms.CharField(label='Destino o repositorio de las copias',max_length=200,required=False)
    vm_offhost=forms.BooleanField(label='Confirmo que las copias se guardan fuera del servidor de la VM',required=False)
    vm_encrypted=forms.BooleanField(label='Confirmo que las copias están cifradas',required=False)
    vm_last_backup_at=forms.DateTimeField(label='Última copia correcta declarada',required=False,widget=forms.DateTimeInput(format='%Y-%m-%dT%H:%M',attrs={'type':'datetime-local'}))
    vm_last_restore_at=forms.DateTimeField(label='Último ensayo de recuperación de VM declarado',required=False,widget=forms.DateTimeInput(format='%Y-%m-%dT%H:%M',attrs={'type':'datetime-local'}))
    vm_restore_isolated=forms.BooleanField(label='Confirmo que el ensayo se realizó en una red aislada de producción',required=False)
    vm_restore_reference=forms.CharField(label='Referencia y resultado del ensayo de VM',max_length=1000,required=False,widget=forms.Textarea(attrs={'rows':3}))
    hostname=forms.CharField(label='Servidor SFTP externo',max_length=253,required=False)
    port=forms.IntegerField(label='Puerto',min_value=1,max_value=65535,initial=22)
    username=forms.CharField(label='Usuario SFTP',max_length=120,required=False)
    password=forms.CharField(label='Contraseña (vacío conserva la guardada)',max_length=512,required=False,widget=forms.PasswordInput)
    remote_path=forms.CharField(label='Directorio remoto absoluto',max_length=255,required=False)
    fingerprint=forms.CharField(label='Huella SHA256 confirmada por el administrador del destino',max_length=100,required=False)
    retention_days=forms.IntegerField(label='Retención de copias (días)',min_value=7,max_value=365,initial=30)
    evidence_days=forms.IntegerField(label='Retención de evidencias sin incidencia (días)',min_value=30,max_value=365,initial=90)
    operational_email=forms.EmailField(label='Correo de operaciones',initial='noc@ibred.es')
    notify_enabled=forms.BooleanField(label='Avisos operativos por correo',required=False,initial=True)
    enabled=forms.BooleanField(label='Copias externas activadas',required=False)

    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        mode=self.data.get('transport') if self.is_bound else self.initial.get('transport','sftp')
        for name in list(self.fields):
            if (mode=='vm' and name in ('hostname','port','username','password','remote_path','fingerprint','enabled')) or (mode!='vm' and name.startswith('vm_')):self.fields.pop(name)

    def clean(self):
        values=super().clean()
        if values.get('transport')=='vm':
            from django.utils import timezone
            for name in ('vm_last_backup_at','vm_last_restore_at'):
                if values.get(name) and values[name]>timezone.now():self.add_error(name,'La fecha no puede estar en el futuro.')
            if values.get('vm_last_restore_at') and (not values.get('vm_restore_isolated') or len(values.get('vm_restore_reference','').strip())<10):
                self.add_error('vm_restore_reference','Confirma la red aislada y registra una referencia y resultado del ensayo.')
        return values

@login_required
@require_http_methods(['GET','POST'])
def recovery(request):
    if not global_permission(request,'manage_recovery'): return HttpResponseForbidden('Administración global de recuperación requerida.')
    cfg,_=RecoverySettings.objects.get_or_create(pk=1)
    initial={k:getattr(cfg,k) for k in RecoveryForm.base_fields if hasattr(cfg,k)}
    from django.utils.dateparse import parse_datetime
    from django.utils import timezone
    for name,value in cfg.vm_backup.items():
        if name in RecoveryForm.base_fields:
            initial[name]=timezone.localtime(parse_datetime(value)) if name.endswith('_at') and value and parse_datetime(value) else value
    mode=request.GET.get('mode',cfg.transport)
    if mode in ('vm','sftp'):initial['transport']=mode
    form=RecoveryForm(request.POST or None,initial=initial)
    observed=None
    if request.method=='POST':
        if not mfa_fresh(request): return redirect('mfa_challenge')
        action=request.POST.get('action')
        if action=='backup':
            if not BackupRun.objects.filter(status__in=['queued','running']).exists():
                run=BackupRun.objects.create(); audit('backup.queued',run)
            messages.success(request,'Copia y comprobación de recuperación en cola.')
            return redirect('recovery')
        if form.is_valid():
            v=form.cleaned_data
            if v['transport']=='vm' and action=='save':
                cfg.transport='vm'
                cfg.vm_backup={k:val.isoformat() if hasattr(val,'isoformat') else val for k,val in v.items() if k.startswith('vm_')}
                for k in ('retention_days','evidence_days','operational_email','notify_enabled'):setattr(cfg,k,v[k])
                cfg.save();audit('recovery.settings',cfg,{'fields':list(v)})
                messages.success(request,'Datos de copias de VM guardados como declaración del operador. No se han verificado desde el hipervisor.')
                return redirect('recovery')
            if v.get('hostname') and action in ('probe','save'):
                from .ssh_connection import probe_host_key
                try: observed=probe_host_key(v['hostname'],v['port'])
                except Exception: form.add_error('hostname','No se pudo obtener la huella del servidor.')
                if action=='save' and observed and observed['fingerprint']!=v['fingerprint']:
                    form.add_error('fingerprint','La huella no coincide. Confírmala por un canal independiente antes de guardar.')
            if action=='save' and not form.errors:
                if v.get('transport')!='sftp':form.add_error(None,'Selecciona el método de copia.')
                elif v['enabled'] and not all(v[k] for k in ('hostname','username','remote_path','fingerprint')):
                    form.add_error(None,'Completa el destino y su huella antes de activar las copias externas.')
                elif v['enabled'] and not (v['password'] or cfg.encrypted_password):
                    form.add_error('password','Falta la contraseña del destino.')
                elif (cfg.encrypted_password and not v['password']
                      and (cfg.hostname,cfg.port,cfg.username)!=(v['hostname'],v['port'],v['username'])):
                    # La contraseña guardada era del destino anterior: no se envía a otro servidor o usuario.
                    form.add_error('password','Has cambiado el servidor, el puerto o el usuario: vuelve a escribir la contraseña de este destino.')
                else:
                    from pathlib import PurePosixPath
                    if v['remote_path'] and (not PurePosixPath(v['remote_path']).is_absolute() or '..' in PurePosixPath(v['remote_path']).parts):
                        form.add_error('remote_path','Usa un directorio absoluto sin ..')
                    else:
                        for k in v:
                            if hasattr(cfg,k) and k not in ('fingerprint',): setattr(cfg,k,v[k])
                        if v['password']: cfg.encrypted_password=encrypt(v['password'])
                        cfg.verified=bool(observed)
                        if observed:
                            cfg.host_key_type=observed['type']; cfg.host_key_base64=observed['base64']; cfg.fingerprint=observed['fingerprint']
                        cfg.save(); audit('recovery.settings',cfg,{'fields':list(v.keys())})
                        messages.success(request,'Configuración guardada. La próxima copia verificará la transferencia y su contenido.')
                        return redirect('recovery')
    return render(request,'operations_recovery.html',{'form':form,'observed':observed,'cfg':cfg,'runs':BackupRun.objects.order_by('-pk')[:30]})

from datetime import timedelta
from django import forms
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.http import HttpResponseForbidden
from django.shortcuts import get_object_or_404,render,redirect
from django.utils import timezone
from django.views.decorators.http import require_POST,require_http_methods
from .models import (Incident,IncidentUpdate,IncidentAction,RunbookStep,CustomerTask,CustomerTaskEntry,
    Device,ProtectionValidation,SecurityEvidence,ConfigurationArchive,UrgentAlert,NetworkCoverage)
from .security import audit
from .service_development import customer_client

def runbook_titles(incident):
    text=(incident.title+' '+incident.recommendation).lower()
    common=['Identificar el equipo y confirmar la evidencia, su fecha y la acción del firewall',
        'Determinar alcance e impacto; contactar con el responsable del equipo']
    if any(s in text for s in ('malware','virus','trojan','botnet')):
        return common+['Decidir y documentar si procede aislar el equipo; coordinar la intervención',
            'Analizar con el antivirus/EDR, revisar persistencia y documentar los resultados',
            'Comprobar nuevas conexiones y detecciones; documentar recuperación y seguimiento']
    if any(s in text for s in ('expos','puerto','nat','rdp')):
        return common+['Confirmar el servicio publicado y su necesidad con el cliente',
            'Preparar y revisar restricciones, copia y ventana de cambio',
            'Comprobar servicios autorizados y exposición tras el cambio']
    return common+['Revisar contexto, reincidencia y si corresponde a actividad autorizada',
        'Coordinar una medida proporcionada y registrar el cambio o la excepción',
        'Verificar el resultado y acordar el seguimiento posterior']

@login_required
@require_POST
def runbook(request,pk):
    incident=get_object_or_404(Incident,pk=pk)
    if not request.user.has_perm('core.change_incident'):return HttpResponseForbidden()
    if incident.status=='resolved':
        messages.error(request,'Reabre el caso antes de modificar su guía.');return redirect('incident_detail',pk=pk)
    with transaction.atomic():
        if request.POST.get('operation')=='prepare':
            for position,title in enumerate(runbook_titles(incident),1):
                RunbookStep.objects.get_or_create(incident=incident,position=position,defaults={'title':title})
            audit('runbook.prepared',incident)
        else:
            step=get_object_or_404(RunbookStep,pk=request.POST.get('step') if request.POST.get('step','').isdigit() else 0,incident=incident)
            text=request.POST.get('evidence','').strip()
            if not text or len(text)>4000:
                messages.error(request,'Documenta el resultado o el motivo por el que no aplica (máximo 4000 caracteres).')
                return redirect('incident_detail',pk=pk)
            done=request.POST.get('done')=='1'
            step.done=done;step.evidence=text;step.completed_by=request.user if done else None;step.completed_at=timezone.now() if done else None;step.save()
            IncidentUpdate.objects.create(incident=incident,author=request.user,text=('Comprobación completada: ' if done else 'Comprobación pendiente: ')+step.title+'. '+text)
            audit('runbook.updated',step,{'status':'done' if done else 'pending'})
    return redirect('incident_detail',pk=pk)

class TaskForm(forms.ModelForm):
    class Meta:
        model=CustomerTask
        fields=['title','instructions','due_at','action','visible','status','review_note']
        widgets={'instructions':forms.Textarea(attrs={'rows':5}),'review_note':forms.Textarea(attrs={'rows':3}),
            'due_at':forms.DateTimeInput(attrs={'type':'datetime-local'},format='%Y-%m-%dT%H:%M')}
    def __init__(self,*args,incident,**kwargs):
        super().__init__(*args,**kwargs)
        self.fields['action'].label='Acción interna del cliente vinculada (opcional)'
        self.fields['action'].queryset=IncidentAction.objects.filter(incident=incident,responsible_party='client')
        for field in self.fields.values():field.widget.attrs['class']='input'
        self.fields['instructions'].max_length=6000;self.fields['review_note'].max_length=6000
    def clean(self):
        values=super().clean()
        if values.get('status') in ('accepted','submitted') and not (self.instance.response or '').strip():
            self.add_error('status','Se necesita una respuesta del cliente antes de validarla.')
        if values.get('status') in ('accepted','rework','cancelled') and not (values.get('review_note') or '').strip():
            self.add_error('review_note','Explica la comprobación realizada o qué información falta.')
        return values

@login_required
@require_http_methods(['GET','POST'])
def task_edit(request,incident_pk=None,pk=None):
    if not request.user.has_perm('core.change_incident'):return HttpResponseForbidden()
    task=get_object_or_404(CustomerTask,pk=pk) if pk else None
    incident=task.incident if task else get_object_or_404(Incident,pk=incident_pk)
    before=(task.status,task.review_note) if task else (None,'')
    form=TaskForm(request.POST or None,instance=task,incident=incident)
    if request.method=='POST' and form.is_valid():
        with transaction.atomic():
            saved=form.save(commit=False);saved.incident=incident
            if saved.status in ('accepted','rework','cancelled'):
                saved.reviewed_by=request.user;saved.reviewed_at=timezone.now()
            saved.save()
            if saved.status in ('accepted','rework','cancelled') and (saved.status,saved.review_note)!=before:
                CustomerTaskEntry.objects.create(task=saved,kind='review',status=saved.status,text=saved.review_note,author=request.user)
            if saved.status=='accepted' and saved.action_id:
                action=IncidentAction.objects.select_for_update().get(pk=saved.action_id,incident=incident,responsible_party='client')
                if action.status not in ('done','cancelled'):
                    action.status='done';action.resolution='Respuesta del cliente: '+saved.response+'\nVerificación SOC: '+saved.review_note
                    action.completed_at=timezone.now();action.save()
            elif saved.status in ('pending','rework','submitted') and saved.action_id:
                # Una tarea reabierta no puede dejar su acción como completada.
                action=IncidentAction.objects.select_for_update().get(pk=saved.action_id,incident=incident,responsible_party='client')
                if action.status=='done':
                    action.status='awaiting_client';action.completed_at=None;action.resolution='';action.save()
                    IncidentUpdate.objects.create(incident=incident,author=request.user,text='Acción reabierta al reabrir la tarea del cliente: '+action.title+'.')
            elif saved.status not in ('accepted','cancelled') and incident.status=='resolved':
                incident.status='investigating';incident.resolved_at=None;incident.save()
            IncidentUpdate.objects.create(incident=incident,author=request.user,text='Tarea para el cliente: '+saved.title+'. Estado: '+saved.get_status_display()+'.')
            audit('customer.task_saved',saved,{'status':saved.status})
        return redirect('incident_detail',pk=incident.pk)
    return render(request,'customer_task_edit.html',{'form':form,'task':task,'incident':incident})

@login_required
@require_http_methods(['GET','POST'])
def customer_task_reply(request,pk):
    client=customer_client(request)
    task=get_object_or_404(CustomerTask,pk=pk,incident__client=client,visible=True)
    error=''
    if request.method=='POST':
        text=request.POST.get('response','').strip()
        if not text or len(text)>6000:error='Explica qué se ha realizado y sus resultados, en un máximo de 6000 caracteres.'
        else:
            with transaction.atomic():
                changed=CustomerTask.objects.filter(pk=task.pk,visible=True,status__in=('pending','rework')).update(
                    response=text,submitted_at=timezone.now(),updated_at=timezone.now(),status='submitted')
                if changed:
                    CustomerTaskEntry.objects.create(task=task,kind='response',status='submitted',text=text,author=request.user)
                    IncidentUpdate.objects.create(incident=task.incident,author=request.user,text='Respuesta recibida del cliente para la tarea «'+task.title+'». Pendiente de verificación SOC.')
                    audit('customer.task_response',task,{'status':'submitted'})
                    return redirect('customer_home')
                error='Esta tarea ya está respondida o validada. El SOC revisará la respuesta.'
    return render(request,'customer_task_reply.html',{'client':client,'task':task,'error':error})

class ValidationForm(forms.ModelForm):
    class Meta:
        model=ProtectionValidation
        fields=['engine','network','test_ip','networks','expected_signature']
        labels={'engine':'Motor que se va a comprobar','networks':'Red/interfaz y equipo de prueba','expected_signature':'Firma exacta de la detección de prueba esperada'}
    def __init__(self,*args,device,**kwargs):
        super().__init__(*args,**kwargs)
        self.device=device
        self.fields['network'].label='Red descubierta para vincular la prueba (opcional)'
        self.fields['network'].queryset=NetworkCoverage.objects.filter(device=device,present=True)
        self.fields['test_ip'].label='IP del ordenador de prueba (obligatoria al vincular una red)'
        self.fields['engine'].choices=[('unifi','UniFi')] if device.vendor=='unifi' else [('hillstone','Hillstone: detección de amenaza')] if device.vendor=='hillstone' else [('suricata','Suricata'),('zenarmor','Zenarmor'),('clamav','ClamAV')]
        for f in self.fields.values():f.widget.attrs['class']='input'

    def clean(self):
        from .network_coverage import current,matches_ip,uniquely_contains
        values=super().clean();network=values.get('network');address=values.get('test_ip')
        if network:
            if not current(network):self.add_error('network','Solicita primero una consulta reciente de redes y motores; el equipo debe estar activo y fuera de mantenimiento.')
            if not address or not matches_ip(address,network.cidrs):self.add_error('test_ip','Indica la IP del ordenador de prueba dentro de una subred descubierta de esta red.')
            elif not uniquely_contains(network,address):self.add_error('test_ip','La IP coincide con varias redes descubiertas. Revisa los solapamientos antes de atribuir esta prueba a una sola red.')
        elif address:
            self.add_error('network','Selecciona una red descubierta para atribuir la IP de prueba.')
        return values

def reconcile_validations(now=None):
    now=now or timezone.now()
    checked=0
    for item in ProtectionValidation.objects.filter(evidence=None,expires_at__gte=now-timedelta(days=1)).order_by('started_at')[:100]:
        candidates=SecurityEvidence.objects.filter(device=item.device,engine=item.engine,signature__iexact=item.expected_signature,
            observed_at__gte=item.started_at,observed_at__lte=min(now,item.expires_at)).exclude(category='application_policy')
        if item.network_id or item.network_snapshot:
            if not item.test_ip or not item.network_snapshot:continue
            candidates=candidates.filter(asset__ip=item.test_ip)
        e=candidates.order_by('observed_at').first()
        if e:
            item.evidence=e;item.save(update_fields=['evidence']);checked+=1
            audit('protection.test_received',item,{'status':e.action})
    return checked

@login_required
@require_http_methods(['GET','POST'])
def validations(request,pk):
    device=get_object_or_404(Device,pk=pk)
    initial={}
    network_id=request.GET.get('network','')
    if network_id.isdigit():
        network=NetworkCoverage.objects.filter(pk=network_id,device=device,present=True).first()
        if network:initial={'network':network,'networks':str(network)}
    form=ValidationForm(request.POST or None,device=device,initial=initial)
    if request.method=='POST':
        if not request.user.has_perm('core.manage_operations'):return HttpResponseForbidden()
        if form.is_valid():
            item=form.save(commit=False);item.device=device;item.requested_by=request.user
            if item.network_id:
                from .network_coverage import fingerprint
                item.network_snapshot=list(item.network.cidrs)
                item.configuration_fingerprint=fingerprint(item.network,item.engine)
            item.started_at=timezone.now();item.expires_at=item.started_at+timedelta(hours=1);item.save()
            audit('protection.test_started',item)
            messages.success(request,'Ventana de una hora preparada. Realiza la prueba controlada desde la red indicada y revisa su recepción.')
            return redirect('validations',pk=pk)
    return render(request,'protection_validations.html',{'device':device,'form':form,'validations':device.validations.select_related('evidence')[:50],'now':timezone.now()})

@login_required
@require_http_methods(['GET','POST'])
def archives(request,pk):
    device=get_object_or_404(Device,pk=pk)
    if request.method=='POST':
        if not request.user.has_perm('core.manage_operations'):return HttpResponseForbidden()
        item=get_object_or_404(ConfigurationArchive,pk=request.POST.get('archive') if request.POST.get('archive','').isdigit() else 0,device=device,status='saved')
        note=request.POST.get('review_note','').strip()
        if not note or len(note)>4000:
            messages.error(request,'Documenta la revisión en un máximo de 4000 caracteres.')
        else:
            with transaction.atomic():
                item.review_note=note;item.reviewed_at=timezone.now();item.reviewed_by=request.user;item.save()
                from .models import OperationalIssue
                pending=device.configuration_archives.filter(status='saved',reviewed_at=None).exclude(changes=[]).exists()
                if not pending:OperationalIssue.objects.filter(key='device:'+str(device.pk)+':configuration-change',active=True).update(active=False,resolved_at=timezone.now())
                audit('firewall.backup_review',item)
        return redirect('configuration_archives',pk=pk)
    return render(request,'configuration_archives.html',{'device':device,'archives':device.configuration_archives.all()[:60]})

@login_required
@require_POST
def acknowledge(request,pk):
    if not request.user.has_perm('core.change_incident'):return HttpResponseForbidden()
    alert=get_object_or_404(UrgentAlert,pk=pk)
    with transaction.atomic():
        if UrgentAlert.objects.filter(pk=pk,acknowledged_at=None).update(acknowledged_at=timezone.now(),acknowledged_by=request.user):
            audit('urgent.acknowledged',alert)
    return redirect('delivery_status')

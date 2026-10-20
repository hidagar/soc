from datetime import timedelta
from django import forms
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.http import HttpResponseForbidden
from django.shortcuts import get_object_or_404,redirect,render
from django.utils import timezone
from django.views.decorators.http import require_http_methods
from .models import Client,Device,ExposureCheck,ExposureFinding,Incident,IncidentUpdate
from .security import audit

class ReviewForm(forms.Form):
    review=forms.ChoiceField(label='Decisión',choices=[('pending','Mantener pendiente'),('accepted','Documentar excepción temporal')])
    note=forms.CharField(label='Justificación y comprobaciones',widget=forms.Textarea(attrs={'rows':4}),max_length=4000)
    until=forms.DateTimeField(label='Revisar de nuevo antes de',required=False,widget=forms.DateTimeInput(attrs={'type':'datetime-local'},format='%Y-%m-%dT%H:%M'))
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        for field in self.fields.values(): field.widget.attrs['class']='input'
    def clean(self):
        v=super().clean()
        if v.get('review')=='accepted' and (not v.get('until') or not timezone.now()<v['until']<=timezone.now()+timedelta(days=365)):
            self.add_error('until','Indica una fecha futura, como máximo dentro de un año.')
        return v

@login_required
def exposure_list(request):
    selected=request.GET.get('client','')
    if selected and not selected.isdigit(): selected=''
    if selected: get_object_or_404(Client,pk=selected)
    devices=Device.objects.filter(active=True,site__active=True,site__client__active=True).select_related('site__client','exposure_check')
    findings=ExposureFinding.objects.filter(device__active=True,device__site__active=True,device__site__client__active=True).select_related('device__site__client','incident')
    if selected:
        devices=devices.filter(site__client_id=selected);findings=findings.filter(device__site__client_id=selected)
    rows=[];now=timezone.now()
    labels={'pending':'Pendiente','checked':'Listados consultados','partial':'Consulta parcial','unavailable':'Sin comprobación'}
    for d in devices:
        c=getattr(d,'exposure_check',None)
        rows.append({'device':d,'check':c,'label':labels.get(c.status if c else 'pending','Pendiente'),
            'stale':bool(c and c.checked_at and now-c.checked_at>timedelta(hours=12))})
    current=list(findings.filter(present=True));pending=[f for f in current if not f.exception_active]
    status=request.GET.get('status','pending')
    if status not in ('pending','accepted','all','removed'): status='pending'
    items= list(findings.filter(present=False)[:300]) if status=='removed' else current if status=='all' else [f for f in current if f.exception_active] if status=='accepted' else pending
    items.sort(key=lambda f:({'high':0,'medium':1,'info':2}.get(f.severity,3),-f.last_seen_at.timestamp()))
    return render(request,'exposure_list.html',{'rows':rows,'items':items[:300],'clients':Client.objects.all(),'selected_client':selected,'status':status,
        'pending_count':len(pending),'high_count':sum(f.severity=='high' for f in pending),'publication_count':sum(f.kind=='publication' for f in current),'accepted_count':len(current)-len(pending)})

@login_required
@require_http_methods(['POST'])
def exposure_recheck(request,pk):
    d=get_object_or_404(Device,pk=pk)
    if not request.user.has_perm('core.manage_operations'): return HttpResponseForbidden('Permiso de gestión del SOC requerido.')
    if not d.active or not d.site.active or not d.site.client.active or d.integration=='paused':
        messages.error(request,'Activa el equipo, la sede y el cliente antes de solicitar la revisión.')
    else:
        c,_=ExposureCheck.objects.get_or_create(device=d);c.requested_at=timezone.now();c.save(update_fields=['requested_at'])
        audit('exposure.recheck',c)
        messages.success(request,'Revisión de lectura solicitada al monitor. Entre comprobaciones del mismo equipo se respetan diez minutos.')
    return redirect('/operations/exposure/?client='+str(d.site.client_id))

@login_required
@require_http_methods(['POST'])
def exposure_interfaces(request,pk):
    import re
    device=get_object_or_404(Device,pk=pk)
    if not request.user.has_perm('core.manage_operations'):return HttpResponseForbidden('Permiso de gestión requerido.')
    values=[v.strip().lower() for v in request.POST.get('interfaces','').split(',') if v.strip()]
    if len(values)>16 or any(not re.fullmatch(r'[a-z0-9_.-]{1,32}',v) for v in values):
        messages.error(request,'Indica hasta 16 identificadores de interfaz separados por comas.')
    else:
        check,_=ExposureCheck.objects.get_or_create(device=device)
        check.external_interfaces=list(dict.fromkeys(values));check.requested_at=timezone.now();check.save(update_fields=['external_interfaces','requested_at'])
        audit('exposure.interfaces',check,{'fields':['external_interfaces']})
        messages.success(request,'Interfaces externas registradas para la revisión. No se ha cambiado el firewall.')
    return redirect('/operations/exposure/?client='+str(device.site.client_id))

@login_required
@require_http_methods(['GET','POST'])
def exposure_detail(request,pk):
    finding=get_object_or_404(ExposureFinding.objects.select_related('device__site__client','incident','reviewed_by'),pk=pk)
    form=ReviewForm(request.POST or None,initial={'review':finding.review,'note':finding.review_note,'until':finding.review_until})
    if request.method=='POST':
        if not request.user.has_perm('core.manage_operations'): return HttpResponseForbidden('Permiso de gestión del SOC requerido.')
        with transaction.atomic():
            finding=ExposureFinding.objects.select_for_update().get(pk=pk)
            # Reject stale forms if the rule changed or disappeared while it was being reviewed.
            if request.POST.get('fingerprint')!=finding.fingerprint or not finding.present:
                messages.error(request,'La evidencia ha cambiado o ya no aparece. Revisa los datos actuales antes de guardar.')
                return redirect('exposure_detail',pk=pk)
            if request.POST.get('action')=='incident':
                if not request.user.has_perm('core.add_incident'): return HttpResponseForbidden('Permiso para crear incidencias requerido.')
                if finding.incident_id:
                    messages.info(request,'Este hallazgo ya tiene una incidencia vinculada.')
                else:
                    incident=Incident.objects.create(client=finding.device.site.client,site=finding.device.site,device=finding.device,
                        title=finding.title,severity='high' if finding.severity=='high' else 'medium',
                        description='Revisión de configuración; no es prueba de ataque ni de acceso desde Internet.\n'+finding.recommendation+'\nEvidencia: '+json_evidence(finding))
                    finding.incident=incident;finding.save(update_fields=['incident'])
                    IncidentUpdate.objects.create(incident=incident,author=request.user,text='Incidencia creada desde Control de exposición. Asignar responsable y acción de seguimiento.')
                    audit('exposure.incident',finding,{'incident_id':incident.pk})
                return redirect('incident_detail',pk=finding.incident_id)
            if form.is_valid():
                finding.review=form.cleaned_data['review'];finding.review_note=form.cleaned_data['note']
                finding.review_until=form.cleaned_data['until'] if finding.review=='accepted' else None
                finding.reviewed_by=request.user;finding.reviewed_at=timezone.now();finding.save()
                finding.history=(finding.history+[{'at':finding.reviewed_at.isoformat(),'actor':request.user.username,'decision':finding.get_review_display(),'note':finding.review_note,'until':finding.review_until.isoformat() if finding.review_until else '', 'fingerprint':finding.fingerprint,'evidence':finding.evidence}])[-100:]
                finding.save(update_fields=['history'])
                IncidentUpdate.objects.create(incident=finding.incident,author=request.user,text='Revisión de exposición: '+finding.get_review_display()+'. '+finding.review_note) if finding.incident_id else None
                audit('exposure.review',finding,{'decision':finding.review,'until':finding.review_until.isoformat() if finding.review_until else None})
                messages.success(request,'Revisión documentada. No se ha modificado la configuración del firewall.')
                return redirect('exposure_detail',pk=pk)
    check=getattr(finding.device,'exposure_check',None)
    section=check.coverage.get(finding.section,{}) if check else {}
    return render(request,'exposure_detail.html',{'finding':finding,'form':form,'check':check,
        'uncertain':not check or section.get('status')!='checked' or section.get('preserve_unseen') or finding.remote_id in section.get('unresolved_rules',[]) or not check.checked_at or timezone.now()-check.checked_at>timedelta(hours=12)})

def json_evidence(finding):
    import json
    return json.dumps(finding.evidence,ensure_ascii=False,sort_keys=True)


@login_required
@require_http_methods(['GET'])
def unifi_policies(request,pk):
    device=get_object_or_404(Device.objects.select_related('site__client','exposure_check'),pk=pk,vendor='unifi')
    from .unifi_zone_scope import snapshot
    entry=snapshot(device)
    catalogue=entry['catalogue']
    zones=catalogue.get('zones',[])
    source=request.GET.get('source','');destination=request.GET.get('destination','')
    valid={z['id'] for z in zones}
    if (source and source not in valid) or (destination and destination not in valid):
        from django.http import Http404
        raise Http404()
    pairs=catalogue.get('pairs',[])
    by_pair={(p['source_id'],p['destination_id']):p for p in pairs}
    matrix=[{'zone':z,'cells':[{'destination':d,'pair':by_pair.get((z['id'],d['id']))} for d in zones]} for z in zones]
    filtered=[p for p in pairs if (not source or p['source_id']==source) and (not destination or p['destination_id']==destination)]
    class FlowForm(forms.Form):
        source_ip=forms.GenericIPAddressField(label='IP de origen',required=False,unpack_ipv4=False)
        destination_ip=forms.GenericIPAddressField(label='IP de destino',required=False,unpack_ipv4=False)
        protocol=forms.ChoiceField(label='Protocolo',choices=[(v,v) for v in ('TCP','UDP','ICMP','ICMPV6')])
        ip=forms.ChoiceField(label='Versión IP',choices=[('IPV4','IPv4'),('IPV6','IPv6')])
        state=forms.ChoiceField(label='Estado de conexión',choices=[('NEW','Nueva'),('ESTABLISHED','Establecida'),('RELATED','Relacionada'),('INVALID','No válida')])
        source_port=forms.IntegerField(label='Puerto de origen',min_value=1,max_value=65535,required=False)
        destination_port=forms.IntegerField(label='Puerto de destino',min_value=1,max_value=65535,required=False)
        source_network=forms.ChoiceField(label='Red de origen',required=False)
        destination_network=forms.ChoiceField(label='Red de destino',required=False)
    flow_form=FlowForm(request.GET if request.GET.get('flow')=='1' else None)
    for field,zid in (('source_network',source),('destination_network',destination)):
        zone=next((z for z in zones if z['id']==zid),{})
        choices=zone.get('network_choices') or [{'id':v,'name':'Red sin identificar ('+v[-6:]+')'} for v in zone.get('network_ids',[])]
        flow_form.fields[field].choices=[('','Sin especificar')]+[(v['id'],v['name']) for v in choices]
    flow_result=None
    if flow_form.is_bound and flow_form.is_valid():
        from .unifi_flow import evaluate
        flow=flow_form.cleaned_data
        if (flow['protocol']=='ICMP' and flow['ip']!='IPV4') or (flow['protocol']=='ICMPV6' and flow['ip']!='IPV6'):
            flow_form.add_error('protocol','El protocolo ICMP debe corresponder a la versión IP.')
        else:
            import ipaddress
            for field in ('source_ip','destination_ip'):
                if flow.get(field) and (ipaddress.ip_address(flow[field]).version==4)!=(flow['ip']=='IPV4'):
                    flow_form.add_error(field,'La dirección debe corresponder a la versión IP seleccionada.')
            if not flow_form.errors:flow_result=evaluate(by_pair.get((source,destination)),flow,entry['current'])
    return render(request,'unifi_policies.html',{'entry':entry,'device':device,'matrix':matrix,
        'zones':zones,'pairs':filtered,'source':source,'destination':destination,'flow_form':flow_form,'flow_result':flow_result})

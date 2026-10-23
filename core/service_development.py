"""Customer publication boundaries and evidence-based service follow-up."""
import ipaddress
import hashlib
import json
from calendar import monthrange
from datetime import datetime, time, timedelta
from django import forms
from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.db.models import Count, Max, Min, Q, F
from django.db.models.functions import TruncDate
from django.http import HttpResponseForbidden, HttpResponse, Http404,JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_GET, require_http_methods
from .models import (Client, Device, DeviceObservation, CustomerPublication, SecurityEvidence,
    Incident, IncidentAction, CustomerTask, WeeklyReport, FeedBucket, StaffAccess, ChangePlan)
from .security import audit
from .trends import period_metrics

OPEN_TASK_STATUSES=('pending','rework','submitted')

class PublicationForm(forms.ModelForm):
    class Meta:
        model=CustomerPublication
        fields=['title','summary','next_steps','status','incident','weekly_report','visible']
        labels={'incident':'Incidencia asociada','weekly_report':'Informe semanal asociado'}
        widgets={'summary':forms.Textarea(attrs={'rows':5}),'next_steps':forms.Textarea(attrs={'rows':4})}
    def __init__(self,*args,client,**kwargs):
        super().__init__(*args,**kwargs)
        self.fields['incident'].queryset=Incident.objects.filter(client=client)
        self.fields['weekly_report'].queryset=WeeklyReport.objects.filter(client=client)
        for field in self.fields.values():field.widget.attrs['class']='input'
    def clean_summary(self):
        value=self.cleaned_data['summary'].strip()
        if len(value)>6000:raise forms.ValidationError('Máximo 6000 caracteres.')
        return value
    def clean_next_steps(self):
        value=self.cleaned_data['next_steps'].strip()
        if len(value)>6000:raise forms.ValidationError('Máximo 6000 caracteres.')
        return value

@login_required
@require_http_methods(['GET','POST'])
def publish(request,client_pk):
    client=get_object_or_404(Client,pk=client_pk)
    if not request.user.has_perm('core.change_incident'):return HttpResponseForbidden('Permiso de gestión requerido.')
    publication=None
    if request.GET.get('edit','').isdigit():
        publication=get_object_or_404(CustomerPublication,pk=request.GET['edit'],client=client)
    form=PublicationForm(request.POST or None,client=client,instance=publication)
    if request.method=='POST' and form.is_valid():
        item=form.save(commit=False);item.client=client;item.save()
        audit('customer.publication',item,{'status':item.status,'fields':form.changed_data})
        return redirect('customer_publish',client_pk=client.pk)
    return render(request,'customer_publish.html',{'client':client,'form':form,'publications':CustomerPublication.objects.filter(client=client)[:100]})

def customer_client(request):
    access=StaffAccess.objects.filter(user=request.user,role='customer',all_clients=False).first()
    if not access or request.user.is_superuser:raise Http404
    ids=list(access.clients.values_list('pk',flat=True))
    if len(ids)!=1:raise Http404
    return get_object_or_404(Client,pk=ids[0],active=True)

def released_reports(client):
    return WeeklyReport.objects.filter(client=client).filter(
        Q(sent_at__isnull=False)|Q(customerpublication__visible=True)).distinct()

def customer_report_context(report):
    from types import SimpleNamespace
    from .reporting import report_context
    context=report_context(report)
    start=timezone.make_aware(datetime.combine(report.week_start,time.min));end=start+timedelta(days=7)
    publications=CustomerPublication.objects.filter(client=report.client,visible=True,incident__observed_at__gte=start,incident__observed_at__lt=end).select_related('incident')
    rows=[SimpleNamespace(title=p.title,observed_at=p.incident.observed_at,site=None,device=None,
        get_severity_display=lambda:'Comunicada',get_status_display=p.get_status_display,status=p.status) for p in publications]
    context.update(incidents=rows,incident_count=len(rows),resolved_count=sum(r.status=='resolved' for r in rows),
        open_count=sum(r.status!='resolved' for r in rows),authenticated_customer=True)
    return context

@login_required
@require_GET
def customer_home(request):
    return render(request,'customer_home.html',customer_home_context(customer_client(request)))

def customer_home_context(client,preview=False):
    """Inicio del portal del cliente; la vista previa del SOC usa el mismo contenido sin enlaces de respuesta."""
    from django.urls import reverse
    from .investigation import customer_security_summary
    from .customer_portal import firewall_rows,portal_links,wazuh_ready
    live=client.customer_live_map_enabled or client.customer_portal_detail_enabled
    reports=list(released_reports(client).order_by('-week_start')[:52])
    for report in reports:
        report.portal_url=reverse('customer_preview_report',args=[client.pk,report.pk]) if preview else reverse('customer_weekly',args=[report.pk])
    # Todas las pendientes, sin límite; las cerradas aparte para que no las desplacen.
    tasks=list(CustomerTask.objects.filter(incident__client=client,visible=True,status__in=OPEN_TASK_STATUSES).order_by(F('due_at').asc(nulls_last=True),'pk'))
    closed=list(CustomerTask.objects.filter(incident__client=client,visible=True).exclude(status__in=OPEN_TASK_STATUSES).order_by(F('reviewed_at').desc(nulls_last=True),'-pk')[:20])
    for task in tasks+closed:
        task.portal_url='' if preview else reverse('customer_task_reply',args=[task.pk])
    return {'client':client,'security_summary':customer_security_summary(client) if live else None,
        'portal_section':'home','portal':portal_links(client,preview),'wazuh_ready':wazuh_ready(client),
        'firewall_status':firewall_rows(client) if client.customer_portal_detail_enabled else None,
        'tasks':tasks,'closed_tasks':closed,'publications':CustomerPublication.objects.filter(client=client,visible=True)[:100],
        'reports':reports}

def customer_geography(request,client=None):
    from .threat_map import map_data
    client=client or customer_client(request)
    if not client.customer_live_map_enabled:raise Http404
    days=int(request.GET.get('days','7')) if request.GET.get('days','7') in ('1','7','30') else 7
    action=request.GET.get('action','all');direction=request.GET.get('direction','all')
    if action not in ('all','blocked','allowed','unknown'):action='all'
    if direction not in ('all','inbound','outbound','external','internal'):direction='all'
    payload=map_data(client,days,action,direction)
    # All event detail and internal operational state are discarded before serialization.
    payload['recent']=[];payload['geo_error']='';payload['history_pending']=False
    return client,payload,days,action,direction

@login_required
@require_GET
def customer_map(request):
    return render(request,'threat_map.html',customer_map_context(request,customer_client(request)))

def customer_map_context(request,client,preview=False):
    from .customer_portal import portal_links,wazuh_ready
    client,payload,days,action,direction=customer_geography(request,client)
    return {'customer_map':True,'map_base':'customer_report_base.html','portal_section':'map','wazuh_ready':wazuh_ready(client),
        'portal':portal_links(client,preview),
        'client':client,'map_client':client,'days':days,'action':action,'direction':direction,'map_payload':payload}

@login_required
@require_GET
def customer_map_data(request):
    return JsonResponse(customer_geography(request)[1])

def customer_version(request,pk,client=None):
    from .report_versions import published_version
    report=get_object_or_404(released_reports(client or customer_client(request)),pk=pk)
    raw=request.GET.get('version','')
    version=published_version(report,int(raw) if raw.isdigit() and len(raw)<6 else None)
    if not version:raise Http404
    return version,('?version='+str(version.number) if raw else '')

@login_required
@require_GET
def customer_weekly(request,pk):
    from django.urls import reverse
    from .report_versions import version_page
    version,suffix=customer_version(request,pk)
    return version_page(request,version,reverse('customer_weekly_pdf',args=[pk])+suffix,base='customer_report_base.html',
        versions=version.report.versions.all(),version_url=reverse('customer_weekly',args=[pk]))

@login_required
@require_GET
def customer_weekly_pdf(request,pk):
    from .report_versions import version_pdf
    version,_=customer_version(request,pk)
    return version_pdf(version,f'informe-semanal-v{version.number}.pdf')

def record_observation(device,health):
    """Persist only fixed non-secret fields; unknown results don't erase known data."""
    with transaction.atomic():
        Device.objects.select_for_update().get(pk=device.pk)
        previous=DeviceObservation.objects.filter(device=device).first()
        snap=dict(previous.snapshot) if previous else {}
        snap.update(model=device.model,software_version=device.software_version,
            zenarmor_version=device.zenarmor_version,active=device.active,api_ok=health.api_ok)
        if health.api_ok is True:
            snap['engines']={str(name)[:40]:{key:values[key] for key in
                ('running','enabled','configured','mode','export','bypass','version','daily')
                if key in values and isinstance(values[key],(str,int,bool,type(None))) and len(str(values[key]))<100}
                for name,values in health.engines.items() if isinstance(values,dict)}
        changes=[key for key in sorted(snap) if not previous or previous.snapshot.get(key)!=snap[key]]
        if changes:return DeviceObservation.objects.create(device=device,snapshot=snap,changes=changes)
        return previous

@login_required
@require_GET
def device_history(request,pk):
    device=get_object_or_404(Device,pk=pk)
    return render(request,'device_history.html',{'device':device,'observations':DeviceObservation.objects.filter(device=device)[:200],
        'incidents':Incident.objects.filter(device=device).order_by('-observed_at')[:100],
        'plans':ChangePlan.objects.filter(device=device).order_by('-pk')[:100]})

def is_outbound(source,destination):
    try:
        src,dst=ipaddress.ip_address(source),ipaddress.ip_address(destination)
        networks=[ipaddress.ip_network(x) for x in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','fc00::/7')]
        return any(src in net for net in networks if src.version==net.version) and dst.is_global
    except (ValueError,TypeError):return False

def priority_reasons(row):
    text=(row['signature']+' '+row['category']).lower()
    malware=any(word in text for word in ('malware','trojan','botnet','command-and-control','credential-theft','dga','ransomware'))
    reasons=[];score=0
    if malware and row['action']=='allowed':reasons.append('Indicador de malware permitido');score+=80
    elif row['action']=='allowed':reasons.append('Detección permitida');score+=30
    if malware and is_outbound(row['source_ip'],row['destination_ip']):reasons.append('Indicador de conexión saliente sospechosa');score+=50
    if row['asset__critical']:reasons.append('Equipo declarado crítico');score+=40
    if row['days']>=2:reasons.append('Reincidencia en varios días');score+=20
    if row['level']>=12:reasons.append('Nivel elevado en Wazuh');score+=50
    return score,reasons

def intelligence_rows(client_id=None,now=None):
    import heapq
    now=now or timezone.now()
    events=SecurityEvidence.objects.filter(observed_at__gte=now-timedelta(days=30),observed_at__lt=now,
        client_scope_id=F('device__site__client_id')).exclude(category='application_policy')
    if client_id:events=events.filter(device__site__client_id=client_id)
    groups=events.values('device_id','device__name','device__site__name','device__site__client__name','asset_id','asset__name','asset__discovered_name','asset__ip','asset__critical','identity__label','signature','category','action','source_ip','destination_ip').annotate(
        count=Count('uid'),days=Count(TruncDate('observed_at'),distinct=True),first=Min('observed_at'),last=Max('observed_at'),level=Max('level'),evidence_uid=Min('uid'),incident_pk=Max('incident_id'))
    # Evaluate risk before selection. Streaming bounds memory without hiding an
    # older critical detection behind more recent routine observations.
    seen=0
    def ranked():
        nonlocal seen
        for row in groups.order_by().iterator(chunk_size=500):
            seen+=1
            row['priority'],row['reasons']=priority_reasons(row)
            row['asset_label']=row['identity__label'] or row['asset__ip'] or 'Equipo por identificar'
            yield row
    rows=heapq.nlargest(500,ranked(),key=lambda r:(r['priority'],r['last'],r['evidence_uid']))
    return rows,seen>500

@login_required
@require_http_methods(['GET','POST'])
def intelligence(request):
    if request.method=='POST':
        if not request.user.has_perm('core.add_incident'):return HttpResponseForbidden('Permiso de incidencias requerido.')
        event=get_object_or_404(SecurityEvidence.objects.select_related('device__site__client','asset'),uid=request.POST.get('evidence',''))
        if event.category=='application_policy' or not timezone.now()-timedelta(days=30)<=event.observed_at<timezone.now():
            raise Http404('La evidencia ya no pertenece al periodo de revisión.')
        key='intelligence-'+hashlib.sha256(json.dumps([event.device_id,event.asset_id,event.signature,event.category,event.action]).encode()).hexdigest()
        with transaction.atomic():
            incident=event.incident or Incident.objects.filter(fingerprint=key).first()
            if incident is None:
                incident=Incident.objects.create(client=event.device.site.client,site=event.device.site,device=event.device,
                    title=event.signature[:220] or 'Revisar detección',severity='high',status='open',fingerprint=key,
                    observed_at=event.observed_at,last_seen_at=event.observed_at,description='Revisión solicitada desde detecciones prioritarias. Acción registrada: '+event.action+'.',
                    recommendation=event.recommendation,wazuh_alert_id=event.wazuh_id)
                event.incident=incident;event.save(update_fields=['incident'])
                audit('intelligence.incident',incident)
        return redirect('incident_detail',pk=incident.pk)
    selected=request.GET.get('client','');client=None
    if selected:
        if not selected.isdigit():raise Http404
        client=get_object_or_404(Client,pk=selected)
    view=request.GET.get('reputacion','')
    if view not in ('','lista','permitida','sin_ruido'):raise Http404
    rows,limited=intelligence_rows(client.pk if client else None)
    # Reputación CrowdSec: contexto y filtro de revisión; no altera prioridad, motivos ni orden.
    from .reputation import lookup_many
    reputations=lookup_many(row['source_ip'] for row in rows)
    for row in rows:
        row['reputation']=reputation=reputations.get(row['source_ip'])
        row['listed']=bool(reputation and reputation.flagged)
        row['noise']=bool(reputation and reputation.noise)
        row['listed_allowed']=row['listed'] and row['action']=='allowed'
    counts={'listed':sum(row['listed'] for row in rows),'listed_allowed':sum(row['listed_allowed'] for row in rows)}
    if view=='sin_ruido':rows=[row for row in rows if not row['noise']]
    elif view:rows=[row for row in rows if row['listed_allowed' if view=='permitida' else 'listed']]
    return render(request,'intelligence.html',{'rows':rows,'limited':limited,'clients':Client.objects.all(),'selected':selected,
        'view':view,'counts':counts})

def monthly_context(client,month,now=None):
    now=now or timezone.now()
    start=timezone.make_aware(datetime.combine(month.replace(day=1),time.min))
    next_month=(month.replace(day=28)+timedelta(days=4)).replace(day=1)
    finish=timezone.make_aware(datetime.combine(next_month,time.min))
    end=min(finish,now)
    previous_month=(month.replace(day=1)-timedelta(days=1)).replace(day=1)
    previous_start=timezone.make_aware(datetime.combine(previous_month,time.min))
    # Same local calendar days and time for an open month; complete months compare calendar totals.
    if now<finish:
        local=timezone.localtime(end)
        day=min(local.day,monthrange(previous_month.year,previous_month.month)[1])
        previous_end=timezone.make_aware(datetime.combine(previous_month.replace(day=day),local.time().replace(tzinfo=None)))
    else:previous_end=start
    events=SecurityEvidence.objects.filter(device__site__client=client).exclude(category='application_policy')
    metrics=period_metrics(events,start,end);old=period_metrics(events,previous_start,previous_end)
    incidents=Incident.objects.filter(client=client)
    actions=IncidentAction.objects.filter(incident__client=client)
    return {'client':client,'month':month,'start':start,'end':end,'provisional':now<finish,'metrics':metrics,'previous':old,
        'resolved':incidents.filter(resolved_at__gte=start,resolved_at__lt=end).count(),
        'soc_completed':actions.filter(responsible_party='soc',status='done',completed_at__gte=start,completed_at__lt=end)[:100],
        'client_pending':actions.filter(responsible_party='client',created_at__lt=end).exclude(status__in=['done','cancelled'])[:100],
        'assets':events.filter(observed_at__gte=start,observed_at__lt=end,asset__isnull=False).values('asset__ip','identity__label','device__site__name').annotate(count=Count('uid')).order_by('-count')[:20],
        'hours':FeedBucket.objects.filter(device__site__client=client,hour__gte=start,hour__lt=end).values('hour').distinct().count()}

@login_required
@require_GET
def monthly(request,client_pk):
    client=get_object_or_404(Client,pk=client_pk)
    raw=request.GET.get('month',timezone.localdate().strftime('%Y-%m'))
    try:
        month=datetime.strptime(raw,'%Y-%m').date().replace(day=1)
        if month>timezone.localdate().replace(day=1) or month.year<2020:raise ValueError
    except ValueError:raise Http404('Mes no válido.')
    context=monthly_context(client,month)
    if request.GET.get('format')=='pdf':
        response=HttpResponse(monthly_pdf(context),content_type='application/pdf')
        response['Content-Disposition']=f'attachment; filename="resumen-{month:%Y-%m}.pdf"'
        return response
    return render(request,'monthly_summary.html',context)

def monthly_pdf(context):
    from io import BytesIO
    from html import escape
    from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.pagesizes import A4
    styles=getSampleStyleSheet();body=[]
    styles['BodyText'].fontSize=10;styles['BodyText'].leading=15
    def paragraph(value,style='BodyText'):
        body.extend([Paragraph(escape(str(value)).replace('\n','<br/>'),styles[style]),Spacer(1,10)])
    paragraph('ib-red · Resumen ejecutivo mensual','Title')
    paragraph(f"{context['client'].name} · {context['month']:%m/%Y}",'Heading1')
    paragraph('Periodo provisional' if context['provisional'] else 'Mes completo')
    m=context['metrics'];old=context['previous']
    paragraph(f"Detecciones recibidas: {m['total']}. Bloqueadas: {m['blocked']}. Permitidas: {m['allowed']}. Equipos identificados: {m['assets']}. Incidencias resueltas: {context['resolved']}.")
    paragraph(f"Periodo anterior: {old['total']} detecciones. En un mes abierto se comparan días y hora equivalentes, limitados por la duración del mes anterior.")
    paragraph(f"Registros en {context['hours']} horas distintas. No acredita cobertura continua ni ausencia de ataques. Una detección no confirma infección.")
    paragraph('Qué resolvió ib-red','Heading2')
    for item in context['soc_completed']:paragraph(item.title+'\n'+item.resolution)
    if not context['soc_completed']:paragraph('No hay acciones SOC completadas y documentadas en el periodo.')
    paragraph('Qué debe hacer el cliente','Heading2')
    paragraph('Pendientes actuales creadas antes del final del periodo; no reconstruye el estado histórico.')
    for item in context['client_pending']:
        due=timezone.localtime(item.due_at).strftime('%d/%m/%Y') if item.due_at else 'Por acordar'
        paragraph(item.title+'\n'+item.description+'\nFecha límite: '+due)
    if not context['client_pending']:paragraph('No hay acciones pendientes asignadas al cliente.')
    paragraph('Equipos que requieren revisión','Heading2')
    for asset in context['assets']:paragraph(f"{asset['identity__label'] or asset['asset__ip']} · {asset['asset__ip']} · {asset['device__site__name']} · {asset['count']} detecciones")
    paragraph('Contacto: noc@ibred.es')
    def footer(canvas,doc):
        canvas.saveState();canvas.setFont('Helvetica',8)
        canvas.drawString(48,27,'ib-red · Seguridad gestionada · Confidencial')
        canvas.drawRightString(A4[0]-48,27,f'Página {doc.page}')
        canvas.restoreState()
    buffer=BytesIO();SimpleDocTemplate(buffer,pagesize=A4,rightMargin=48,leftMargin=48,topMargin=48,bottomMargin=48).build(body,onFirstPage=footer,onLaterPages=footer)
    return buffer.getvalue()

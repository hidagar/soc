from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.db.models import Q
from django.http import HttpResponseForbidden
from django.shortcuts import get_object_or_404,redirect,render
from django.contrib import messages
from django.utils import timezone
from django.views.decorators.http import require_http_methods
from .models import IncidentAction,Incident,IncidentUpdate,Client
from .security import audit
from .forms import ScopedModelForm

CLOSED=('done','cancelled')

class ActionForm(ScopedModelForm):
    class Meta:
        model=IncidentAction
        fields=['title','description','owner','responsible_party','due_at','status','resolution']
        widgets={'due_at':forms.DateTimeInput(attrs={'type':'datetime-local'},format='%Y-%m-%dT%H:%M'),'description':forms.Textarea(attrs={'rows':4}),'resolution':forms.Textarea(attrs={'rows':4})}
    def __init__(self,*args,incident,**kwargs):
        self.incident=incident
        super().__init__(*args,**kwargs)
        self.fields['owner'].queryset=get_user_model().objects.filter(is_active=True).filter(Q(is_superuser=True)|Q(soc_access__all_clients=True)|Q(soc_access__clients__pk=incident.client_id)).exclude(soc_access__role='customer').distinct()
        for f in self.fields.values():f.widget.attrs['class']='input'
    def clean(self):
        values=super().clean()
        if values.get('status') in CLOSED and not values.get('resolution','').strip():
            self.add_error('resolution','Documenta la evidencia de resolución o el motivo de cancelación.')
        if values.get('status') not in CLOSED:
            if not values.get('owner'):self.add_error('owner','Asigna un responsable de seguimiento.')
            if not values.get('due_at'):self.add_error('due_at','Indica una fecha límite.')
        return values

@login_required
def action_list(request):
    rows=IncidentAction.objects.select_related('incident__client','incident__site','incident__device','owner')
    client=request.GET.get('client','')
    if client.isdigit():
        selected=get_object_or_404(Client,pk=client)
        rows=rows.filter(incident__client=selected)
    status=request.GET.get('status','open')
    if status=='overdue':rows=rows.exclude(status__in=CLOSED).filter(due_at__lt=timezone.now())
    elif status=='open':rows=rows.exclude(status__in=CLOSED)
    elif status in dict(IncidentAction._meta.get_field('status').choices):rows=rows.filter(status=status)
    if request.GET.get('mine')=='1':rows=rows.filter(owner=request.user)
    all_actions=IncidentAction.objects.all()
    if client.isdigit():all_actions=all_actions.filter(incident__client_id=client)
    return render(request,'action_list.html',{'actions':rows.order_by('due_at','-created_at')[:300],'clients':Client.objects.all(),'selected_client':client,'status':status,'mine':request.GET.get('mine')=='1','statuses':IncidentAction._meta.get_field('status').choices,'open_count':all_actions.exclude(status__in=CLOSED).count(),'overdue_count':all_actions.exclude(status__in=CLOSED).filter(due_at__lt=timezone.now()).count(),'done_count':all_actions.filter(status='done').count()})

@login_required
@require_http_methods(['GET','POST'])
def action_form(request,incident_pk=None,pk=None):
    item=get_object_or_404(IncidentAction.objects.select_related('incident'),pk=pk) if pk else None
    incident=item.incident if item else get_object_or_404(Incident,pk=incident_pk)
    if not request.user.has_perm('core.change_incident'):
        return HttpResponseForbidden('Permiso de gestión de incidencias requerido.')
    initial={'title':'Revisar '+incident.title[:220],'description':incident.recommendation,'owner':incident.owner_id or request.user.pk} if item is None else {}
    form=ActionForm(request.POST or None,instance=item,incident=incident,initial=initial)
    if request.method=='POST' and form.is_valid():
        with transaction.atomic():
            saved=form.save(commit=False);saved.incident=incident
            saved.completed_at=(item.completed_at if item and item.completed_at else timezone.now()) if saved.status in CLOSED else None
            saved.save()
            if saved.status not in CLOSED and incident.status=='resolved':
                incident.status='investigating';incident.resolved_at=None
                incident.save(update_fields=['status','resolved_at','updated_at'])
                IncidentUpdate.objects.create(incident=incident,author=request.user,text='Incidencia reabierta a investigación al registrar una acción pendiente.')
            IncidentUpdate.objects.create(incident=incident,author=request.user,text=f'Acción: {saved.title}. Estado: {saved.get_status_display()}. Responsable de seguimiento: {saved.owner.username if saved.owner else "Sin asignar"}.'+(f' Evidencia: {saved.resolution}' if saved.status in CLOSED else ''))
            from .sla import record
            record(incident,'investigate')
            audit('incident.action_saved',saved,{'status':saved.status,'owner':saved.owner_id,'due_at':saved.due_at.isoformat() if saved.due_at else None})
        messages.success(request,'Acción guardada y registrada en el historial de la incidencia.')
        return redirect('incident_detail',pk=incident.pk)
    return render(request,'action_form.html',{'form':form,'incident':incident,'item':item})

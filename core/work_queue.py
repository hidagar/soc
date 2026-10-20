"""Scoped daily operations and race-safe, explicit incident ownership."""
from datetime import timedelta
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.db.models import Case, When, Value, IntegerField, Max
from django.db.models.functions import Coalesce, Greatest
from django.http import HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST
from .models import Client, Incident, IncidentAction, IncidentUpdate, OperationalIssue
from .security import audit


@login_required
def work_queue(request):
    selected = request.GET.get('client', '')
    incidents = Incident.objects.exclude(status='resolved').select_related('client', 'site', 'device', 'owner').annotate(
        latest_activity=Greatest('updated_at', Coalesce(Max('timeline__created_at'), 'updated_at')),
    )
    actions = IncidentAction.objects.exclude(status__in=('done', 'cancelled')).select_related('incident__client', 'owner')
    issues = OperationalIssue.objects.filter(active=True, device__active=True).select_related('device__site__client')
    if selected:
        client = get_object_or_404(Client, pk=selected) if selected.isdigit() else None
        if client is None:
            from django.http import Http404
            raise Http404
        incidents = incidents.filter(client=client)
        actions = actions.filter(incident__client=client)
        issues = issues.filter(device__site__client=client)
    now = timezone.now()
    stale_before = now - timedelta(hours=24)
    overdue = actions.filter(due_at__lt=now)
    counts = {
        'unassigned': incidents.filter(owner__isnull=True).count(),
        'priority': incidents.filter(severity__in=('high', 'critical')).count(),
        'stale': incidents.filter(latest_activity__lt=stale_before).count(),
        'overdue': overdue.count(),
    }
    queue = request.GET.get('queue', 'unassigned')
    if queue not in ('unassigned', 'priority', 'stale', 'mine', 'all'):
        queue = 'unassigned'
    rows = incidents
    if queue == 'unassigned': rows = rows.filter(owner__isnull=True)
    elif queue == 'priority': rows = rows.filter(severity__in=('high', 'critical'))
    elif queue == 'stale': rows = rows.filter(latest_activity__lt=stale_before)
    elif queue == 'mine': rows = rows.filter(owner=request.user)
    rows = rows.annotate(priority_order=Case(
        When(severity='critical', then=Value(0)), When(severity='high', then=Value(1)),
        When(severity='medium', then=Value(2)), default=Value(3), output_field=IntegerField(),
    )).order_by('priority_order', 'observed_at', 'pk')
    return render(request, 'work_queue.html', {
        'clients': Client.objects.all(), 'selected_client': selected, 'queue': queue,
        'counts': counts, 'incidents': rows[:100], 'incident_total': rows.count(),
        'overdue_actions': overdue.order_by('due_at', 'pk')[:50],
        'issues': issues.order_by('opened_at', 'pk')[:50], 'issue_total': issues.count(),
    })


@login_required
@require_POST
def claim_incident(request, pk):
    if not request.user.is_active or not request.user.has_perm('core.change_incident') or getattr(getattr(request.user, 'soc_access', None), 'role', None) == 'customer':
        return HttpResponseForbidden('Permiso de gestión de incidencias requerido.')
    with transaction.atomic():
        incident = get_object_or_404(Incident, pk=pk)
        changed = Incident.objects.filter(pk=incident.pk, owner__isnull=True, status__in=('open', 'investigating')).update(
            owner=request.user, status='investigating', updated_at=timezone.now(),
        )
        if changed:
            IncidentUpdate.objects.create(incident=incident, author=request.user, text='Caso asumido por ' + request.user.username + '. Estado: En investigación.')
            audit('incident.claimed', incident, {'status': 'investigating', 'fields': ['owner']})
            messages.success(request, 'Caso asignado a ti y marcado en investigación.')
        else:
            messages.warning(request, 'El caso ya tiene responsable o está resuelto. Revisa su estado actual.')
    return redirect('incident_detail', pk=pk)

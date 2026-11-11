"""Solicitudes al SOC desde el portal del cliente.

- El cliente abre una solicitud (consulta, cambio, desbloqueo o sospecha de incidente), sigue la
  conversación y puede darla por resuelta. Solo ve los mensajes del SOC marcados para él: las notas
  internas no salen nunca (invariante 3). Límite de solicitudes abiertas y por día para evitar abusos.
- El equipo SOC recibe un correo interno por cada solicitud nueva (como mucho una vez) y las atiende
  desde «Respuesta › Solicitudes de clientes»: responder, pedir información, resolver, nota interna,
  asignarse o abrir una incidencia enlazada.
- Cada respuesta del SOC al cliente genera un aviso por correo a quien la abrió, sin el texto (enlaza
  al portal). Un envío dudoso queda «por comprobar» y no se repite (invariante 6).
"""
from datetime import timedelta

from django import forms
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.db import transaction
from django.http import HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.cache import never_cache

from .models import Client, CustomerRequest, CustomerRequestEntry, Incident, IncidentUpdate, Site
from .security import audit

MAX_OPEN = 20
MAX_PER_DAY = 10
REOPEN_DAYS = 14
MAX_TEXT = 6000
HINTS = {
    'question': 'Cualquier duda sobre vuestra seguridad, los informes o el servicio.',
    'change': 'Abrir un acceso, una VPN, publicar un servicio… Indicad qué, para quién y desde cuándo.',
    'unblock': 'Una web, aplicación o dirección bloqueada que necesitáis. Indicad cuál, desde qué equipo y a qué hora.',
    'incident': 'Algo raro: un correo sospechoso abierto, un equipo extraño, un aviso del antivirus… Si es grave, llamad también al NOC.',
}


class NewRequestForm(forms.Form):
    kind = forms.ChoiceField(label='Qué necesitáis', choices=CustomerRequest.KINDS, widget=forms.RadioSelect)
    subject = forms.CharField(label='Asunto', max_length=160, widget=forms.TextInput(attrs={'class': 'input'}))
    site = forms.ModelChoiceField(label='Sede (opcional)', queryset=Site.objects.none(), required=False,
                                  empty_label='Todas o no aplica', widget=forms.Select(attrs={'class': 'input'}))
    text = forms.CharField(label='Detalle', max_length=MAX_TEXT,
                           widget=forms.Textarea(attrs={'class': 'input', 'rows': 6, 'maxlength': MAX_TEXT}))
    urgent = forms.BooleanField(label='Afecta al trabajo ahora mismo', required=False)

    def __init__(self, *args, client, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['site'].queryset = Site.objects.filter(client=client, active=True).order_by('name')


def _fallback_email(client):
    """Cuenta del portal sin correo: los avisos van al contacto del cliente."""
    from .customer_notices import recipient
    return recipient(client)


# --- Avisos ----------------------------------------------------------------------------------

def _queue_notice(entry, request_obj):
    try:
        validate_email(request_obj.contact_email)
    except ValidationError:
        return
    entry.notice_status = 'queued'
    entry.save(update_fields=['notice_status'])


def send_pending(limit=10, now=None):
    """Avisos al cliente de las respuestas del SOC. Si el SOC ha respondido varias veces antes del envío,
    sale un solo correo por solicitud."""
    from .invitations import origin
    from .mail_delivery import MailConfigurationError, MailDeliveryError, send_customer_email
    now = now or timezone.now()
    manager = CustomerRequestEntry._base_manager
    manager.filter(notice_status='sending', notice_attempted_at__lt=now - timedelta(minutes=10)).update(
        notice_status='uncertain', notice_error='El envío se interrumpió; comprobar en «Entrega y avisos» antes de reenviar.')
    sent = 0
    request_ids = list(manager.filter(notice_status='queued').order_by('request_id').values_list('request_id', flat=True).distinct()[:limit])
    for req in CustomerRequest._base_manager.filter(pk__in=request_ids).select_related('client'):
        ids = list(manager.filter(request=req, notice_status='queued').values_list('pk', flat=True))
        if not req.client.active:
            manager.filter(pk__in=ids, notice_status='queued').update(notice_status='skipped', notice_error='Cliente inactivo.')
            continue
        if manager.filter(pk__in=ids, notice_status='queued').update(notice_status='sending', notice_attempted_at=now) != len(ids):
            manager.filter(pk__in=ids, notice_status='sending', notice_attempted_at=now).update(notice_status='queued')
            continue
        context = {'request': req, 'client': req.client, 'status': req.status,
                   'url': origin() + reverse('customer_request_detail', args=[req.pk]),
                   'logo_url': origin() + '/static/brand/ibred-empresas-color.png'}
        subject = {'waiting': 'El SOC necesita información', 'resolved': 'Solicitud resuelta'}.get(req.status, 'Respuesta del SOC')
        try:
            provider = send_customer_email(req.contact_email, f'{subject} · {req.reference} · ib-red empresas',
                                           render_to_string('request_notice_email.txt', context),
                                           render_to_string('request_notice_email.html', context),
                                           delivery_context={'client': req.client, 'kind': 'request'})
        except MailConfigurationError:
            manager.filter(pk__in=ids).update(notice_status='failed', notice_error='El correo del SOC no está configurado y probado.')
        except MailDeliveryError:
            manager.filter(pk__in=ids).update(notice_status='uncertain', notice_error='SendGrid no confirmó la aceptación.')
        except Exception:
            manager.filter(pk__in=ids).update(notice_status='failed', notice_error='No se pudo preparar el aviso.')
        else:
            manager.filter(pk__in=ids).update(notice_status='accepted', notice_sent_at=now, provider_id=str(provider)[:180], notice_error='')
            sent += 1
    return sent


def notify_soc(now=None):
    """Correo interno al equipo SOC con las solicitudes nuevas o con mensaje nuevo del cliente. Se marca
    antes de enviar: como mucho una vez por novedad (sigue visible en la bandeja aunque el correo falle)."""
    from .invitations import origin
    from .mail_delivery import send_customer_email
    from .models import RecoverySettings
    now = now or timezone.now()
    cfg = RecoverySettings.objects.filter(pk=1, notify_enabled=True).first()
    pending = list(CustomerRequest._base_manager.filter(soc_notified_at__isnull=True).select_related('client').order_by('created_at')[:30])
    if not pending:
        return 0
    CustomerRequest._base_manager.filter(pk__in=[r.pk for r in pending]).update(soc_notified_at=now)
    if not cfg or not cfg.operational_email:
        return 0
    lines = [f'{r.reference} · {r.client.name} · {r.get_kind_display()}{" · URGENTE" if r.urgent else ""}: {r.subject}\n'
             f'{origin()}{reverse("request_detail", args=[r.pk])}' for r in pending]
    urgent = any(r.urgent or r.kind == 'incident' for r in pending)
    try:
        send_customer_email(cfg.operational_email, ('URGENTE · ' if urgent else '') + 'Centro SOC: solicitudes de clientes con novedades',
                            'Solicitudes nuevas o con mensaje nuevo del cliente:\n\n' + '\n\n'.join(lines),
                            render_to_string('request_soc_email.html', {'rows': pending, 'origin': origin()}))
    except Exception:
        import logging
        logging.getLogger(__name__).warning('No se pudo enviar el aviso interno de solicitudes nuevas.')
        return 0
    return len(pending)


# --- Portal del cliente ----------------------------------------------------------------------

def portal_requests(client):
    return list(CustomerRequest.objects.filter(client=client).select_related('site')[:100])


def customer_requests_context(client, preview=False):
    from .service_development import _portal_base
    rows = portal_requests(client)
    return {**_portal_base(client, preview, 'requests'), 'requests': rows, 'hints': HINTS,
            'waiting': [r for r in rows if r.status == 'waiting']}


@login_required
@never_cache
def customer_list(request):
    from .service_development import customer_client
    client = customer_client(request)
    form = NewRequestForm(request.POST or None, client=client)
    if request.method == 'POST':
        now = timezone.now()
        manager = CustomerRequest.objects.filter(client=client)
        if manager.exclude(status='resolved').count() >= MAX_OPEN:
            form.add_error(None, f'Tenéis {MAX_OPEN} solicitudes abiertas. Cerrad las que ya estén resueltas o escribid a noc@ibred.es.')
        elif manager.filter(created_at__gte=now - timedelta(days=1)).count() >= MAX_PER_DAY:
            form.add_error(None, 'Se ha alcanzado el máximo de solicitudes nuevas por día. Escribid a noc@ibred.es si es urgente.')
        elif form.is_valid():
            data = form.cleaned_data
            with transaction.atomic():
                req = CustomerRequest.objects.create(
                    client=client, site=data['site'], created_by=request.user, contact_email=request.user.email or _fallback_email(client),
                    kind=data['kind'], subject=data['subject'].strip(), urgent=data['urgent'], created_at=now, updated_at=now)
                CustomerRequestEntry.objects.create(request=req, kind='customer', author=request.user, text=data['text'].strip(),
                                                    status='new', created_at=now)
                audit('customer.request', req, {'status': 'new'})
            return redirect(reverse('customer_request_detail', args=[req.pk]) + '?enviada=1')
    return render(request, 'customer_requests.html', {**customer_requests_context(client), 'form': form})


@login_required
@never_cache
def customer_detail(request, pk):
    from .service_development import _portal_base, customer_client
    client = customer_client(request)
    req = get_object_or_404(CustomerRequest, pk=pk, client=client)
    error = ''
    if request.method == 'POST':
        action = request.POST.get('action', 'reply')
        now = timezone.now()
        if action == 'close' and req.open:
            with transaction.atomic():
                CustomerRequest.objects.filter(pk=req.pk).update(status='resolved', resolved_at=now, updated_at=now)
                CustomerRequestEntry.objects.create(request=req, kind='customer', author=request.user, created_at=now,
                                                    text='Damos la solicitud por resuelta.', status='resolved')
                audit('customer.request', req, {'status': 'resolved'})
            return redirect('customer_request_detail', pk=req.pk)
        text = request.POST.get('text', '').strip()
        if not text or len(text) > MAX_TEXT:
            error = f'Escribe el mensaje, en un máximo de {MAX_TEXT} caracteres.'
        elif req.status == 'resolved' and (not req.resolved_at or now - req.resolved_at > timedelta(days=REOPEN_DAYS)):
            error = 'Esta solicitud se cerró hace más de dos semanas. Abre una nueva.'
        else:
            status = 'in_progress' if req.status in ('waiting', 'resolved') else req.status
            with transaction.atomic():
                CustomerRequest.objects.filter(pk=req.pk).update(status=status, updated_at=now,
                                                                 resolved_at=None if status != 'resolved' else req.resolved_at)
                CustomerRequestEntry.objects.create(request=req, kind='customer', author=request.user, text=text, status=status, created_at=now)
                CustomerRequest.objects.filter(pk=req.pk).update(soc_notified_at=None)  # novedad para el equipo SOC
                audit('customer.request', req, {'status': status})
            return redirect(reverse('customer_request_detail', args=[req.pk]) + '?enviada=1')
    entries = req.entries.exclude(kind='internal')
    return render(request, 'customer_request_detail.html', {**_portal_base(client, False, 'requests'), 'req': req,
                  'entries': entries, 'error': error, 'sent': request.GET.get('enviada') == '1',
                  'can_reply': req.open or (req.resolved_at and timezone.now() - req.resolved_at <= timedelta(days=REOPEN_DAYS))})


def open_summary(client):
    rows = CustomerRequest.objects.filter(client=client).exclude(status='resolved')
    return {'open': rows.count(), 'waiting': rows.filter(status='waiting').count()}


# --- SOC -------------------------------------------------------------------------------------

def soc_queue():
    """Para la bandeja: solicitudes abiertas que esperan al SOC, las urgentes primero."""
    return list(CustomerRequest.objects.filter(status__in=('new', 'in_progress')).select_related('client', 'owner')
                .order_by('-urgent', 'updated_at')[:50])


@login_required
@never_cache
def soc_list(request):
    state = request.GET.get('state', 'open')
    rows = CustomerRequest.objects.select_related('client', 'site', 'owner')
    if state == 'open':
        rows = rows.exclude(status='resolved')
    elif state in dict(CustomerRequest.STATUSES):
        rows = rows.filter(status=state)
    client_id = request.GET.get('client', '')
    if client_id.isdigit():
        rows = rows.filter(client_id=int(client_id))
    return render(request, 'requests.html', {'rows': rows[:200], 'state': state, 'clients': Client.objects.all(),
                                             'selected_client': client_id, 'statuses': CustomerRequest.STATUSES})


@login_required
@never_cache
def soc_detail(request, pk):
    req = get_object_or_404(CustomerRequest.objects.select_related('client', 'site', 'owner', 'incident'), pk=pk)
    if request.method == 'POST':
        if not request.user.has_perm('core.change_incident'):
            return HttpResponseForbidden('Tu cuenta no tiene permiso para atender solicitudes.')
        action, now = request.POST.get('action', ''), timezone.now()
        text = request.POST.get('text', '').strip()
        if action == 'assign':
            CustomerRequest.objects.filter(pk=req.pk).update(owner=request.user, updated_at=now)
            audit('request.assign', req, {'owner': request.user.pk})
        elif action == 'note':
            if not text or len(text) > MAX_TEXT:
                messages.error(request, 'Escribe la nota.')
            else:
                CustomerRequestEntry.objects.create(request=req, kind='internal', author=request.user, text=text, status=req.status, created_at=now)
                audit('request.note', req, {'status': req.status})
        elif action == 'reply':
            status = request.POST.get('status', 'in_progress')
            if status not in ('in_progress', 'waiting', 'resolved'):
                return HttpResponseForbidden('Estado no válido.')
            if not text or len(text) > MAX_TEXT:
                messages.error(request, 'Escribe la respuesta para el cliente.')
                return redirect('request_detail', pk=req.pk)
            with transaction.atomic():
                fields = {'status': status, 'updated_at': now, 'resolved_at': now if status == 'resolved' else None}
                if not req.first_response_at:
                    fields['first_response_at'] = now
                if not req.owner_id:
                    fields['owner'] = request.user
                CustomerRequest.objects.filter(pk=req.pk).update(**fields)
                entry = CustomerRequestEntry.objects.create(request=req, kind='soc', author=request.user, text=text, status=status, created_at=now)
                _queue_notice(entry, req)
                audit('request.reply', req, {'status': status})
            messages.success(request, 'Respuesta enviada al portal del cliente.'
                             + (' Le avisamos por correo en el próximo minuto.' if entry.notice_status == 'queued' else ''))
        elif action == 'incident':
            if not request.user.has_perm('core.add_incident'):
                return HttpResponseForbidden('Tu cuenta no puede abrir incidencias.')
            if req.incident_id:
                return redirect('incident_detail', pk=req.incident_id)
            first = req.entries.filter(kind='customer').first()
            with transaction.atomic():
                incident = Incident.objects.create(
                    client=req.client, site=req.site, title=f'{req.reference}: {req.subject}'[:220],
                    description=f'Abierta desde la solicitud {req.reference} del cliente.\n\n{first.text if first else ""}',
                    severity='high' if req.urgent or req.kind == 'incident' else 'medium', owner=request.user)
                IncidentUpdate.objects.create(incident=incident, author=request.user, text=f'Creada desde la solicitud {req.reference}.')
                CustomerRequest.objects.filter(pk=req.pk).update(incident=incident, updated_at=now, owner=req.owner or request.user)
                audit('request.incident', req, {'incident_id': incident.pk})
            messages.success(request, 'Incidencia abierta y enlazada. Las respuestas al cliente siguen en la solicitud.')
            return redirect('incident_detail', pk=incident.pk)
        else:
            return HttpResponseForbidden('Acción no válida.')
        return redirect('request_detail', pk=req.pk)
    return render(request, 'request_detail.html', {'req': req, 'entries': req.entries.select_related('author'),
                                                   'hints': HINTS})


def soc_counts():
    rows = CustomerRequest.objects.filter(status__in=('new', 'in_progress'))
    return {'requests_waiting_soc': rows.count(), 'requests_urgent': rows.filter(urgent=True).count()}

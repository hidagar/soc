"""Políticas propuestas: revisión del SOC, aprobación del cliente en el portal y avisos."""
from datetime import timedelta

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_POST

from .models import ChangePlan, Client, PolicyProposal
from .security import audit

CUSTOMER_STATUSES = ('offered', 'approved', 'rejected', 'applied', 'verified', 'not_effective')
CUSTOMER_LABELS = {'offered': 'Pendiente de vuestra decisión', 'approved': 'Aprobada · el SOC la aplicará en la ventana acordada',
                   'rejected': 'Rechazada', 'applied': 'Aplicada · el SOC está comprobando el resultado',
                   'verified': 'Aplicada y comprobada', 'not_effective': 'Aplicada · el SOC está revisando el resultado'}


# Lo que el SOC tiene entre manos. «Sin efecto comprobado» sigue aquí hasta que alguien lo revisa.
OPEN_SOC = ('proposed', 'offered', 'approved', 'applied', 'not_effective')


# --- Lo que se le enseña al cliente ----------------------------------------------------------

def customer_summary(proposal):
    """Solo cifras, el servicio y el firewall: nunca IPs, reglas internas ni notas del SOC (invariante 3)."""
    e = proposal.evidence or {}
    stats = e.get('attacks') or {}
    summary = {'period_days': 30, 'firewall': e.get('firewall', ''), 'site': e.get('site', ''), 'service': e.get('service', '')}
    if stats:
        summary.update({'attacks': stats.get('total', 0), 'allowed': stats.get('allowed', 0), 'sources': stats.get('sources', 0),
                        'countries': stats.get('countries', 0), 'top_countries': stats.get('top_countries', [])[:5]})
    for key in ('destinations', 'internal_hosts', 'repeat_sources', 'events'):
        if key in e:
            summary[key] = e[key]
    if proposal.kind == 'outbound_c2':
        summary['allowed'] = e.get('allowed', 0)
    return summary


def default_text(proposal):
    s = customer_summary(proposal)
    kind = proposal.kind
    if kind in ('restrict_service', 'geo_filter'):
        text = f'El servicio {s["service"]} del firewall {s["firewall"]} está publicado en Internet y acepta conexiones desde cualquier dirección.'
        if s.get('attacks'):
            text += (f' En los últimos 30 días hemos visto {s["attacks"]} intentos de ataque desde {s["sources"]} direcciones'
                     f'{" de " + str(s["countries"]) + " países" if s.get("countries") else ""}'
                     f'{", y " + str(s["allowed"]) + " no fueron bloqueados" if s.get("allowed") else ""}.')
        if kind == 'restrict_service':
            return text + (' Proponemos permitir el acceso solo desde las direcciones que lo necesitan (por ejemplo, vuestro proveedor '
                           'o vuestras oficinas) o a través de la VPN. Antes de aplicarlo os preguntaremos qué accesos hay que mantener.')
        return text + (' Casi todos esos ataques llegan de fuera de vuestros países habituales. Proponemos aceptar conexiones a este '
                       'servicio solo desde ellos. Quien necesite acceder desde el extranjero tendría que usar la VPN.')
    if kind == 'ips_block':
        return (f'El sistema de prevención de intrusiones del firewall {s["firewall"]} está configurado para avisar, pero no para bloquear.'
                + (f' En los últimos 30 días dejó pasar {s["allowed"]} detecciones.' if s.get('allowed') else '')
                + ' Proponemos activar el bloqueo, revisando antes las alertas para no cortar tráfico legítimo.')
    if kind == 'outbound_c2':
        return (f'Hemos visto conexiones desde vuestra red hacia {s.get("destinations", 0)} destinos que figuran en listas de malware '
                'o de control remoto. Proponemos que los firewalls bloqueen la salida hacia esos destinos con la lista del SOC, '
                'que se mantiene actualizada. Revisaremos además los equipos implicados.')
    return (f'En los últimos 30 días, {s.get("repeat_sources", 0)} direcciones os han atacado repetidamente. Proponemos activar '
            'la lista de bloqueo del SOC, que bloquea de antemano a los atacantes ya conocidos y se actualiza sola.')


def portal_context(client):
    rows = list(PolicyProposal.objects.filter(client=client, status__in=CUSTOMER_STATUSES).order_by('-offered_at'))
    for row in rows:
        row.customer_status = CUSTOMER_LABELS.get(row.status, '')
    return {'pending_policies': [r for r in rows if r.status == 'offered'], 'policy_history': [r for r in rows if r.status != 'offered']}


def pending_count(client):
    return PolicyProposal.objects.filter(client=client, status='offered').count()


def has_policies(client):
    return PolicyProposal.objects.filter(client=client, status__in=CUSTOMER_STATUSES).exists()


def customer_context(client, preview=False):
    from .service_development import _portal_base
    return {**_portal_base(client, preview, 'policies'), **portal_context(client)}


@login_required
@never_cache
def customer_list(request):
    from .service_development import customer_client
    return render(request, 'customer_policies.html', customer_context(customer_client(request)))


@login_required
@require_POST
def customer_decision(request, pk):
    """Aprobar o rechazar. Exige MFA reciente (middleware) y queda registrado quién y cuándo."""
    from .service_development import customer_client
    client = customer_client(request)
    proposal = get_object_or_404(PolicyProposal, pk=pk, client=client)
    decision = request.POST.get('decision', '')
    if decision not in ('approved', 'rejected'):
        return HttpResponseForbidden('Decisión no válida.')
    note = request.POST.get('note', '').strip()[:2000]
    now = timezone.now()
    changed = PolicyProposal.objects.filter(pk=proposal.pk, client=client, status='offered').update(
        status=decision, decided_at=now, decided_by=request.user, decision_note=note, updated_at=now, soc_notified_at=None)
    if changed:
        audit('customer.policy_decision', proposal, {'decision': decision})
        messages.success(request, 'Gracias. Hemos registrado vuestra aprobación; os confirmaremos cuando esté aplicado.'
                         if decision == 'approved' else 'Hemos registrado que no queréis este cambio. Gracias por indicárnoslo.')
    else:
        messages.info(request, 'Esta propuesta ya no está pendiente de decisión.')
    return redirect('customer_policies')


# --- Avisos ----------------------------------------------------------------------------------

def send_pending(limit=5, now=None):
    """Un correo por cliente con las propuestas ofrecidas en cola, sin detalles: enlaza al portal."""
    from .invitations import origin
    from .mail_delivery import MailConfigurationError, MailDeliveryError, send_customer_email
    now = now or timezone.now()
    manager = PolicyProposal._base_manager
    manager.filter(notice_status='sending', notice_attempted_at__lt=now - timedelta(minutes=10)).update(
        notice_status='uncertain', notice_error='El envío se interrumpió; comprobar en «Entrega y avisos» antes de reenviar.')
    sent = 0
    client_ids = list(manager.filter(notice_status='queued').order_by('client_id').values_list('client_id', flat=True).distinct()[:limit])
    for client in Client._base_manager.filter(pk__in=client_ids):
        rows = list(manager.filter(client=client, notice_status='queued'))
        ready = [p for p in rows if p.status == 'offered' and client.active and client.task_notices_enabled]
        stale = [p.pk for p in rows if p not in ready]
        manager.filter(pk__in=stale, notice_status='queued').update(notice_status='skipped', notice_error='Ya no aplica.')
        if not ready:
            continue
        ids = [p.pk for p in ready]
        if manager.filter(pk__in=ids, notice_status='queued').update(notice_status='sending', notice_attempted_at=now) != len(ids):
            manager.filter(pk__in=ids, notice_status='sending', notice_attempted_at=now).update(notice_status='queued')
            continue
        context = {'client': client, 'count': len(ready), 'url': origin() + reverse('customer_policies'),
                   'logo_url': origin() + '/static/brand/ibred-empresas-color.png'}
        try:
            provider = send_customer_email(ready[0].notice_recipient, 'Cambios de seguridad propuestos · ib-red empresas',
                                           render_to_string('policy_notice_email.txt', context),
                                           render_to_string('policy_notice_email.html', context),
                                           delivery_context={'client': client, 'kind': 'policy'})
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
    """Correo interno con las decisiones nuevas de los clientes; como mucho una vez por decisión."""
    from .invitations import origin
    from .mail_delivery import send_customer_email
    from .models import RecoverySettings
    now = now or timezone.now()
    rows = list(PolicyProposal._base_manager.filter(status__in=('approved', 'rejected'), soc_notified_at__isnull=True)
                .select_related('client')[:30])
    if not rows:
        return 0
    PolicyProposal._base_manager.filter(pk__in=[r.pk for r in rows]).update(soc_notified_at=now)
    cfg = RecoverySettings.objects.filter(pk=1, notify_enabled=True).first()
    if not cfg or not cfg.operational_email:
        return 0
    lines = [f'{r.reference} · {r.client.name} · {"APROBADA" if r.status == "approved" else "rechazada"}: {r.title}' for r in rows]
    try:
        send_customer_email(cfg.operational_email, 'Centro SOC: decisiones de clientes sobre cambios propuestos',
                            'Decisiones nuevas:\n\n' + '\n'.join(lines) + f'\n\n{origin()}{reverse("policies")}',
                            render_to_string('policy_soc_email.html', {'rows': rows, 'url': origin() + reverse('policies')}))
    except Exception:
        import logging
        logging.getLogger(__name__).warning('No se pudo enviar el aviso interno de decisiones de clientes.')
        return 0
    return len(rows)


# --- Página del SOC --------------------------------------------------------------------------

def _groups(state):
    rows = PolicyProposal.objects.select_related('client', 'device', 'exposure', 'decided_by', 'change_plan')
    if state == 'open':
        rows = rows.filter(status__in=OPEN_SOC)
    elif state == 'closed':
        rows = rows.exclude(status__in=OPEN_SOC)
    order = {'approved': 0, 'not_effective': 1, 'proposed': 2, 'offered': 3, 'applied': 4}
    result = {}
    for p in sorted(rows, key=lambda p: (order.get(p.status, 9), {'high': 0, 'medium': 1, 'low': 2}[p.confidence], p.pk)):
        group = result.setdefault(p.client_id, {'client': p.client, 'rows': [], 'todo': 0})
        if p.status == 'proposed':
            p.suggested_text = default_text(p)
        p.plans = list(ChangePlan.objects.filter(device__site__client=p.client).order_by('-created_at')[:10]) if p.status == 'approved' else []
        if p.status == 'approved' and p.kind == 'restrict_service':
            from .policy_changes import automatable
            p.manual_reason = automatable(p)
            p.can_automate = not p.manual_reason
        group['rows'].append(p)
        group['todo'] += p.status in ('proposed', 'approved', 'not_effective')
    return sorted(result.values(), key=lambda g: (-g['todo'], g['client'].name))


@login_required
@never_cache
def overview(request):
    if request.method == 'POST':
        return _act(request)
    state = request.GET.get('state', 'open')
    state = state if state in ('open', 'closed', 'all') else 'open'
    return render(request, 'policies.html', {'groups': _groups(state), 'state': state})


def _act(request):
    action, now = request.POST.get('action', ''), timezone.now()
    if action == 'recalculate':
        if not request.user.has_perm('core.change_incident'):
            return HttpResponseForbidden('Tu cuenta no puede recalcular las propuestas.')
        from .policy_proposals import generate
        created = generate(now, clients=list(Client.objects.filter(active=True)))
        messages.success(request, f'Propuestas recalculadas: {created} nueva{"s" if created != 1 else ""}.')
        return redirect('policies')
    pk = request.POST.get('proposal', '')
    proposal = get_object_or_404(PolicyProposal, pk=int(pk) if pk.isdigit() else 0)
    needs = 'core.change_device' if action in ('applied', 'recheck', 'plan') else 'core.change_incident'
    if not request.user.has_perm(needs):
        return HttpResponseForbidden('Tu cuenta no tiene permiso para esta acción.')
    manager = PolicyProposal.objects.filter(pk=proposal.pk)
    if action == 'offer' and proposal.status == 'proposed':
        title = request.POST.get('customer_title', '').strip()[:220]
        text = request.POST.get('customer_text', '').strip()[:3000]
        planned = parse_datetime(request.POST.get('planned_for', '') or '')
        if planned and timezone.is_naive(planned):
            planned = timezone.make_aware(planned)
        if not title or not text or not planned or planned < now:
            messages.error(request, 'Indica el título, la explicación y una ventana futura para el cambio.')
            return redirect('policies')
        from .customer_notices import recipient
        address = recipient(proposal.client) if proposal.client.task_notices_enabled else ''
        manager.filter(status='proposed').update(
            status='offered', customer_title=title, customer_text=text, planned_for=planned, customer_summary=customer_summary(proposal),
            offered_at=now, offered_by=request.user, updated_at=now, decided_at=None, decided_by=None, decision_note='',
            notice_status='queued' if address else '', notice_recipient=address)
        audit('policy.offer', proposal, {'status': proposal.kind})
        messages.success(request, f'Propuesta enviada al portal de {proposal.client.name}.'
                         + (' Le avisamos por correo en el próximo minuto.' if address else
                            ' No recibe correo: activa «Avisos de actuaciones» en sus servicios si quieres avisarle.'))
    elif action == 'withdraw' and proposal.status == 'offered':
        manager.filter(status='offered').update(status='proposed', updated_at=now, offered_at=None, customer_summary={})
        PolicyProposal.objects.filter(pk=proposal.pk, notice_status='queued').update(notice_status='skipped', notice_error='Retirada por el SOC.')
        audit('policy.withdraw', proposal, {'status': proposal.kind})
        messages.success(request, 'Propuesta retirada del portal del cliente.')
    elif action == 'dismiss' and proposal.status == 'proposed':
        reason = request.POST.get('reason', '').strip()[:240]
        if not reason:
            messages.error(request, 'Indica por qué se descarta (uso interno).')
            return redirect('policies')
        manager.update(status='dismissed', dismissed_reason=reason, updated_at=now)
        audit('policy.dismiss', proposal, {'reason': reason})
        messages.success(request, 'Propuesta descartada. Volverá a evaluarse dentro de 90 días si sigue aplicando.')
    elif action == 'recheck' and proposal.status == 'not_effective':
        # Se corrigió lo que faltaba: vuelve a verificación con la fecha de hoy.
        manager.filter(status='not_effective').update(status='applied', applied_at=now, verified_at=None, updated_at=now,
                                                       verification={'text': 'Corregida por el SOC; pendiente de volver a comprobar.'})
        audit('policy.recheck', proposal, {'status': proposal.kind})
        messages.success(request, 'Vuelve a verificación: se comprobará de nuevo a partir de 7 días.')
    elif action == 'close' and proposal.status == 'not_effective':
        reason = request.POST.get('reason', '').strip()[:240]
        if not reason:
            messages.error(request, 'Indica por qué se cierra (uso interno).')
            return redirect('policies')
        manager.filter(status='not_effective').update(status='dismissed', dismissed_reason=reason, decided_at=now, updated_at=now)
        audit('policy.dismiss', proposal, {'reason': reason})
        messages.success(request, 'Propuesta cerrada.')
    elif action == 'plan' and proposal.status == 'approved':
        from . import policy_changes
        if not request.user.has_perm('core.manage_connections'):
            return HttpResponseForbidden('Preparar un cambio en el firewall requiere el permiso de conexiones.')
        try:
            origins = policy_changes.parse_origins(request.POST.get('origins', ''))
            plan = policy_changes.create_plan(proposal, origins, request.user)
        except ValueError as exc:
            messages.error(request, str(exc))
            return redirect('policies')
        audit('change.draft', plan, {'template': plan.template})
        messages.success(request, 'Borrador creado: todavía no se ha escrito nada en el firewall. Revísalo y sigue los pasos del control de cambios.')
        return redirect('change_detail', pk=plan.pk)
    elif action == 'applied' and proposal.status == 'approved':
        note = request.POST.get('note', '').strip()[:500]
        plan_id = request.POST.get('change_plan', '')
        plan = ChangePlan.objects.filter(pk=int(plan_id), device__site__client=proposal.client).first() if plan_id.isdigit() else None
        if not note and not plan:
            messages.error(request, 'Indica qué se ha cambiado o el plan del control de cambios usado.')
            return redirect('policies')
        manager.filter(status='approved').update(status='applied', applied_at=now, applied_by=request.user, applied_note=note,
                                                  change_plan=plan, updated_at=now)
        audit('policy.applied', proposal, {'status': proposal.kind})
        messages.success(request, 'Marcada como aplicada. El SOC comprobará el efecto a partir de 7 días.')
    else:
        messages.info(request, 'La propuesta ha cambiado de estado; revisa la página.')
    return redirect('policies')

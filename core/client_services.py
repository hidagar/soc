"""Servicios de un cliente en un solo sitio: la ficha del cliente y, filtrada, la de cada sede.

- **Ajustes de comunicación** (portal, informes, avisos): se editan aquí con un solo formulario.
- **Servicios con sus propias garantías** (lista de bloqueo, plazos de atención, publicación del informe
  mensual): aquí se muestran su estado y un enlace. Se configuran en su página, que conserva MFA, control
  de cambios y auditoría.
- **Por firewall**: recepción de registros, Zenarmor, regla de bloqueo y copias de configuración.
"""
from django import forms
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse
from django.views.decorators.http import require_POST

from .models import Client
from .security import audit

COMMUNICATION_FIELDS = ['customer_portal_detail_enabled', 'customer_live_map_enabled', 'weekly_reports_enabled', 'report_email',
                        'monthly_reports_enabled', 'monthly_email', 'urgent_alerts_enabled', 'urgent_email',
                        'urgent_availability_enabled', 'task_notices_enabled', 'task_email']


class ClientServicesForm(forms.ModelForm):
    """Ajustes de comunicación del cliente, con las mismas reglas que antes tenía la ficha de edición."""

    class Meta:
        model = Client
        fields = COMMUNICATION_FIELDS

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs['class'] = 'input' if not isinstance(field.widget, forms.CheckboxInput) else ''
            if isinstance(field, forms.EmailField):
                field.widget.attrs['placeholder'] = 'correo@cliente.es'

    def clean(self):
        values = super().clean()
        contact = self.instance.contact_email if self.instance else ''
        if values.get('weekly_reports_enabled') and not values.get('report_email'):
            self.add_error('report_email', 'Indica el correo que recibirá el informe antes de activar el envío.')
        if values.get('monthly_reports_enabled') and not (values.get('monthly_email') or values.get('report_email')):
            self.add_error('monthly_email', 'Indica el correo del informe mensual o el de informes.')
        if values.get('urgent_alerts_enabled') and not (values.get('urgent_email') or values.get('report_email')):
            self.add_error('urgent_email', 'Indica el correo para avisos urgentes o el de informes semanales.')
        if values.get('urgent_availability_enabled') and not values.get('urgent_alerts_enabled'):
            self.add_error('urgent_availability_enabled', 'Activa primero los avisos urgentes.')
        if values.get('task_notices_enabled') and not (values.get('task_email') or contact or values.get('report_email')):
            self.add_error('task_email', 'Indica a quién avisar: este correo, el de contacto o el de informes.')
        return values


def status(client):
    """Estado de los servicios que se configuran en su propia página."""
    from .models import BlocklistFeed, MonthlyReport, SlaPolicy, SlaSettings, StaffAccess
    feed = BlocklistFeed.objects.filter(client=client).first()
    if not feed or not feed.enabled:
        blocklist = ('paused', 'Desactivada')
    elif feed.stopped:
        blocklist = ('pending', 'Detenida con el freno de emergencia')
    else:
        blocklist = ('ok', f'Publicada · {len(feed.entries)} IP' + ('s' if len(feed.entries) != 1 else '') + (' · salida C2' if feed.outbound_enabled else ''))
    sla = SlaSettings.objects.filter(pk=1).first()
    own = SlaPolicy.objects.filter(client=client).count()
    if not (sla and sla.enabled):
        plazos = ('paused', 'Desactivados en todo el SOC')
    else:
        plazos = ('ok', f'Activados · {own} gravedades con plazo propio' if own else 'Activados · plazos generales')
    latest = MonthlyReport.objects.filter(client=client, published_at__isnull=False).order_by('-month').first()
    from .monthly_report import month_label
    users = StaffAccess.objects.filter(role='customer', clients=client).count()
    from .customer_portal import wazuh_ready
    return {
        'blocklist': blocklist, 'sla': plazos, 'portal_users': users, 'wazuh': wazuh_ready(client),
        'monthly': ('ok', 'Último publicado: ' + month_label(latest.month)) if latest else ('paused', 'Ninguno publicado'),
    }


def device_rows(devices):
    """Estado por firewall de lo que se activa en él."""
    from .blocklist import TEMPLATES
    from .models import ChangePlan, ConfigurationArchive, UnifiBlocklistBinding
    devices = list(devices)
    ids = [d.pk for d in devices]
    plans = {}
    for plan in ChangePlan._base_manager.filter(device_id__in=ids, template__in=TEMPLATES).order_by('pk'):
        plans[plan.device_id] = plan  # el último plan del dispositivo manda
    # La de entrada manda; la de salida (C2) solo si no hay de entrada.
    bindings = {b.device_id: b for b in UnifiBlocklistBinding._base_manager.filter(device_id__in=ids).order_by('-direction')}
    archives = {}
    for archive in ConfigurationArchive._base_manager.filter(device_id__in=ids, status='saved').order_by('created_at'):
        archives[archive.device_id] = archive
    for device in devices:
        export = getattr(device, 'export_configuration', None)
        health = getattr(device, 'health', None)
        if health and health.last_log_at:
            device.svc_logs = ('ok', 'Recibiendo')
        elif export:
            device.svc_logs = ('pending', export.get_status_display())
        else:
            device.svc_logs = ('paused', 'Envío sin configurar')
        device.svc_zenarmor = ('ok', 'Incluido') if device.zenarmor_enabled else None
        plan, binding = plans.get(device.pk), bindings.get(device.pk)
        if plan:
            device.svc_block = ('ok', 'Regla activa') if plan.status == 'active' else ('pending', 'Regla preparada, sin activar')
        elif binding:
            device.svc_block = (('ok', 'Política activa') if binding.enabled and binding.policies_enabled else
                                ('pending', 'Lista escrita, política sin activar'))
        elif device.vendor in ('opnsense', 'unifi'):
            device.svc_block = ('paused', 'Sin regla')
        else:
            device.svc_block = None
        archive = archives.get(device.pk)
        device.svc_archive = ('ok', f'Última {archive.created_at:%d/%m}') if archive else None
    return devices


@login_required
@require_POST
def save(request, pk):
    if not request.user.has_perm('core.change_client'):
        return HttpResponseForbidden('Tu cuenta no tiene permiso para cambiar los servicios del cliente.')
    client = get_object_or_404(Client, pk=pk)
    site = client.sites.filter(pk=request.POST.get('site')).first() if request.POST.get('site', '').isdigit() else None
    target = reverse('site_detail', args=[site.pk]) if site else reverse('client_detail', args=[client.pk])
    form = ClientServicesForm(request.POST, instance=client)
    if form.is_valid():
        if form.changed_data:
            form.save()
            audit('client.services', client, {'fields': form.changed_data})
            messages.success(request, 'Servicios del cliente guardados.')
        else:
            messages.info(request, 'No había cambios que guardar.')
        return redirect(target + '#servicios')
    for field, errors in form.errors.items():
        label = form.fields[field].label if field in form.fields else ''
        messages.error(request, (f'{label}: ' if label else '') + ' '.join(errors))
    return redirect(target + '#servicios')


def portal_users(client):
    """Cuentas del portal de este cliente y si ya han activado su acceso."""
    from .models import StaffAccess
    rows = StaffAccess.objects.filter(role='customer', clients=client).select_related('user').order_by('user__email')
    return [{'email': a.user.email or a.user.get_username(), 'active': a.user.is_active,
             'pending': not a.user.has_usable_password()} for a in rows]


@login_required
@require_POST
def invite(request, pk):
    """Alta de un usuario del portal para este cliente y su invitación, en un paso.

    Mismas condiciones que la gestión de usuarios: permiso de seguridad, acceso global y MFA reciente.
    La cuenta solo ve este cliente; la contraseña la pone el usuario con el enlace (48 h, un solo uso).
    """
    from django.contrib.auth import get_user_model
    from django.db import transaction
    from .blocklist import global_access
    from .invitations import queue
    from .models import StaffAccess
    from .security import mfa_fresh
    if not request.user.has_perm('core.manage_security') or not global_access(request.user):
        return HttpResponseForbidden('Dar acceso al portal requiere administración global de seguridad.')
    if not mfa_fresh(request):
        return redirect('mfa_challenge')
    client = get_object_or_404(Client, pk=pk)
    target = reverse('client_detail', args=[client.pk]) + '#servicios'
    email = request.POST.get('email', '').strip().lower()
    try:
        forms.EmailField().clean(email)
    except forms.ValidationError:
        messages.error(request, 'Indica un correo válido para el usuario del portal.')
        return redirect(target)
    User = get_user_model()
    if User.objects.filter(email__iexact=email).exists() or User.objects.filter(username__iexact=email).exists():
        messages.error(request, 'Ya existe una cuenta con ese correo. Revísala en «Usuarios y permisos».')
        return redirect(target)
    with transaction.atomic():
        user = User(username=email, email=email, is_active=True)
        user.set_unusable_password()
        user.save()
        access = StaffAccess.objects.create(user=user, role='customer', all_clients=False)
        access.clients.set([client])
        audit('staff.access', user, {'role': 'customer', 'clients': [client.pk], 'all_clients': False})
        queue(user)
    messages.success(request, f'Acceso al portal creado para {email}. La invitación sale en el próximo minuto y caduca en 48 horas.')
    return redirect(target)


def can_invite(user):
    from .blocklist import global_access
    return user.has_perm('core.manage_security') and global_access(user)

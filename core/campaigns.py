"""Ataques a varios clientes: una misma IP pública que ataca a varios clientes del SOC en poco tiempo.

Es la señal más clara de una campaña (escaneo dirigido a una tecnología, fuerza bruta contra
VPN...) y la mejor candidata para un bloqueo común. Frenos:
- Se calcula con el gestor con ámbito: un operador con clientes asignados solo ve las IPs que
  atacan a varios de *sus* clientes y nunca el nombre de otros (invariante 1).
- Solo orígenes públicos que no sean de un cliente o del SOC (`protected_addresses`).
- Que ataque a varios clientes no prueba un compromiso (invariante 4): se propone bloquear y
  se muestran las permitidas, nada más.
- El bloqueo común es un `ManualBlock` para todos los clientes: acceso global, MFA reciente,
  motivo y caducidad, y siguen mandando las excepciones de cada cliente.
"""
import ipaddress
from datetime import timedelta

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import Count, F, Max, Q
from django.http import HttpResponseForbidden
from django.shortcuts import redirect, render
from django.utils import timezone
from django.views.decorators.http import require_http_methods

from .models import Client, ManualBlock, SecurityEvidence

MIN_CLIENTS = 3
WINDOWS = {'24': timedelta(hours=24), '72': timedelta(hours=72), '168': timedelta(days=7)}


def _blocked_networks(now):
    """Redes con un bloqueo manual común vigente (entrada o ambas direcciones)."""
    networks = []
    for value in ManualBlock._base_manager.filter(client=None, revoked_at=None, expires_at__gt=now).exclude(
            direction='out').values_list('network', flat=True):
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError:
            continue
    return networks


def campaigns(now=None, window=WINDOWS['24'], min_clients=MIN_CLIENTS):
    """IPs que han atacado a `min_clients` o más clientes visibles en la ventana, de más a menos clientes."""
    from .reputation import protected_addresses
    now = now or timezone.now()
    rows = (SecurityEvidence.objects
            .filter(observed_at__gte=now - window, observed_at__lte=now, client_scope_id__isnull=False,
                    client_scope_id=F('device__site__client_id'))
            .exclude(category='application_policy').exclude(source_ip=None)
            .values('source_ip', 'client_scope_id')
            .annotate(events=Count('uid'), allowed=Count('uid', filter=Q(action='allowed')), last=Max('observed_at')))
    grouped = {}
    for row in rows:
        grouped.setdefault(row['source_ip'], []).append(row)
    candidates = {ip: items for ip, items in grouped.items() if len(items) >= min_clients}
    if not candidates:
        return []
    protected, blocked = protected_addresses(), _blocked_networks(now)
    names = dict(Client.objects.filter(pk__in={r['client_scope_id'] for items in candidates.values() for r in items})
                 .values_list('pk', 'name'))
    result = []
    for ip, items in candidates.items():
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if not address.is_global or ip in protected:
            continue
        items.sort(key=lambda r: (-r['events'], r['client_scope_id']))
        result.append({
            'ip': ip, 'clients': len(items), 'events': sum(r['events'] for r in items),
            'allowed': sum(r['allowed'] for r in items), 'last': max(r['last'] for r in items),
            'blocked': any(address.version == n.version and address in n for n in blocked),
            'per_client': [{'client_id': r['client_scope_id'], 'name': names.get(r['client_scope_id'], 'Cliente'),
                            'events': r['events'], 'allowed': r['allowed']} for r in items],
        })
    result.sort(key=lambda c: (c['blocked'], -c['clients'], -c['allowed'], -c['events'], c['ip']))
    return result


def pending_count(now=None):
    """Campañas de las últimas 24 h sin bloqueo común: el número que aparece en «Requiere atención»."""
    return sum(1 for c in campaigns(now) if not c['blocked'])


@login_required
@require_http_methods(['GET', 'POST'])
def campaign_list(request):
    from .blocklist import global_access
    from .reputation import lookup_many
    from .security import audit, mfa_fresh
    can_block = request.user.has_perm('core.manage_operations') and global_access(request.user)
    if request.method == 'POST':
        if not can_block:
            return HttpResponseForbidden('Bloquear para todos los clientes requiere acceso global y permiso de operaciones.')
        if not mfa_fresh(request):
            return redirect('mfa_challenge')
        return _block(request, audit)
    key = request.GET.get('ventana', '24')
    key = key if key in WINDOWS else '24'
    rows = campaigns(window=WINDOWS[key])
    reputations = lookup_many(row['ip'] for row in rows)
    for row in rows:
        row['reputation'] = reputations.get(row['ip'])
    return render(request, 'campaigns.html', {
        'rows': rows, 'window': key, 'min_clients': MIN_CLIENTS, 'can_block': can_block,
        'pending': sum(1 for r in rows if not r['blocked']),
        'windows': [('24', '24 horas'), ('72', '3 días'), ('168', '7 días')],
    })


def _block(request, audit):
    """Bloqueo común (todos los clientes) de una IP que aparece en la vista: nunca una IP arbitraria."""
    from .blocklist import MANUAL_MAX_DAYS, add_manual, refresh_feeds
    ip = request.POST.get('ip', '')
    current = {c['ip']: c for c in campaigns(window=WINDOWS['168'])}
    if ip not in current:
        messages.error(request, 'Esa IP ya no figura como ataque a varios clientes; revisa la lista actualizada.')
        return redirect('campaign_list')
    try:
        days = int(request.POST.get('days', '7'))
    except ValueError:
        days = 0
    if not 1 <= days <= MANUAL_MAX_DAYS:
        messages.error(request, f'La caducidad debe estar entre 1 y {MANUAL_MAX_DAYS} días.')
        return redirect('campaign_list')
    item = current[ip]
    post = request.POST.copy()
    post.update({'network': ip, 'scope': 'all', 'direction': 'in', 'days': str(days),
                 'reason': f'Ataque a {item["clients"]} clientes ({item["events"]} detecciones) · '
                           f'bloqueo común desde «Ataques a varios clientes»'})
    request.POST = post
    error = add_manual(request, None)
    if error:
        messages.error(request, error)
        return redirect('campaign_list')
    refresh_feeds()
    messages.success(request, f'{ip} bloqueada para todos los clientes con la lista activada durante {days} días. '
                              'Los firewalls la aplicarán en su próxima descarga (UniFi, en 15 minutos como mucho).')
    return redirect('campaign_list')

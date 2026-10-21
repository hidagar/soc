"""Listas de bloqueo del SOC para los firewalls de cada cliente (hoja de ruta 7A/C2, fase 1).

El SOC hace de puente entre CrowdSec y los firewalls, con frenos:
- Solo entran IPs que han atacado a algún cliente del SOC en los últimos 7 días y que
  CrowdSec tiene en una lista (dato de menos de 24 h) o califica de maliciosas en la CTI
  (dato vigente). Nunca ruido de fondo, posibles falsos positivos, IPs no públicas, IPs
  de clientes o del SOC, ni las excepciones del cliente. Con un máximo de entradas.
- Observación: sin tocar el firewall, se calcula qué habría bloqueado con las detecciones
  reales del cliente.
- El firewall descarga la lista con un token propio del cliente. El freno de emergencia
  sirve una lista vacía. La regla de bloqueo se crea con el control de cambios (borrador
  desactivado, aprobación, savepoint y reversión), nunca desde esta página directamente.
"""
import hashlib
import hmac
import ipaddress
import secrets
from datetime import timedelta

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.db.models import Count, Q
from django.http import Http404, HttpResponse, HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET, require_http_methods

from .models import BlocklistFeed, ChangePlan, Client, Device, IpReputation, SecurityEvidence
from .reputation import TTL, protected_addresses
from .security import audit, decrypt, encrypt

WINDOW = timedelta(days=7)
LISTS_FRESH = timedelta(hours=24)
MAX_ALLOWLIST = 200
TEMPLATE = 'crowdsec'
TITLE = 'Bloqueo CrowdSec del SOC'
VERSION = '1.0'


def parse_allowlist(text):
    """Excepciones del cliente: IPs o redes CIDR, una por línea. ValueError si alguna no es válida."""
    networks = []
    for line in (text or '').splitlines():
        value = line.split('#', 1)[0].strip()
        if not value:
            continue
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError:
            raise ValueError(f'Excepción no válida: {value[:60]}') from None
    if len(networks) > MAX_ALLOWLIST:
        raise ValueError(f'Como máximo {MAX_ALLOWLIST} excepciones.')
    return networks


def qualifying(now):
    """IPs con motivo vigente para bloquear y su motivo. La reputación sola no basta: ver `build`."""
    rows = IpReputation.objects.filter(
        Q(listed=True, lists_checked_at__gte=now - LISTS_FRESH) |
        Q(cti_found=True, reputation='malicious', cti_checked_at__gte=now - TTL))
    result = {}
    for row in rows.iterator(chunk_size=1000):
        if row.cti_found and (row.background_noise == 'high' or row.false_positives):
            continue  # Ruido de fondo de Internet o posible falso positivo: nunca se bloquea.
        reasons = []
        if row.listed and row.lists_checked_at and row.lists_checked_at >= now - LISTS_FRESH:
            reasons += list(row.list_origins or ['Lista CrowdSec'])
        if row.cti_found and row.reputation == 'malicious' and row.cti_checked_at and row.cti_checked_at >= now - TTL:
            reasons.append('CTI: maliciosa')
        if reasons:
            result[row.ip] = {'reasons': reasons[:4], 'listed': bool(row.listed), 'cti': row.reputation == 'malicious'}
    return result


def activity(ips, now):
    """Detecciones de los últimos 7 días de esas IPs, por cliente (propietario histórico)."""
    stats = {}
    wanted = sorted(ips)
    for start in range(0, len(wanted), 1000):
        rows = (SecurityEvidence._base_manager.filter(observed_at__gte=now - WINDOW, source_ip__in=wanted[start:start + 1000],
                                                      client_scope_id__isnull=False)
                .values('source_ip', 'client_scope_id')
                .annotate(count=Count('uid'), allowed=Count('uid', filter=Q(action='allowed'))))
        for row in rows.order_by():
            item = stats.setdefault(row['source_ip'], {'count': 0, 'clients': {}})
            item['count'] += row['count']
            item['clients'][row['client_scope_id']] = (row['count'], row['allowed'])
    return stats


def build(feed, candidates, stats, protected, now):
    """Entradas de un cliente, de más a menos relevante: le atacaron a él, a más clientes, más veces."""
    allow = parse_allowlist(feed.allowlist)
    entries = []
    for ip, info in candidates.items():
        if not (feed.include_lists and info['listed']) and not (feed.include_cti and info['cti']):
            continue
        item = stats.get(ip)
        address = ipaddress.ip_address(ip)
        if not item or not address.is_global or ip in protected or any(address in network for network in allow):
            continue
        here = item['clients'].get(feed.client_id, (0, 0))
        entries.append({'ip': ip, 'reasons': info['reasons'], 'clients': len(item['clients']), 'events': item['count'],
                        'here': here[0], 'here_allowed': here[1]})
    entries.sort(key=lambda e: (-e['here'], -e['clients'], -e['events'], e['ip']))
    return entries[:feed.max_entries]


def observation(entries, now):
    """Qué habría bloqueado la lista: detecciones del propio cliente desde esas IPs en 7 días."""
    hits = [e for e in entries if e['here']]
    return {'at': now.isoformat(), 'ips': len(hits), 'events': sum(e['here'] for e in hits),
            'allowed': sum(e['here_allowed'] for e in hits), 'protective': sum(1 for e in entries if not e['here'])}


def refresh_feeds(now=None):
    """Trabajo `blocklists`: recalcula la lista de cada cliente con la lista activada."""
    now = now or timezone.now()
    feeds = list(BlocklistFeed.objects.filter(enabled=True, client__active=True))
    if not feeds:
        return 0
    candidates = qualifying(now)
    stats = activity(candidates, now)
    protected = protected_addresses()
    for feed in feeds:
        try:
            entries = build(feed, candidates, stats, protected, now)
        except ValueError:
            continue  # Excepciones no válidas: se conserva la última lista buena y se avisa en su página.
        before = {e['ip'] for e in feed.entries}
        after = {e['ip'] for e in entries}
        BlocklistFeed.objects.filter(pk=feed.pk).update(entries=entries, generated_at=now,
                                                        observation=observation(entries, now))
        if before != after:
            audit('blocklist.generated', feed.client, {'count': len(after),
                                                       'status': f'+{len(after - before)} -{len(before - after)}'})
    return len(feeds)


def _hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def rotate_token(feed):
    token = secrets.token_urlsafe(32)
    feed.token_hash, feed.encrypted_token = _hash(token), encrypt(token)
    feed.save(update_fields=['token_hash', 'encrypted_token', 'updated_at'])
    return token


def feed_url(feed):
    """URL completa con el token, para el firewall. Solo se construye para quien gestiona conexiones."""
    from .invitations import origin
    if not feed.encrypted_token:
        return ''
    return origin() + reverse('blocklist_serve', args=[feed.client_id, decrypt(feed.encrypted_token)])


@never_cache
@require_GET
def serve(request, client_pk, token):
    """Descarga del firewall: una IP por línea. Vacía si la lista está desactivada o detenida."""
    feed = BlocklistFeed._base_manager.filter(client_id=client_pk).select_related('client').first()
    if not feed or not feed.token_hash or not hmac.compare_digest(feed.token_hash, _hash(token)):
        raise Http404
    active = feed.enabled and not feed.stopped and feed.client.active
    BlocklistFeed._base_manager.filter(pk=feed.pk).update(last_fetch_at=timezone.now())
    body = ''.join(entry['ip'] + '\n' for entry in feed.entries) if active else ''
    response = HttpResponse(body, content_type='text/plain; charset=utf-8')
    response['X-Content-Type-Options'] = 'nosniff'
    return response


def alias_name(plan):
    return f'SOC_CROWDSEC_{plan.pk}'


def plan_preview(device):
    """Vista previa de la plantilla: tabla de IPs descargada del SOC y regla de bloqueo de entrada en WAN."""
    return {'profile': TITLE, 'version': VERSION, 'networks': [], 'interface': 'wan',
            'alias': {'type': 'urltable', 'updatefreq': '0.04', 'description': 'Lista de bloqueo del SOC (CrowdSec)'},
            'rules': [{'enabled': '0', 'sequence': '1', 'action': 'block', 'quick': '1', 'interface': 'wan',
                       'direction': 'in', 'ipprotocol': 'inet46', 'protocol': 'any', 'source_net': 'Lista del SOC',
                       'destination_net': 'any', 'destination_port': '', 'log': '1'}],
            'checks': ['Revisar en «Listas de bloqueo» la observación: qué habría bloqueado y si incluye algún proveedor o socio.',
                       'Completar las excepciones del cliente (oficinas remotas, proveedores, servicios en la nube) antes de activar.',
                       'La regla bloquea conexiones entrantes en WAN desde las IPs de la lista; no afecta al tráfico saliente.',
                       'El firewall debe poder descargar la URL del SOC por HTTPS; la tabla se actualiza aproximadamente cada hora.',
                       'Freno de emergencia: detener la lista en el SOC vacía la tabla en la siguiente descarga; revertir la regla la retira.'],
            'zenarmor': [], 'suricata': []}


def _devices(client):
    return Device.objects.filter(site__client=client, active=True, vendor=Device.Vendor.OPNSENSE,
                                 management_method='api').select_related('site')


@login_required
@require_GET
def overview(request):
    if not request.user.has_perm('core.manage_operations'):
        return HttpResponseForbidden('Permiso de operaciones requerido.')
    feeds = {f.client_id: f for f in BlocklistFeed.objects.all()}
    rows = [{'client': c, 'feed': feeds.get(c.pk)} for c in Client.objects.filter(active=True).order_by('name')]
    return render(request, 'blocklists.html', {'rows': rows})


@login_required
@require_http_methods(['GET', 'POST'])
def detail(request, client_pk):
    from .security import mfa_fresh
    if not request.user.has_perm('core.manage_operations'):
        return HttpResponseForbidden('Permiso de operaciones requerido.')
    client = get_object_or_404(Client, pk=client_pk, active=True)
    feed, _ = BlocklistFeed.objects.get_or_create(client=client)
    error = ''
    if request.method == 'POST':
        action = request.POST.get('action', '')
        # Detener solo deja de bloquear: no exige repetir el MFA para no retrasar una emergencia.
        if action != 'stop' and not mfa_fresh(request):
            return redirect('mfa_challenge')
        if action == 'settings':
            try:
                parse_allowlist(request.POST.get('allowlist', ''))
                maximum = int(request.POST.get('max_entries', '2000'))
                if not 1 <= maximum <= 20000:
                    raise ValueError('El máximo de entradas debe estar entre 1 y 20000.')
            except ValueError as exc:
                error = str(exc)
            else:
                feed.allowlist = request.POST.get('allowlist', '').strip()[:20000]
                feed.max_entries = maximum
                feed.include_lists = request.POST.get('include_lists') == 'on'
                feed.include_cti = request.POST.get('include_cti') == 'on'
                feed.enabled = request.POST.get('enabled') == 'on'
                feed.save()
                if feed.enabled and not feed.token_hash:
                    rotate_token(feed)
                audit('blocklist.settings', client, {'status': 'enabled' if feed.enabled else 'disabled',
                                                     'count': feed.max_entries})
                refresh_feeds()
                messages.success(request, 'Configuración guardada y lista recalculada.')
                return redirect('blocklist_detail', client_pk=client.pk)
        elif action in ('stop', 'resume'):
            with transaction.atomic():
                stopped = action == 'stop'
                BlocklistFeed.objects.filter(pk=feed.pk).update(stopped=stopped, stopped_at=timezone.now() if stopped else None)
            audit('blocklist.' + action, client)
            messages.success(request, 'Lista detenida: los firewalls recibirán una lista vacía en su próxima descarga.'
                             if action == 'stop' else 'Lista reanudada.')
            return redirect('blocklist_detail', client_pk=client.pk)
        elif action == 'rotate':
            if not request.user.has_perm('core.manage_connections'):
                return HttpResponseForbidden('Permiso de conexiones requerido.')
            rotate_token(feed)
            audit('blocklist.token_rotated', client)
            messages.success(request, 'Token nuevo. Actualiza la URL en los firewalls: la anterior deja de funcionar.')
            return redirect('blocklist_detail', client_pk=client.pk)
        elif action == 'plan':
            if not request.user.has_perm('core.manage_connections'):
                return HttpResponseForbidden('Permiso de conexiones requerido.')
            device = get_object_or_404(_devices(client), pk=request.POST.get('device', '0') or 0)
            if not feed.enabled or not feed.token_hash:
                messages.error(request, 'Activa primero la lista y revisa la observación.')
                return redirect('blocklist_detail', client_pk=client.pk)
            plan = ChangePlan.objects.create(device=device, template=TEMPLATE, template_version=VERSION, title=TITLE,
                                             parameters={'client': client.pk}, preview=plan_preview(device),
                                             requested_by=request.user)
            audit('change.draft', plan, {'template': TEMPLATE})
            return redirect('change_detail', pk=plan.pk)
        else:
            raise Http404
    feed.refresh_from_db()
    show_url = request.user.has_perm('core.manage_connections')
    try:
        parse_allowlist(feed.allowlist)
        allowlist_error = ''
    except ValueError as exc:
        allowlist_error = str(exc)
    plans = ChangePlan.objects.filter(template=TEMPLATE, device__site__client=client).select_related('device').order_by('-pk')[:10]
    return render(request, 'blocklist_detail.html', {
        'client': client, 'feed': feed, 'entries': feed.entries[:300], 'count': len(feed.entries),
        'url': feed_url(feed) if show_url and feed.enabled else '', 'error': error or allowlist_error,
        'devices': _devices(client), 'plans': plans, 'observation': feed.observation})

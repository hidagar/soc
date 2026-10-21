"""Catálogo de listas de CrowdSec y suscripción guiada por los ataques reales (Service API).

El SOC conoce a quién atacan y desde dónde. Con esa información mide cada lista del catálogo:
cuántos atacantes de los clientes (30 días) contiene, cuántos aún no cubre ninguna lista
suscrita y cuántos tuvieron tráfico permitido. Recomienda las que aportan y, si se activa el
modo automático, suscribe el motor a las mejores dentro de un máximo.

Solo el trabajo protegido `crowdsec_lists` usa la clave (`SOC_PORTAL_CROWDSEC_SERVICE_KEY`);
la web lee el catálogo y deja peticiones de alta o baja en cola. Las descargas están acotadas
en número diario y tamaño. Ninguna IP de clientes sale del SOC: la comparación es local.
"""
import ipaddress
import json
import os
from collections import defaultdict
from datetime import timedelta
from urllib import error as urlerror
from urllib import parse as urlparse
from urllib import request as urlrequest

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import Count, Q
from django.http import Http404, HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_GET, require_http_methods

from .models import CrowdsecBlocklist, IpReputation, SecurityEvidence, WorkerState
from .reputation import eligible, protected_addresses
from .security import audit

API = 'https://admin.api.crowdsec.net/v1'
STATE = 'crowdsec-catalog'
WINDOW = timedelta(days=30)
CATALOG_EVERY = timedelta(hours=24)
REEVALUATE = timedelta(days=7)
MAX_JSON = 4 * 1024 * 1024
MAX_LIST = 64 * 1024 * 1024
MAX_FALSE_POSITIVE = 0.01
MIN_NEW_HITS = 3
TIERS = ('free', 'premium')


class ServiceError(Exception):
    pass


class _NoRedirect(urlrequest.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def service_key():
    return os.environ.get('SOC_PORTAL_CROWDSEC_SERVICE_KEY', '').strip()


def _int_env(name, default, low, high):
    try:
        return max(low, min(high, int(os.environ.get(name, str(default)))))
    except ValueError:
        return default


def daily_downloads():
    return _int_env('SOC_PORTAL_CROWDSEC_LIST_DOWNLOADS', 10, 0, 100)


def auto_subscribe_limit():
    """Máximo de listas que el SOC suscribe por su cuenta; 0 = solo recomendar."""
    return _int_env('SOC_PORTAL_CROWDSEC_AUTO_SUBSCRIBE', 0, 0, 50)


def call(key, path, method='GET', body=None, raw=False):
    """Petición a la Service API. Errores sin contenido del proveedor ni la clave."""
    data = json.dumps(body).encode() if body is not None else None
    headers = {'x-api-key': key, 'User-Agent': 'ib-red-SOC/1', 'Accept': 'text/plain' if raw else 'application/json'}
    if data is not None:
        headers['Content-Type'] = 'application/json'
    req = urlrequest.Request(API + path, data=data, headers=headers, method=method)
    try:
        response = urlrequest.build_opener(_NoRedirect()).open(req, timeout=60 if raw else 20)
    except urlerror.HTTPError as exc:
        raise ServiceError({401: 'clave rechazada', 403: 'clave rechazada o sin acceso con este plan', 404: 'no encontrada',
                            429: 'límite de la API'}.get(exc.code, f'HTTP {exc.code}')) from None
    except (urlerror.URLError, TimeoutError, ConnectionError):
        raise ServiceError('sin conexión con la API de CrowdSec') from None
    if raw:
        return response
    with response:
        payload = response.read(MAX_JSON + 1)
    if len(payload) > MAX_JSON:
        raise ServiceError('respuesta demasiado grande')
    return json.loads(payload) if payload.strip() else {}


def engine_id(key, details):
    """Motor a suscribir: el configurado o, si la organización tiene uno solo, ese."""
    configured = os.environ.get('SOC_PORTAL_CROWDSEC_ENGINE_ID', '').strip()
    if configured:
        return configured
    if details.get('engine_id'):
        return details['engine_id']
    engines = call(key, '/engines?size=100').get('items') or []
    if len(engines) != 1:
        raise ServiceError(f'la organización tiene {len(engines)} motores; fija SOC_PORTAL_CROWDSEC_ENGINE_ID')
    details['engine_id'] = str(engines[0].get('id', ''))[:80]
    return details['engine_id']


def _text(value, size):
    return value[:size] if isinstance(value, str) else ''


def refresh_catalog(key, details, now):
    """Catálogo visible para la organización y qué listas tiene ya el motor."""
    engine = engine_id(key, details)
    subscribed = set()
    for item in call(key, '/engines?size=100').get('items') or []:
        if str(item.get('id')) == engine:
            subscribed = {str(b.get('id')) for b in item.get('blocklists') or [] if isinstance(b, dict)}
    page, seen = 1, set()
    while page <= 50:
        query = urlparse.urlencode({'page': page, 'size': 100, 'include_filter': 'all'})
        data = call(key, '/blocklists?' + query)
        for item in data.get('items') or []:
            if not isinstance(item, dict) or not item.get('id'):
                continue
            stats = item.get('stats') if isinstance(item.get('stats'), dict) else {}
            content = stats.get('content_stats') if isinstance(stats.get('content_stats'), dict) else {}
            blocklist_id = str(item['id'])[:40]
            seen.add(blocklist_id)
            values = {'name': _text(item.get('name'), 200), 'label': _text(item.get('label'), 200),
                      'description': _text(item.get('description'), 500), 'pricing_tier': _text(item.get('pricing_tier'), 16),
                      'source': _text(item.get('source'), 16),
                      'categories': [_text(c, 40) for c in (item.get('categories') or [])[:10] if isinstance(c, str)],
                      'size': max(0, int(stats.get('count') or 0)),
                      'false_positives': max(0, int(content.get('total_false_positive') or 0)),
                      'top_scenarios': [_text(s.get('label') or s.get('name'), 80) for s in (content.get('most_present_scenarios') or [])[:5]
                                        if isinstance(s, dict)],
                      'subscribed': blocklist_id in subscribed, 'seen_at': now}
            row, created = CrowdsecBlocklist.objects.get_or_create(blocklist_id=blocklist_id, defaults=values)
            if not created:
                if values['subscribed'] and not row.subscribed:
                    values['subscribed_by'] = row.subscribed_by or 'console'
                for field, value in values.items():
                    setattr(row, field, value)
                row.save()
            elif values['subscribed']:
                CrowdsecBlocklist.objects.filter(pk=row.pk).update(subscribed_by='console')
        if page >= int(data.get('pages') or 1):
            break
        page += 1
    details['catalog_at'] = now.isoformat()
    details['catalog_count'] = len(seen)


def attackers(now):
    """Atacantes reales de los clientes (30 días): IP → clientes y si hubo tráfico permitido."""
    protected = protected_addresses()
    result = defaultdict(lambda: {'clients': set(), 'allowed': False})
    rows = (SecurityEvidence._base_manager.filter(observed_at__gte=now - WINDOW, source_ip__isnull=False,
                                                  client_scope_id__isnull=False).exclude(destination_ip=None)
            .values('source_ip', 'destination_ip', 'client_scope_id')
            .annotate(allowed=Count('uid', filter=Q(action='allowed'))))
    for row in rows.order_by().iterator(chunk_size=2000):
        if eligible(row['source_ip'], row['destination_ip'], protected):
            item = result[row['source_ip']]
            item['clients'].add(row['client_scope_id'])
            item['allowed'] = item['allowed'] or row['allowed'] > 0
    return dict(result)


def matches(lines, targets):
    """IPs de `targets` contenidas en la lista (IPs sueltas o redes), leyendo línea a línea."""
    exact, networks = set(), []
    for line in lines:
        value = line.strip().split('#', 1)[0].strip()
        if not value:
            continue
        try:
            if '/' in value:
                network = ipaddress.ip_network(value, strict=False)
                if network.num_addresses == 1:
                    exact.add(str(network.network_address))
                else:
                    networks.append(network)
            else:
                exact.add(str(ipaddress.ip_address(value)))
        except ValueError:
            continue
    found = {ip for ip in targets if ip in exact}
    if networks:
        for ip in targets.keys() - found:
            address = ipaddress.ip_address(ip)
            if any(address in network for network in networks if network.version == address.version):
                found.add(ip)
    return found


def _download(key, blocklist_id):
    response = call(key, f'/blocklists/{blocklist_id}/download', raw=True)
    total = 0
    with response:
        for raw in response:
            total += len(raw)
            if total > MAX_LIST:
                raise ServiceError('lista demasiado grande para evaluarla')
            yield raw.decode('utf-8', 'replace')


def evaluate(key, row, targets, covered, now):
    try:
        found = matches(_download(key, row.blocklist_id), targets)
    except ServiceError as exc:
        row.access = 'denied' if 'acceso' in str(exc) else 'error'
        row.error, row.evaluated_at = str(exc)[:240], now
        row.save()
        return
    new = found - covered
    row.hits, row.new_hits = len(found), len(new)
    row.allowed_hits = sum(1 for ip in found if targets[ip]['allowed'])
    row.clients = len(set().union(*(targets[ip]['clients'] for ip in found))) if found else 0
    ratio = row.false_positives / row.size if row.size else 0
    # Aporte nuevo, sobre todo si dejó pasar tráfico; penaliza listas con falsos positivos.
    row.score = 0 if ratio > MAX_FALSE_POSITIVE else round(row.new_hits + 4 * row.allowed_hits + 0.5 * row.clients, 2)
    row.access, row.error, row.evaluated_at = 'ok', '', now
    row.save()


def recommended(queryset=None):
    """Listas recomendables: con aporte nuevo real, plan accesible y pocos falsos positivos."""
    rows = (CrowdsecBlocklist.objects.all() if queryset is None else queryset).filter(
        access='ok', pricing_tier__in=TIERS, subscribed=False, new_hits__gte=MIN_NEW_HITS, score__gt=0)
    return rows.order_by('-score', 'name')


def _subscribe(key, row, engine, action):
    if action == 'subscribe':
        result = call(key, f'/blocklists/{row.blocklist_id}/subscribers', 'POST',
                      {'entity_type': 'engine', 'ids': [engine], 'remediation': 'ban'})
        if engine not in [str(i) for i in result.get('updated') or []]:
            raise ServiceError('CrowdSec no confirmó la suscripción')
    else:
        call(key, f'/blocklists/{row.blocklist_id}/subscribers/{engine}', 'DELETE')


def process_actions(key, details, now):
    engine = engine_id(key, details)
    for row in CrowdsecBlocklist.objects.exclude(pending_action='').select_related('requested_by'):
        action = row.pending_action
        try:
            _subscribe(key, row, engine, action)
        except ServiceError as exc:
            CrowdsecBlocklist.objects.filter(pk=row.pk).update(pending_action='', error=f'{action}: {exc}'[:240])
            continue
        subscribed = action == 'subscribe'
        CrowdsecBlocklist.objects.filter(pk=row.pk).update(
            pending_action='', subscribed=subscribed, subscribed_by='soc-manual' if subscribed else '', error='')
        audit('crowdsec.' + action, row, {'status': row.name[:60]}, user=row.requested_by)


def auto_subscribe(key, details, now):
    limit = auto_subscribe_limit()
    current = CrowdsecBlocklist.objects.filter(subscribed=True, subscribed_by='soc-auto').count()
    if not limit or current >= limit:
        return 0
    engine = engine_id(key, details)
    done = 0
    for row in recommended()[:limit - current]:
        try:
            _subscribe(key, row, engine, 'subscribe')
        except ServiceError as exc:
            CrowdsecBlocklist.objects.filter(pk=row.pk).update(error=f'alta automática: {exc}'[:240])
            continue
        CrowdsecBlocklist.objects.filter(pk=row.pk).update(subscribed=True, subscribed_by='soc-auto', error='')
        audit('crowdsec.subscribe', row, {'status': row.name[:60], 'reason': 'automática'})
        done += 1
    return done


def refresh(now=None):
    """Trabajo `crowdsec_lists`: cola de altas y bajas, catálogo diario, evaluación acotada y modo automático."""
    now = now or timezone.now()
    state, _ = WorkerState.objects.get_or_create(name=STATE)
    key = service_key()
    if not key:
        state.error, state.details = '', {**state.details, 'enabled': False}
        state.save(update_fields=['error', 'details'])
        return 0
    details = dict(state.details, enabled=True)
    today = now.date().isoformat()
    if details.get('day') != today:
        details.update(day=today, downloads=0)
    done = 0
    try:
        process_actions(key, details, now)
        if details.get('catalog_at', '') <= (now - CATALOG_EVERY).isoformat():
            refresh_catalog(key, details, now)
        budget = daily_downloads() - details.get('downloads', 0)
        if budget > 0:
            stale = (CrowdsecBlocklist.objects.filter(pricing_tier__in=TIERS, seen_at__gte=now - 2 * CATALOG_EVERY)
                     .filter(Q(evaluated_at__isnull=True) | Q(evaluated_at__lt=now - REEVALUATE))
                     .order_by('evaluated_at', '-size')[:min(budget, 3)])
            if stale:
                targets = attackers(now)
                covered = set(IpReputation.objects.filter(listed=True).values_list('ip', flat=True))
                for row in stale:
                    details['downloads'] = details.get('downloads', 0) + 1
                    evaluate(key, row, targets, covered, now)
                    done += 1
        done += auto_subscribe(key, details, now)
        state.error = ''
    except ServiceError as exc:
        state.error = f'Service API de CrowdSec: {exc}.'[:240]
    state.details, state.last_run_at = details, now
    if not state.error:
        state.last_success_at = now
    state.save()
    return done


@login_required
@require_GET
def overview(request):
    if not request.user.has_perm('core.manage_operations'):
        return HttpResponseForbidden('Permiso de operaciones requerido.')
    state = WorkerState.objects.filter(name=STATE).first()
    rows = CrowdsecBlocklist.objects.all()
    best = list(recommended()[:15])
    return render(request, 'crowdsec_lists.html', {
        'state': state, 'details': state.details if state else {}, 'auto': auto_subscribe_limit(),
        'recommended': best, 'subscribed': rows.filter(subscribed=True).order_by('-score', 'name'),
        'others': rows.filter(subscribed=False, access='ok', pricing_tier__in=TIERS).exclude(
            pk__in=[r.pk for r in best]).order_by('-score', 'name')[:100],
        'pending': rows.filter(evaluated_at__isnull=True, pricing_tier__in=TIERS).count(),
        'blocked': rows.exclude(pricing_tier__in=TIERS).count() + rows.filter(access='denied').count()})


@login_required
@require_http_methods(['POST'])
def action(request, pk):
    from .security import mfa_fresh
    if not request.user.has_perm('core.manage_connections'):
        return HttpResponseForbidden('Permiso de gestión de conexiones requerido.')
    if not mfa_fresh(request):
        return redirect('mfa_challenge')
    row = get_object_or_404(CrowdsecBlocklist, pk=pk)
    wanted = request.POST.get('action')
    if wanted not in ('subscribe', 'unsubscribe', 'cancel'):
        raise Http404
    if wanted == 'cancel':
        CrowdsecBlocklist.objects.filter(pk=row.pk).update(pending_action='', requested_by=None)
    elif (wanted == 'subscribe') == row.subscribed or row.pricing_tier not in TIERS:
        messages.error(request, 'La lista ya está en ese estado o no está incluida en el plan.')
        return redirect('crowdsec_lists')
    else:
        CrowdsecBlocklist.objects.filter(pk=row.pk).update(pending_action=wanted, requested_by=request.user, error='')
        audit('crowdsec.' + wanted + '.requested', row, {'status': row.name[:60]})
        messages.success(request, 'Petición en cola: se aplicará en los próximos minutos y quedará en la auditoría.')
    return redirect('crowdsec_lists')

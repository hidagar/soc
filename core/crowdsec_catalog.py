"""Catálogo de listas de CrowdSec y suscripción guiada por los ataques reales (Service API).

El SOC conoce a quién atacan y desde dónde. Con esa información mide cada lista del catálogo
sin descargarla (CrowdSec no permite descargar listas no suscritas, comprobado en la VM):
- listas suscritas: exacto, con las decisiones del motor local, que llevan el nombre de la lista;
- resto: estimado con la API CTI, que indica en qué listas está cada IP consultada.
Cuenta atacantes de los clientes (30 días), cuántos aporta cada lista y cuántos tuvieron tráfico
permitido. Recomienda las que aportan y, si se activa el modo automático, suscribe las mejores.

Solo el trabajo protegido `crowdsec_lists` usa la clave (`SOC_PORTAL_CROWDSEC_SERVICE_KEY`);
la web lee el catálogo y deja peticiones de alta o baja en cola. Ninguna IP de clientes se
envía por esta vía: la comparación es local con datos ya obtenidos.
"""
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
EVALUATE_EVERY = timedelta(hours=1)
MAX_JSON = 4 * 1024 * 1024
MAX_FALSE_POSITIVE = 0.01
MIN_NEW_HITS = 3
TIERS = ('free', 'premium')


class ServiceError(Exception):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


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


def auto_subscribe_limit():
    """Máximo de listas que el SOC suscribe por su cuenta; 0 = solo recomendar."""
    return _int_env('SOC_PORTAL_CROWDSEC_AUTO_SUBSCRIBE', 0, 0, 50)


def call(key, path, method='GET', body=None):
    """Petición a la Service API. Errores sin contenido del proveedor ni la clave."""
    data = json.dumps(body).encode() if body is not None else None
    headers = {'x-api-key': key, 'User-Agent': 'ib-red-SOC/1', 'Accept': 'application/json'}
    if data is not None:
        headers['Content-Type'] = 'application/json'
    req = urlrequest.Request(API + path, data=data, headers=headers, method=method)
    try:
        response = urlrequest.build_opener(_NoRedirect()).open(req, timeout=20)
    except urlerror.HTTPError as exc:
        raise ServiceError({401: 'clave rechazada', 403: 'clave rechazada o sin acceso con este plan', 404: 'no encontrada',
                            429: 'límite de la API'}.get(exc.code, f'HTTP {exc.code}'), exc.code) from None
    except (urlerror.URLError, TimeoutError, ConnectionError):
        raise ServiceError('sin conexión con la API de CrowdSec') from None
    with response:
        payload = response.read(MAX_JSON + 1)
    if len(payload) > MAX_JSON:
        raise ServiceError('respuesta demasiado grande')
    return json.loads(payload) if payload.strip() else {}


def engine_id(key, details):
    """Motor a suscribir: el configurado o, si la organización tiene uno solo, ese.

    Devuelve '' si la clave no tiene permiso para ver motores: entonces se suscribe la
    organización entera, equivalente con un único motor (los nuevos motores también recibirían la lista).
    """
    configured = os.environ.get('SOC_PORTAL_CROWDSEC_ENGINE_ID', '').strip()
    if configured:
        return configured
    if 'engine_id' in details:
        return details['engine_id']
    try:
        engines = call(key, '/engines?size=100').get('items') or []
    except ServiceError as exc:
        if 'acceso' not in str(exc):
            raise
        details['engine_id'] = ''
        return ''
    if len(engines) != 1:
        raise ServiceError(f'la organización tiene {len(engines)} motores; fija SOC_PORTAL_CROWDSEC_ENGINE_ID')
    details['engine_id'] = str(engines[0].get('id', ''))[:80]
    return details['engine_id']


def subscribed_lists(key):
    """Listas con alguna suscripción de la organización; no necesita permiso sobre motores."""
    found, page = set(), 1
    while page <= 50:
        data = call(key, '/blocklists?' + urlparse.urlencode({'page': page, 'size': 100, 'include_filter': 'all',
                                                              'subscribed_only': 'true'}))
        found |= {str(item.get('id')) for item in data.get('items') or [] if isinstance(item, dict)}
        if page >= int(data.get('pages') or 1):
            return found
        page += 1
    return found


def _text(value, size):
    return value[:size] if isinstance(value, str) else ''


def refresh_catalog(key, details, now):
    """Catálogo visible para la organización y qué listas tiene ya el motor."""
    engine_id(key, details)
    subscribed = subscribed_lists(key)
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
                    values['subscribed_by'] = 'console' if row.subscribed_by in ('', 'rejected') else row.subscribed_by
                elif row.subscribed and not values['subscribed']:
                    values['subscribed_by'] = 'rejected'  # baja en la consola: decisión que el modo automático respeta
                for field, value in values.items():
                    setattr(row, field, value)
                # Solo los campos del catálogo: no pisa una petición en cola ni un error recientes.
                row.save(update_fields=list(values))
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


def membership(targets):
    """Por atacante: listas del catálogo según el motor (exacto) y según la CTI, y si ya está cubierto."""
    engine, cti = defaultdict(set), defaultdict(set)
    covered, community, sampled, per_ip = set(), set(), set(), defaultdict(set)
    wanted = sorted(targets)
    for start in range(0, len(wanted), 1000):
        rows = IpReputation.objects.filter(ip__in=wanted[start:start + 1000]).only(
            'ip', 'listed', 'list_origins', 'list_scenarios', 'cti_found', 'cti_lists')
        for row in rows:
            if row.listed:
                covered.add(row.ip)
                if 'Lista comunitaria' in (row.list_origins or []):
                    community.add(row.ip)
                for name in row.list_scenarios or []:
                    engine[name].add(row.ip)
                    per_ip[row.ip].add(name)
            if row.cti_found is not None:
                sampled.add(row.ip)
            for name in (row.cti_lists or []) if row.cti_found else []:
                cti[name].add(row.ip)
    return {'engine': engine, 'cti': cti, 'covered': covered, 'community': community, 'sampled': sampled,
            'per_ip': per_ip}


def evaluate_all(targets, now):
    """Mide todas las listas del catálogo con los atacantes reales; sin llamadas externas."""
    data = membership(targets)
    for row in CrowdsecBlocklist.objects.all():
        if row.subscribed and data['engine'].get(row.name):
            found = data['engine'][row.name]
            # Aporte de una lista suscrita: atacantes que solo cubre ella (ni la comunitaria ni otra).
            new = {ip for ip in found if ip not in data['community'] and data['per_ip'][ip] == {row.name}}
            row.method, row.sample = 'motor', len(targets)
        else:
            found = data['cti'].get(row.name, set())
            new = found - data['covered']
            row.method, row.sample = 'cti', len(data['sampled'])
        row.hits, row.new_hits = len(found), len(new)
        row.allowed_hits = sum(1 for ip in found if targets[ip]['allowed'])
        row.clients = len(set().union(*(targets[ip]['clients'] for ip in found))) if found else 0
        ratio = row.false_positives / row.size if row.size else 0
        # Aporte nuevo, sobre todo si dejó pasar tráfico; penaliza listas con falsos positivos.
        row.score = 0 if ratio > MAX_FALSE_POSITIVE else round(row.new_hits + 4 * row.allowed_hits + 0.5 * row.clients, 2)
        row.evaluated_at = now
        if row.access == 'pending':
            row.access = 'ok'  # medida; un 'denied' del alta automática se conserva para no reintentarlo
        row.save(update_fields=['method', 'sample', 'hits', 'new_hits', 'allowed_hits', 'clients', 'score', 'evaluated_at',
                                'access'])
    return len(data['sampled'])


def recommended(queryset=None):
    """Listas recomendables: con aporte nuevo real, plan accesible y pocos falsos positivos."""
    rows = (CrowdsecBlocklist.objects.all() if queryset is None else queryset).filter(
        access='ok', pricing_tier__in=TIERS, subscribed=False, new_hits__gte=MIN_NEW_HITS, score__gt=0
    ).exclude(subscribed_by='rejected')  # descartada por el SOC: no se vuelve a proponer ni a suscribir sola
    return rows.order_by('-score', 'name')


def _subscribe(key, row, engine, action):
    """Alta del motor (o de la organización si no hay motor identificado) o baja de sus suscripciones."""
    if action == 'subscribe':
        body = ({'entity_type': 'engine', 'ids': [engine], 'remediation': 'ban'} if engine
                else {'entity_type': 'org', 'remediation': 'ban'})
        result = call(key, f'/blocklists/{row.blocklist_id}/subscribers', 'POST', body)
        if result.get('errors') or (engine and engine not in [str(i) for i in result.get('updated') or []]):
            raise ServiceError('CrowdSec no confirmó la suscripción')
        return
    entities = call(key, f'/blocklists/{row.blocklist_id}/subscribers?size=100').get('items') or []
    targets = [str(e.get('id')) for e in entities if isinstance(e, dict) and e.get('id')
               and (e.get('entity_type') == 'org' or str(e.get('id')) == engine or not engine)]
    if not targets:
        raise ServiceError('no hay suscripción de la organización que retirar')
    for target in targets:
        call(key, f'/blocklists/{row.blocklist_id}/subscribers/{urlparse.quote(target, safe="")}', 'DELETE')


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
            pending_action='', subscribed=subscribed, subscribed_by='soc-manual' if subscribed else 'rejected',
            access='ok' if subscribed else row.access, error='')
        audit('crowdsec.' + action, row, {'status': row.name[:60]}, user=row.requested_by)


def auto_subscribe(key, details, now):
    limit = auto_subscribe_limit()
    current = CrowdsecBlocklist.objects.filter(subscribed=True, subscribed_by='soc-auto').count()
    if not limit or current >= limit:
        return 0
    engine = engine_id(key, details)
    done = 0
    for row in list(recommended()):
        if done >= limit - current:
            break
        try:
            _subscribe(key, row, engine, 'subscribe')
        except ServiceError as exc:
            # Sin acceso con el plan: no se reintenta cada 5 minutos y se pasa a la siguiente recomendada.
            CrowdsecBlocklist.objects.filter(pk=row.pk).update(
                access='denied' if exc.status == 403 else row.access, error=f'alta automática: {exc}'[:240])
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
    done = 0
    try:
        process_actions(key, details, now)
        if details.get('catalog_at', '') <= (now - CATALOG_EVERY).isoformat():
            refresh_catalog(key, details, now)
        if details.get('evaluated_at', '') <= (now - EVALUATE_EVERY).isoformat():
            targets = attackers(now)
            details.update(evaluated_at=now.isoformat(), attackers=len(targets), sampled=evaluate_all(targets, now))
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
    from django.utils.dateparse import parse_datetime
    state = WorkerState.objects.filter(name=STATE).first()
    details = state.details if state else {}
    rows = CrowdsecBlocklist.objects.all()
    best = list(recommended()[:15])
    return render(request, 'crowdsec_lists.html', {
        'state': state, 'details': details, 'auto': auto_subscribe_limit(),
        'catalog_at': parse_datetime(details.get('catalog_at') or ''),
        'evaluated_at': parse_datetime(details.get('evaluated_at') or ''),
        'recommended': best, 'subscribed': rows.filter(subscribed=True).order_by('-score', 'name'),
        'others': rows.filter(subscribed=False, pricing_tier__in=TIERS).exclude(
            pk__in=[r.pk for r in best]).order_by('-score', 'name')[:100],
        'blocked': rows.exclude(pricing_tier__in=TIERS).count()})


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

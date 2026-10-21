"""Página «Reputación CrowdSec»: estado del motor y orígenes en lista dentro del ámbito del usuario.

Solo lee la caché y el estado que deja el trabajo protegido `reputation`; nunca consulta
al motor ni a terceros desde la web. Las detecciones se filtran con el ámbito de cliente
(`evidence_queryset`), así que un operador limitado solo ve las IPs de sus clientes.
"""
from collections import Counter, defaultdict

from django.contrib.auth.decorators import login_required
from django.db.models import Count, Max, Q
from django.shortcuts import render
from django.urls import reverse
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET

from .investigation import evidence_queryset, ip_url, selection
from .models import Client, WorkerState
from .reputation import MODES, ORIGINS, daily_limit, lookup_many, monthly_limit

ROWS = 200


def engine_status():
    state = WorkerState.objects.filter(name='crowdsec-quota').first()
    job = WorkerState.objects.filter(name='job:reputation').first()
    details = state.details if state else {}
    lists = details.get('lists') or {}
    origins = [{'label': ORIGINS[name], 'count': data.get('count'), 'error': data.get('error', False),
                'top': data.get('top', [])[:5]}
               for name, data in (lists.get('origins') or {}).items() if name in ORIGINS and isinstance(data, dict)]
    return {'mode': MODES.get(details.get('mode', ''), MODES['']), 'enabled': details.get('enabled', False),
            'error': (state.error if state else '') or (job.error if job else ''),
            'last_run': job.last_run_at if job else None, 'last_success': job.last_success_at if job else None,
            'paused_until': parse_datetime(details.get('paused_until') or ''),
            'lists_paused_until': parse_datetime(details.get('lists_paused_until') or ''),
            'lists_at': parse_datetime(lists.get('at') or ''), 'origins': origins,
            'cti': 'cti' in details.get('mode', ''), 'cti_today': details.get('used', 0), 'cti_daily': daily_limit(),
            'cti_month': details.get('month_used', 0), 'cti_monthly': monthly_limit()}


@login_required
@never_cache
@require_GET
def overview(request):
    client, days, _, _ = selection(request)
    groups = (evidence_queryset(client, days).filter(source_ip__isnull=False)
              .values('source_ip', 'client_scope_id')
              .annotate(count=Count('uid'), allowed=Count('uid', filter=Q(action='allowed')), last=Max('observed_at')))
    sources = defaultdict(lambda: {'count': 0, 'allowed': 0, 'clients': set(), 'last': None})
    for row in groups.order_by().iterator(chunk_size=1000):
        item = sources[row['source_ip']]
        item['count'] += row['count']
        item['allowed'] += row['allowed']
        item['clients'].add(row['client_scope_id'])
        item['last'] = max(filter(None, (item['last'], row['last'])))
    reputations = lookup_many(sources)
    names = dict(Client.objects.filter(pk__in={c for s in sources.values() for c in s['clients']}).values_list('pk', 'name'))
    listed, by_reason, by_client = [], Counter(), Counter()
    for ip, item in sources.items():
        reputation = reputations.get(ip)
        if not reputation or not reputation.flagged:
            continue
        clients = sorted(names.get(pk, '—') for pk in item['clients'])
        by_reason.update(reputation.list_scenarios or reputation.behaviors or ['Sin motivo informado'])
        by_client.update(clients)
        listed.append({'ip': ip, 'reputation': reputation, 'clients': clients, 'count': item['count'],
                       'allowed': item['allowed'], 'last': item['last'],
                       'url': ip_url(ip, client.pk if client else None, days)})
    listed.sort(key=lambda r: (-r['allowed'], -r['count'], r['ip']))
    metrics = {'sources': len(sources), 'checked': len(reputations), 'listed': len(listed),
               'listed_allowed': sum(1 for r in listed if r['allowed']),
               'cti': sum(1 for r in reputations.values() if r.cti_found is not None),
               'noise': sum(1 for r in listed if r['reputation'].noise)}
    allowed_url = reverse('intelligence') + '?reputacion=permitida' + (f'&client={client.pk}' if client else '')
    return render(request, 'crowdsec.html', {
        'status': engine_status(), 'metrics': metrics, 'rows': listed[:ROWS], 'limited': len(listed) > ROWS,
        'by_reason': by_reason.most_common(10), 'by_client': by_client.most_common(10), 'selected': client,
        'clients': Client.objects.all(), 'days': days, 'allowed_url': allowed_url,
        'now': timezone.now()})

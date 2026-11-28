"""Vulnerabilidades de los equipos de los clientes, con la detección de vulnerabilidades de Wazuh.

Wazuh (4.8 o posterior) cruza el inventario de software que envía cada agente con su base de CVE y guarda el
resultado en el índice `wazuh-states-vulnerabilities-*`: una fila por equipo, programa y CVE. El SOC no instala ni
cambia nada en los equipos: lee ese índice con su usuario de solo lectura.

Trabajo `endpoint_vulnerabilities` (cada hora):
- solo equipos asignados a un cliente (los sin asignar no se atribuyen a nadie);
- lectura paginada y comprobada (`indexer_results.complete`). Si no termina (fallo, respuesta incompleta o más
  páginas de las previstas), se guarda lo leído pero no se marca nada como resuelto (invariante 5);
- con una lectura completa, lo que ya no aparece queda resuelto (programa actualizado o desinstalado).

Al cliente solo llega una proyección explícita: equipo, CVE, gravedad, puntuación, programa y versión, fecha de
publicación y el enlace público de NVD. Nunca las rutas, el texto del proveedor ni datos de otros clientes.
Una vulnerabilidad conocida no prueba que se haya explotado (invariante 4).
"""
import json
import os
import re
import urllib.error
import urllib.request
from datetime import timedelta

from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.db.models import Count, Q
from django.http import HttpResponseForbidden
from django.shortcuts import render
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.views.decorators.http import require_GET

from .models import Client, EndpointAgent, EndpointVulnerability, OperationalIssue, WorkerState

STATE = 'endpoint-vulnerabilities'
ISSUE = 'platform:endpoint-vulnerabilities'
INDEX = os.environ.get('SOC_VULNERABILITY_INDEX', 'wazuh-states-vulnerabilities-*')
PAGE = 1000
MAX_PAGES = 100
CVE = re.compile(r'^(CVE|GHSA|RHSA|USN|DSA|ALAS|OSV)-[A-Za-z0-9.:_-]{3,30}$')
SEVERITY = {'critical': 'critical', 'high': 'high', 'medium': 'medium', 'moderate': 'medium', 'low': 'low'}
ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'none': 4}
NO_PERMISSION = ('El usuario de lectura del indexador no puede leer las vulnerabilidades de los equipos: ejecutar '
                 '«sudo deploy/wazuh/permitir_vulnerabilidades.sh --aplicar» en la VM.')


class Incomplete(Exception):
    pass


def _search(body, authorization):
    from .indexer_tls import context as tls_context
    url = f'https://127.0.0.1:9200/{INDEX}/_search'
    req = urllib.request.Request(url, json.dumps(body).encode(), {'Authorization': authorization,
                                                                  'Content-Type': 'application/json'})
    context = tls_context(cafile=os.environ.get('SOC_INDEXER_CA', '/etc/wazuh-indexer/certs/root-ca.pem'))
    with urllib.request.urlopen(req, context=context, timeout=30) as response:
        return json.load(response)


def _text(value, size):
    return ''.join(c for c in str(value) if ord(c) >= 32)[:size] if isinstance(value, (str, int, float)) else ''


def parse(source):
    """Fila del índice → campos del modelo, o None si no tiene la forma esperada."""
    agent = source.get('agent') if isinstance(source.get('agent'), dict) else {}
    package = source.get('package') if isinstance(source.get('package'), dict) else {}
    vuln = source.get('vulnerability') if isinstance(source.get('vulnerability'), dict) else {}
    cve = _text(vuln.get('id'), 40)
    name = _text(package.get('name'), 200)
    if not CVE.match(cve) or not name or not agent.get('id'):
        return None
    score = (vuln.get('score') or {}).get('base') if isinstance(vuln.get('score'), dict) else None
    try:
        score = round(float(score), 1) if score is not None and 0 <= float(score) <= 10 else None
    except (TypeError, ValueError):
        score = None

    def stamp(value):
        result = parse_datetime(_text(value, 40)) if value else None
        return result if result and not timezone.is_naive(result) else None
    return {'agent_id': _text(agent.get('id'), 16), 'cve': cve, 'package': name,
            'version': _text(package.get('version'), 120),
            'severity': SEVERITY.get(_text(vuln.get('severity'), 20).lower(), 'none'), 'score': score,
            'title': _text(vuln.get('description'), 300), 'published_at': stamp(vuln.get('published_at')),
            'detected_at': stamp(vuln.get('detected_at'))}


def read(agent_ids, authorization, pages=None):
    """Todas las filas de esos equipos. Incomplete si la lectura no termina dentro del límite."""
    from .indexer_results import complete, hits as checked_hits
    pages = pages or MAX_PAGES
    rows, after = {}, None
    sort = [{field: {'order': 'asc', 'unmapped_type': 'keyword'}}
            for field in ('agent.id', 'package.name', 'vulnerability.id', 'package.version')]
    for _ in range(pages):
        body = {'size': PAGE, 'track_total_hits': False, 'sort': sort,
                'query': {'bool': {'filter': [{'terms': {'agent.id': sorted(agent_ids)}}]}},
                '_source': ['agent.id', 'package.name', 'package.version', 'vulnerability.id', 'vulnerability.severity',
                            'vulnerability.score.base', 'vulnerability.description', 'vulnerability.published_at',
                            'vulnerability.detected_at']}
        if after:
            body['search_after'] = after
        result = complete(_search(body, authorization))
        hits = checked_hits(result)
        for hit in hits:
            row = parse(hit['_source'])
            if row:
                key = (row['agent_id'], row['cve'], row['package'])
                if key not in rows or (row['score'] or 0) > (rows[key]['score'] or 0):
                    rows[key] = row
        if len(hits) < PAGE:
            return rows, True
        after = hits[-1].get('sort')
        if not isinstance(after, list) or len(after) != 4:
            raise Incomplete('Sin identidad estable para seguir leyendo.')
    return rows, False  # más filas de las previstas: lo leído vale, pero no se resuelve nada


def apply(rows, agents, complete_read, now):
    """Guarda la fotografía. Devuelve (nuevas, resueltas)."""
    existing = {(v.agent_id, v.cve, v.package): v for v in
                EndpointVulnerability._base_manager.filter(agent__in=agents.values())}
    fields = ('client_id', 'version', 'severity', 'score', 'title', 'published_at', 'detected_at', 'last_seen_at',
              'resolved_at')
    create, update, seen = [], [], set()
    for (agent_id, cve, package), row in rows.items():
        agent = agents.get(agent_id)
        if not agent:
            continue
        key = (agent.pk, cve, package)
        seen.add(key)
        values = {'client_id': agent.client_id, 'version': row['version'], 'severity': row['severity'],
                  'score': row['score'], 'title': row['title'], 'published_at': row['published_at'],
                  'detected_at': row['detected_at'], 'last_seen_at': now, 'resolved_at': None}
        current = existing.get(key)
        if current is None:
            create.append(EndpointVulnerability(agent=agent, cve=cve, package=package, first_seen_at=now, **values))
            continue
        if current.resolved_at:
            current.first_seen_at = now  # vuelve a aparecer: cuenta como nueva
        for name, value in values.items():
            setattr(current, name, value)
        update.append(current)
    resolved = 0
    with transaction.atomic():
        WorkerState.reserve(STATE)
        EndpointVulnerability._base_manager.bulk_create(create, batch_size=500)
        EndpointVulnerability._base_manager.bulk_update(update, fields + ('first_seen_at',), batch_size=500)
        if complete_read:
            stale = [v.pk for key, v in existing.items() if key not in seen and v.resolved_at is None]
            for start in range(0, len(stale), 500):
                resolved += EndpointVulnerability._base_manager.filter(pk__in=stale[start:start + 500]).update(resolved_at=now)
            # Equipos retirados o reasignados fuera de la lectura: lo suyo deja de contar.
            resolved += EndpointVulnerability._base_manager.filter(resolved_at=None).exclude(
                agent__in=agents.values()).update(resolved_at=now)
    return len(create), resolved


def sync(now=None):
    """Trabajo `endpoint_vulnerabilities`. Devuelve cuántas vulnerabilidades abiertas hay."""
    from .operations import set_issue
    from .reporting import indexer_authorization
    now = now or timezone.now()
    agents = {a.agent_id: a for a in EndpointAgent._base_manager.filter(status='assigned', client__isnull=False)}
    details = {'checked_at': now.isoformat(), 'agents': len(agents)}
    if agents:
        try:
            rows, complete_read = read(set(agents), indexer_authorization())
        except urllib.error.HTTPError as exc:
            message = NO_PERMISSION if exc.code in (401, 403) else 'El indexador rechazó la consulta de vulnerabilidades.'
            details['error'] = message
            set_issue(ISSUE, 'Vulnerabilidades de los equipos sin actualizar', details=message, now=now)
            _save(details)
            return 0
        except Exception:
            message = 'No se pudo leer el índice de vulnerabilidades de Wazuh; se conserva la última lectura.'
            details['error'] = message
            set_issue(ISSUE, 'Vulnerabilidades de los equipos sin actualizar', details=message, now=now)
            _save(details)
            return 0
        created, resolved = apply(rows, agents, complete_read, now)
        details.update(rows=len(rows), created=created, resolved=resolved, complete=complete_read,
                       agents_with_data=len({key[0] for key in rows}))
        if not complete_read:
            details['error'] = 'Hay más vulnerabilidades de las que se leen por pasada: no se ha marcado ninguna como resuelta.'
    else:
        apply({}, {}, True, now)
    _save(details)
    if not details.get('error'):
        OperationalIssue.objects.filter(key=ISSUE, active=True).update(active=False, resolved_at=now)
    return EndpointVulnerability._base_manager.filter(resolved_at=None).count()


def _save(details):
    with transaction.atomic():
        WorkerState.reserve(STATE)
        WorkerState.objects.filter(name=STATE).update(details=details)


def status():
    state = WorkerState.objects.filter(name=STATE).first()
    return dict(state.details) if state else {}


def nvd_url(cve):
    return f'https://nvd.nist.gov/vuln/detail/{cve}' if cve.startswith('CVE-') else ''


def counts(queryset):
    data = queryset.aggregate(**{code: Count('pk', filter=Q(severity=code)) for code, _ in EndpointVulnerability.SEVERITIES})
    return data


def client_summary(client):
    """Para el portal y el inicio del cliente: equipos con vulnerabilidades críticas o altas abiertas."""
    open_rows = EndpointVulnerability.objects.filter(client=client, resolved_at=None, agent__status='assigned')
    return {**counts(open_rows),
            'critical_devices': open_rows.filter(severity='critical').values('agent').distinct().count(),
            'high_devices': open_rows.filter(severity='high').values('agent').distinct().count()}


def customer_rows(client, limit=150):
    """Proyección explícita para el cliente: solo críticas y altas abiertas de sus equipos asignados."""
    rows = (EndpointVulnerability.objects.filter(client=client, resolved_at=None, agent__status='assigned',
                                                 severity__in=('critical', 'high'))
            .select_related('agent__site'))
    result = [{'device': v.agent.name, 'site': v.agent.site.name if v.agent.site else '', 'cve': v.cve,
               'severity': v.severity, 'severity_label': v.get_severity_display(), 'score': v.score,
               'package': v.package, 'version': v.version, 'published_at': v.published_at, 'url': nvd_url(v.cve),
               'first_seen_at': v.first_seen_at} for v in rows]
    result.sort(key=lambda r: (ORDER[r['severity']], -(r['score'] or 0), r['device'], r['cve']))
    return result[:limit]


@login_required
@require_GET
def overview(request):
    """Página del SOC: vulnerabilidades abiertas de los equipos de los clientes, agrupadas por CVE."""
    if not request.user.has_perm('core.manage_operations'):
        return HttpResponseForbidden('Permiso de operaciones requerido.')
    clients = list(Client.objects.filter(active=True).order_by('name'))
    selected = request.GET.get('client', '')
    severity = request.GET.get('severity', 'high')
    open_rows = EndpointVulnerability.objects.filter(resolved_at=None, agent__status='assigned')
    if selected.isdigit():
        open_rows = open_rows.filter(client_id=int(selected))
    totals = counts(open_rows)
    shown = open_rows.filter(severity__in=('critical', 'high') if severity == 'high' else ('critical',)
                             if severity == 'critical' else [code for code, _ in EndpointVulnerability.SEVERITIES])
    groups = {}
    for v in shown.select_related('agent', 'client').order_by('-score', 'cve')[:5000]:
        group = groups.setdefault((v.cve, v.package), {'cve': v.cve, 'package': v.package, 'severity': v.severity,
                                                       'severity_label': v.get_severity_display(), 'score': v.score,
                                                       'title': v.title, 'url': nvd_url(v.cve), 'devices': [],
                                                       'clients': set(), 'versions': set(),
                                                       'first_seen_at': v.first_seen_at})
        group['devices'].append(v.agent.name)
        group['clients'].add(v.client.name)
        group['versions'].add(v.version)
        group['first_seen_at'] = min(group['first_seen_at'], v.first_seen_at)
    rows = sorted(groups.values(), key=lambda g: (ORDER[g['severity']], -len(g['devices']), -(g['score'] or 0), g['cve']))
    for row in rows:
        row['clients'] = sorted(row['clients'])
        row['versions'] = sorted(v for v in row['versions'] if v)
    per_client = (open_rows.values('client__name', 'client_id')
                  .annotate(critical=Count('pk', filter=Q(severity='critical')), high=Count('pk', filter=Q(severity='high')),
                            devices=Count('agent', distinct=True)).order_by('-critical', '-high', 'client__name'))
    info = status()
    return render(request, 'endpoint_vulnerabilities.html', {
        'rows': rows[:300], 'more': max(0, len(rows) - 300), 'totals': totals, 'per_client': per_client,
        'clients': clients, 'selected_client': selected, 'severity': severity, 'status': info,
        'checked_at': parse_datetime(info.get('checked_at') or ''), 'new_since': timezone.now() - timedelta(days=7)})

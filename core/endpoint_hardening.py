"""Configuración segura de los equipos de los clientes: evaluación SCA de Wazuh (benchmarks CIS y similares).

- Entrada: las alertas `sca` de los agentes de PC y servidores (`endpoints.observe`, desde `alerts.json`) y su
  recuperación desde el indexador. El agente de Wazuh evalúa sus políticas por defecto cada 12 horas; no hace
  falta cambiar su configuración. Solo cuentan los equipos asignados y desde su asignación (invariante 2).
- Wazuh envía la alerta de cada comprobación en el primer análisis y cuando su resultado cambia, y un resumen
  (puntuación, superadas y fallidas) cuando cambia el análisis. El SOC guarda el último resultado de cada
  comprobación; un evento más antiguo que llega tarde no pisa uno posterior. Las comprobaciones «no aplica» no
  generan alerta (nivel 0) y no se ven.
- Límite: de un equipo asignado antes de que su primer análisis llegara al SOC solo se conoce lo que haya cambiado
  después (y lo que recupere el indexador, hasta 30 días atrás en la primera pasada).
- Una comprobación fallida es una recomendación de bastionado, no una vulnerabilidad explotada ni un ataque
  (invariante 4). El cliente ve el equipo, la política, la puntuación y el título de lo que no cumple; el texto de
  corrección del benchmark y los identificadores quedan para el SOC (invariante 3).
"""
from datetime import timedelta

from django.contrib.auth.decorators import login_required
from django.db.models import Count, Max, Q
from django.http import HttpResponseForbidden
from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.cache import never_cache

from .models import Client, EndpointAgent, EndpointPolicy, EndpointPolicyCheck

RESULTS = {'passed': 'passed', 'failed': 'failed', 'not applicable': 'not_applicable', 'not_applicable': 'not_applicable'}
MAX_COMPLIANCE = 20
REGRESSED_DAYS = 7
LOW_SCORE = 50
RECOVERY_INITIAL_DAYS = 30


def _clean(value, size):
    from .endpoints import _clean as clean
    return clean(value, size)


def _text(value, size=4000):
    """Texto largo del benchmark: conserva los saltos de línea, sin otros caracteres de control."""
    import re
    return re.sub(r'[\x00-\x09\x0b-\x1f\x7f]+', ' ', str(value or '')).strip()[:size]


def _count(value):
    from .endpoints import _number
    return _number(value)


def sca_event(source):
    """El bloque `data.sca` si es una alerta SCA de comprobación o de resumen; si no, None."""
    rule = source.get('rule') if isinstance(source.get('rule'), dict) else {}
    groups = rule.get('groups') if isinstance(rule.get('groups'), list) else []
    data = source.get('data') if isinstance(source.get('data'), dict) else {}
    sca = data.get('sca') if isinstance(data.get('sca'), dict) else None
    if sca is None or 'sca' not in groups or sca.get('type') not in ('check', 'summary'):
        return None
    return sca


def _result(check):
    result = str(check.get('result') or '').strip().lower()
    if not result and 'not applicable' in str(check.get('status') or '').lower():
        result = 'not applicable'
    return RESULTS.get(result)


def _compliance(value):
    if not isinstance(value, dict):
        return {}
    out = {}
    for key, item in list(value.items())[:MAX_COMPLIANCE]:
        text = ', '.join(str(v) for v in item) if isinstance(item, list) else str(item)
        out[_clean(key, 60)] = _clean(text, 200)
    return out


def record(endpoint, sca, stamp, now, cache):
    """Guarda una alerta SCA de un equipo asignado. Llamada desde `endpoints.observe` dentro del lote."""
    policy_id = _clean(sca.get('policy_id'), 120)
    if not policy_id:
        return
    name = _clean(sca.get('policy'), 200)
    key = ('sca', endpoint.pk, policy_id)
    policy = cache.get(key)
    if policy is None:
        policy, _ = EndpointPolicy._base_manager.get_or_create(
            agent=endpoint, policy_id=policy_id,
            defaults={'client_scope_id': endpoint.client_id, 'name': name, 'first_seen_at': stamp, 'updated_at': now})
        cache[key] = policy
    if name and name != policy.name:
        EndpointPolicy._base_manager.filter(pk=policy.pk).update(name=name)
        policy.name = name
    if sca['type'] == 'summary':
        if policy.scanned_at and stamp < policy.scanned_at:
            return
        values = {'score': _count(sca.get('score')), 'passed': _count(sca.get('passed')), 'failed': _count(sca.get('failed')),
                  'invalid': _count(sca.get('invalid')), 'total': _count(sca.get('total_checks')),
                  'scan_id': _clean(sca.get('scan_id'), 40), 'scanned_at': stamp, 'updated_at': now}
        if values['score'] is not None:
            values['score'] = min(values['score'], 100)
        EndpointPolicy._base_manager.filter(pk=policy.pk).update(**values)
        for field, value in values.items():
            setattr(policy, field, value)
        return
    check = sca.get('check') if isinstance(sca.get('check'), dict) else {}
    check_id, result = _clean(check.get('id'), 20), _result(check)
    if not check_id or not result:
        return
    fields = {'title': _clean(check.get('title'), 300) or f'Comprobación {check_id}', 'result': result,
              'description': _text(check.get('description')), 'rationale': _text(check.get('rationale')),
              'remediation': _text(check.get('remediation')), 'compliance': _compliance(check.get('compliance')),
              'observed_at': stamp}
    row = EndpointPolicyCheck._base_manager.filter(agent=endpoint, policy_id=policy_id, check_id=check_id).first()
    if row is None:
        previous = RESULTS.get(str(check.get('previous_result') or '').strip().lower(), '')
        EndpointPolicyCheck._base_manager.create(
            agent=endpoint, client_scope_id=endpoint.client_id, policy_id=policy_id, check_id=check_id,
            previous_result=previous, first_seen_at=stamp, changed_at=stamp if previous and previous != result else None,
            **fields)
        return
    if stamp < row.observed_at:
        return  # llega tarde: no deshace un resultado posterior
    if result != row.result:
        fields.update(previous_result=row.result, changed_at=stamp)
    EndpointPolicyCheck._base_manager.filter(pk=row.pk).update(**fields)


# --- Resúmenes ---------------------------------------------------------------------------------

def policy_rows(policies):
    """Por equipo y política: puntuación (la de Wazuh si hay resumen; si no, calculada con lo recibido)."""
    policies = list(policies.select_related('agent__client', 'agent__site'))
    counts = {}
    if policies:
        agent_ids = {p.agent_id for p in policies}
        for row in (EndpointPolicyCheck._base_manager.filter(agent_id__in=agent_ids)
                    .values('agent_id', 'policy_id').annotate(passed=Count('pk', filter=Q(result='passed')),
                                                              failed=Count('pk', filter=Q(result='failed')),
                                                              last=Max('observed_at'))):
            counts[(row['agent_id'], row['policy_id'])] = row
    rows = []
    for policy in policies:
        seen = counts.get((policy.agent_id, policy.policy_id), {})
        passed, failed = seen.get('passed', 0), seen.get('failed', 0)
        computed = round(passed * 100 / (passed + failed)) if passed + failed else None
        score = policy.score if policy.scanned_at and policy.score is not None else computed
        last = max([d for d in (policy.scanned_at, seen.get('last')) if d] or [policy.first_seen_at])
        rows.append({'policy': policy, 'agent': policy.agent, 'score': score, 'from_summary': bool(policy.scanned_at and policy.score is not None), 'passed': passed, 'failed': failed, 'last': last,
                     'reported_failed': policy.failed, 'reported_total': policy.total})
    rows.sort(key=lambda r: (r['score'] is None, r['score'] if r['score'] is not None else 0, r['agent'].name))
    return rows


def _assigned(queryset):
    return queryset.filter(agent__status='assigned')


def client_summary(client):
    """Para el portal y la ficha: equipos evaluados, puntuación media y equipos por debajo de 50."""
    rows = policy_rows(_assigned(EndpointPolicy.objects.filter(client_scope_id=client.pk)))
    scored = [r['score'] for r in rows if r['score'] is not None]
    devices = {r['agent'].pk for r in rows}
    low = {r['agent'].pk for r in rows if r['score'] is not None and r['score'] < LOW_SCORE}
    return {'devices': len(devices), 'average': round(sum(scored) / len(scored)) if scored else None,
            'low_devices': len(low), 'failed': sum(r['failed'] for r in rows)}


def top_failed(checks, limit=30):
    """Comprobaciones que no cumplen, agrupadas por política y título, las de más equipos primero."""
    groups = {}
    for check in checks.filter(result='failed').select_related('agent').order_by('policy_id', 'check_id')[:20000]:
        group = groups.setdefault((check.policy_id, check.title), {
            'policy_id': check.policy_id, 'check_id': check.check_id, 'title': check.title, 'devices': [], 'regressed': 0,
            'remediation': check.remediation, 'rationale': check.rationale, 'compliance': check.compliance})
        group['devices'].append(check.agent.name)
        group['regressed'] += int(check.regressed)
    rows = sorted(groups.values(), key=lambda g: (-len(g['devices']), -g['regressed'], g['title']))
    for row in rows:
        row['devices'] = sorted(set(row['devices']))
    return rows[:limit], len(rows)


@login_required
@never_cache
def overview(request):
    """Página del SOC: puntuación por equipo, lo que más se repite sin cumplir y lo que ha empeorado."""
    if not request.user.has_perm('core.manage_operations'):
        return HttpResponseForbidden('Permiso de operaciones requerido.')
    now = timezone.now()
    selected = request.GET.get('client', '')
    policies = _assigned(EndpointPolicy.objects.all())
    checks = _assigned(EndpointPolicyCheck.objects.all())
    if selected.isdigit():
        policies = policies.filter(client_scope_id=int(selected))
        checks = checks.filter(client_scope_id=int(selected))
    rows = policy_rows(policies)
    failed, groups = top_failed(checks)
    regressed = list(checks.filter(result='failed', previous_result='passed',
                                   changed_at__gte=now - timedelta(days=REGRESSED_DAYS))
                     .select_related('agent').order_by('-changed_at')[:100])
    scored = [r['score'] for r in rows if r['score'] is not None]
    assigned = EndpointAgent.objects.filter(status='assigned')
    if selected.isdigit():
        assigned = assigned.filter(client_id=int(selected))
    kpis = {'devices': len({r['agent'].pk for r in rows}), 'assigned': assigned.count(),
            'average': round(sum(scored) / len(scored)) if scored else None,
            'low': len({r['agent'].pk for r in rows if r['score'] is not None and r['score'] < LOW_SCORE}),
            'regressed': len(regressed)}
    clients = {c.pk: c for c in Client.objects.all()}
    for row in rows:
        row['client'] = clients.get(row['policy'].client_scope_id)
    return render(request, 'endpoint_hardening.html', {
        'rows': rows, 'failed': failed, 'groups': groups, 'regressed': regressed, 'kpis': kpis,
        'clients': Client.objects.filter(active=True), 'selected_client': selected, 'low_score': LOW_SCORE,
        'regressed_days': REGRESSED_DAYS})


# --- Portal del cliente (proyección explícita, invariante 3) -----------------------------------

def customer_context(client):
    """Equipo, sede, política, puntuación, cuántas no cumple y fecha; y los títulos de lo que no cumple, por equipos.
    Sin texto de corrección, identificadores de política o comprobación, ni datos de otros clientes."""
    rows = []
    for row in policy_rows(_assigned(EndpointPolicy.objects.filter(client_scope_id=client.pk))):
        agent = row['agent']
        rows.append({'device': agent.name, 'site': agent.site.name if agent.site else '', 'policy': row['policy'].name,
                     'score': row['score'], 'failed': row['failed'], 'last': row['last'],
                     'tone': 'attention' if row['score'] is not None and row['score'] < LOW_SCORE else 'ok'})
    failed, groups = top_failed(_assigned(EndpointPolicyCheck.objects.filter(client_scope_id=client.pk)), limit=15)
    return {'devices': rows, 'to_fix': [{'title': g['title'], 'devices': g['devices']} for g in failed],
            'to_fix_more': max(0, groups - len(failed)), 'low_score': LOW_SCORE}


# --- Recuperación desde el indexador -----------------------------------------------------------

def recovery_filter():
    """Alertas que recupera `endpoints.reconcile` (flujo «sca»)."""
    return {'bool': {'filter': [{'term': {'rule.groups': 'sca'}},
                                {'terms': {'data.sca.type': ['check', 'summary']}}]}}

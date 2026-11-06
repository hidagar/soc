"""Índice de seguridad del cliente (0–100): una cifra comprensible con lo que la suma y lo que la resta.

Ocho factores con pesos fijos (WEIGHTS), medidos con datos que el SOC ya comprueba:
- **Por firewall activo** (media de sus firewalls): exposición a Internet, protección en marcha, IPS en
  modo bloqueo, firmware al día y visibilidad.
- **Del cliente:** ataques que entran (30 días), bloqueo proactivo del SOC y actuaciones al día.

Valores: 1 cumple, 0,5 parcial o **sin comprobar** (no se finge que está bien), 0 no cumple. Niveles:
85 o más, «Bien»; de 65 a 84, «Mejorable»; menos de 65, «Requiere atención».

Es una proyección para el cliente (invariante 3): recuentos y textos claros, nunca IPs, títulos
internos ni notas del SOC. Tampoco es una prueba de ausencia de riesgo: mide lo que el SOC puede
comprobar.
"""
from datetime import timedelta

from django.utils import timezone

WEIGHTS = {'exposure': 20, 'engines': 10, 'ips': 10, 'firmware': 15, 'visibility': 15,
           'attacks': 10, 'blocklist': 10, 'tasks': 10}
LABELS = {'exposure': 'Exposición a Internet', 'engines': 'Protección en marcha', 'ips': 'IPS en modo bloqueo',
          'firmware': 'Firmware al día', 'visibility': 'Visibilidad del SOC', 'attacks': 'Ataques que entran',
          'blocklist': 'Bloqueo proactivo del SOC', 'tasks': 'Actuaciones al día'}
ACTIONS = {
    'exposure': 'Cerrar o limitar a orígenes conocidos los servicios publicados en Internet que no sean necesarios; el SOC os indica cuáles.',
    'engines': 'Revisar con el SOC los motores de protección detenidos o en bypass y volver a ponerlos en marcha.',
    'ips': 'Pasar el IPS de solo detección a bloqueo, en una ventana acordada con el SOC.',
    'firmware': 'Actualizar el firmware del firewall en una ventana de mantenimiento, con copia previa.',
    'visibility': 'Restablecer el envío de registros al SOC: sin ellos no podemos vigilar ese firewall.',
    'attacks': 'Aplicar las recomendaciones de los informes sobre las detecciones permitidas.',
    'blocklist': 'Activar en vuestros firewalls la lista de bloqueo del SOC.',
    'tasks': 'Completar las actuaciones pendientes del portal que tienen la fecha acordada vencida.',
}
UNKNOWN_ACTION = 'Dar al SOC acceso para comprobarlo (por ejemplo, la conexión API del firewall).'
LEVELS = (('good', 85, 'Bien'), ('fair', 65, 'Mejorable'), ('poor', 0, 'Requiere atención'))
EXPOSURE_FRESH = timedelta(days=7)
ATTACK_WINDOW = timedelta(days=30)


def level_of(score):
    for code, threshold, label in LEVELS:
        if score >= threshold:
            return code, label
    return 'poor', 'Requiere atención'


def _exposure(device, findings, now):
    check = getattr(device, 'exposure_check', None)
    if not check or not check.last_success_at or now - check.last_success_at > EXPOSURE_FRESH:
        return None
    severities = {f.severity for f in findings.get(device.pk, []) if not f.exception_active}
    return 0.0 if 'high' in severities else 0.5 if 'medium' in severities else 1.0


def _engines(snapshot):
    states = [c['state'] for c in snapshot['controls']]
    if not states:
        return None
    if any(s in ('disabled', 'stopped', 'bypass') for s in states):
        return 0.0
    return 1.0 if all(s in ('running', 'configured') for s in states) else None


def _ips(snapshot):
    ips = [c for c in snapshot['controls'] if c['name'] in ('Suricata', 'UniFi IPS')]
    if not ips or not snapshot['current']:
        return None
    modes = {c['mode'] for c in ips}
    if 'ips' in modes:
        return 1.0
    return 0.0 if modes & {'ids', 'disabled'} else None


def _firmware(device, snapshot, now):
    firmware = snapshot['firmware'] or {}
    catalogue = snapshot['catalogue']
    if device.vendor != 'opnsense' or not snapshot['current']:
        return None
    if firmware.get('updates_available') is True:
        return 0.0
    if firmware.get('updates_available') is False and catalogue and now - catalogue <= timedelta(days=7):
        return 1.0
    return None


def _visibility(snapshot):
    codes = {g['code'] for g in snapshot['gaps']}
    if 'silence' in codes or 'receipt' in codes:
        return 0.0
    health = snapshot['health']
    return 1.0 if health and health.last_log_at else None


def _average(values):
    """(valor 0–1, todos sin comprobar): lo no comprobado cuenta la mitad."""
    if not values:
        return 0.5, True
    known = [v for v in values if v is not None]
    return sum(v if v is not None else 0.5 for v in values) / len(values), not known


def _factor(key, value, unknown, detail):
    points = round(WEIGHTS[key] * value, 1)
    state = 'unknown' if unknown else 'ok' if value >= 0.999 else 'bad' if value <= 0.001 else 'partial'
    return {'key': key, 'label': LABELS[key], 'max': WEIGHTS[key], 'points': points, 'state': state, 'detail': detail,
            'action': UNKNOWN_ACTION if unknown else ACTIONS[key] if state != 'ok' else ''}


def compute(client, now=None):
    """Índice actual de un cliente: {'score', 'level', 'level_label', 'factors', 'improvements', 'firewalls'}.

    Sin firewalls activos devuelve `score` None: no hay nada que medir.
    """
    from .blocklist_efficacy import client_protection
    from .investigation import evidence_queryset
    from .models import CustomerTask, Device, ExposureFinding
    from .protection import snapshot as protection_snapshot
    now = now or timezone.now()
    devices = list(Device.objects.filter(site__client=client, active=True, site__active=True)
                   .select_related('site__client', 'health', 'protection_policy', 'exposure_check').prefetch_related('feeds'))
    if not devices:
        return {'score': None, 'level': '', 'level_label': 'Sin firewalls conectados', 'factors': [], 'improvements': [],
                'firewalls': 0}
    findings = {}
    for finding in ExposureFinding.objects.filter(device__in=devices, present=True, severity__in=('high', 'medium')):
        findings.setdefault(finding.device_id, []).append(finding)
    per_device = {key: [] for key in ('exposure', 'engines', 'ips', 'firmware', 'visibility')}
    for device in devices:
        snap = protection_snapshot(device, now, incidents=False)
        per_device['exposure'].append(_exposure(device, findings, now))
        per_device['engines'].append(_engines(snap))
        per_device['ips'].append(_ips(snap))
        per_device['firmware'].append(_firmware(device, snap, now))
        per_device['visibility'].append(_visibility(snap))
    total = len(devices)

    def counted(values, good):
        return sum(1 for v in values if v == good)

    factors = []
    value, unknown = _average(per_device['exposure'])
    high = sum(1 for d in devices for f in findings.get(d.pk, []) if f.severity == 'high' and not f.exception_active)
    medium = sum(1 for d in devices for f in findings.get(d.pk, []) if f.severity == 'medium' and not f.exception_active)
    parts = [f'{n} de riesgo {label}' for n, label in ((high, 'alto'), (medium, 'medio')) if n]
    factors.append(_factor('exposure', value, unknown, 'Sin comprobar todavía.' if unknown else
                           'Ningún servicio de riesgo publicado en Internet.' if not parts else
                           f'Servicios publicados en Internet: {" y ".join(parts)}.'))
    for key, ok_text, bad_text, single in (
            ('engines', 'Todos los motores de protección están en marcha.', 'con algún motor detenido o en bypass',
             'Algún motor de protección está detenido o en bypass.'),
            ('ips', 'El IPS bloquea los ataques que detecta.', 'con el IPS solo en detección', 'El IPS solo detecta: no bloquea.'),
            ('firmware', 'Firmware al día.', 'con actualizaciones pendientes', 'Hay actualizaciones de firmware pendientes.'),
            ('visibility', 'El SOC recibe los registros de todos los firewalls.', 'sin registros recientes en el SOC',
             'El SOC no recibe registros recientes del firewall.')):
        value, unknown = _average(per_device[key])
        bad = counted(per_device[key], 0.0)
        good = counted(per_device[key], 1.0)
        if unknown:
            detail = 'Sin comprobar todavía.'
        elif good == total:
            detail = ok_text
        elif total == 1:
            detail = single if bad else 'Sin comprobar todavía.'
        else:
            detail = f'{good} de {total} firewalls correctos' + (f'; {bad} {bad_text}.' if bad else '; el resto sin comprobar.')
        factors.append(_factor(key, value, unknown, detail))
    if all(v == 0.0 for v in per_device['visibility']):
        factors.append(_factor('attacks', 0.5, True, 'Sin registros en el SOC: no se puede medir.'))
    else:
        allowed = evidence_queryset(client, ATTACK_WINDOW.days).filter(action='allowed').count()
        value = 1.0 if not allowed else 0.5 if allowed <= 10 else 0.0
        factors.append(_factor('attacks', value, False, 'Ninguna detección permitida en 30 días.' if not allowed else
                               f'{allowed} detección{"es" if allowed != 1 else ""} permitida{"s" if allowed != 1 else ""} por el firewall en 30 días.'))
    protection = client_protection(client, now=now) or {}
    inbound = protection.get('inbound')
    if inbound:
        firewalls, entries = len(inbound['firewalls']), inbound['entries']
        factors.append(_factor('blocklist', 1.0, False, f"Activa en {firewalls} firewall{'s' if firewalls != 1 else ''} "
                                                        f"con {entries} IP{'s' if entries != 1 else ''} maliciosa{'s' if entries != 1 else ''}."))
    else:
        factors.append(_factor('blocklist', 0.0, False, 'No está activa en vuestros firewalls.'))
    overdue = CustomerTask.objects.filter(incident__client=client, visible=True, status__in=('pending', 'rework'),
                                          due_at__lt=now).count()
    factors.append(_factor('tasks', 0.0 if overdue else 1.0, False, 'Ninguna actuación vencida.' if not overdue else
                           f'{overdue} actuación{"es" if overdue != 1 else ""} con la fecha acordada vencida.'))
    score = round(sum(f['points'] for f in factors))
    code, label = level_of(score)
    improvements = sorted((f for f in factors if f['action']), key=lambda f: (f['points'] - f['max'], f['key']))[:3]
    return {'score': score, 'level': code, 'level_label': label, 'factors': factors,
            'improvements': [{'label': f['label'], 'action': f['action'], 'gain': round(f['max'] - f['points'])} for f in improvements],
            'firewalls': total}


def record(now=None):
    """Trabajo horario: guarda (o actualiza) la foto de hoy de cada cliente activo."""
    from .models import Client, SecurityScore
    now = now or timezone.now()
    today = timezone.localdate(now)
    count = 0
    for client in Client._base_manager.filter(active=True):
        result = compute(client, now)
        SecurityScore._base_manager.update_or_create(client=client, day=today, defaults={
            'score': result['score'], 'level': result['level'], 'factors': result['factors'], 'computed_at': now})
        count += 1
    return count


def history(client, days=90, now=None):
    from .models import SecurityScore
    since = timezone.localdate(now or timezone.now()) - timedelta(days=days)
    return list(SecurityScore.objects.filter(client=client, day__gte=since, score__isnull=False).order_by('day'))


def at(client, day):
    """Última foto hasta ese día (para informes de un periodo cerrado)."""
    from .models import SecurityScore
    return SecurityScore.objects.filter(client=client, day__lte=day, score__isnull=False).order_by('-day').first()


def portal_context(client, now=None):
    """Lo que ve el cliente: el índice actual, su evolución y qué mejorar."""
    current = compute(client, now)
    rows = history(client, 90, now)
    today = timezone.localdate(now or timezone.now())
    # Referencia: la foto de hace 30 días o, si el histórico es más corto, la primera del periodo.
    reference = at(client, today - timedelta(days=30)) or next((r for r in rows if r.day >= today - timedelta(days=30) and r.day < today), None)
    change = current['score'] - reference.score if current['score'] is not None and reference else None
    points = [{'day': r.day, 'score': r.score, 'height': max(3, r.score)} for r in rows[-30:]]
    return {'index': current, 'index_change': change, 'index_since': reference.day if reference else None, 'index_history': points}

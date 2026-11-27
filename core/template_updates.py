"""Mejoras de las plantillas del SOC ya activas en los firewalls: se preparan solas y se aplican con aprobación.

Una versión nueva de una plantilla (por ejemplo, la 1.1: tablas por URL cada ~15 minutos y lista DNS con copia de
15 minutos) no cambia por sí sola ningún firewall (AGENTS: una modificación de código no autoriza cambios en
firewalls). El trabajo «Propagación a los firewalls» prepara para cada regla activa con una versión anterior un
plan «Actualización de plantilla» en el control de cambios, en borrador. Ese plan solo cambia los ajustes indicados
en los objetos que creó el SOC (identificados por su descripción); activarlo exige aprobación con MFA, se confirma
en 10 minutos o se revierte a los valores anteriores. Nada de esto afecta al acceso de gestión del firewall.
"""
from .models import ChangePlan
from .security import audit

UPDATE_TEMPLATE = 'soc_update'
LATEST = '1.1'
# Cambios de cada versión por tipo de objeto del SOC en OPNsense.
CHANGES = {'1.1': {'alias': {'updatefreq': '0.01'}, 'dnsbl': {'cache_ttl': '900'}}}
SUMMARY = {'1.1': 'La tabla del SOC se descarga cada ~15 minutos (antes ~1 hora) y la lista DNS se renueva si su copia '
                  'tiene más de 15 minutos (antes 1 hora): las novedades de Q-Feeds y CrowdSec llegan antes al firewall.'}
CONFIRM_MINUTES = 10
CLOSED = ('rolled_back', 'failed')


def updatable_templates():
    from .blocklist import ALL_TEMPLATES
    from .qfeeds_distribution import DNS_TEMPLATE
    return ALL_TEMPLATES + (DNS_TEMPLATE,)


def applied_version(plan):
    return (plan.parameters or {}).get('version_applied') or plan.template_version


def _key(version):
    return tuple(int(part) for part in str(version).split('.') if part.isdigit())


def outdated(plan):
    return (plan.status == 'active' and plan.template in updatable_templates() and plan.device.vendor == 'opnsense'
            and plan.device.management_method == 'api' and _key(applied_version(plan)) < _key(LATEST))


def pending_update(plan):
    return (ChangePlan._base_manager.filter(template=UPDATE_TEMPLATE, parameters__plan=plan.pk)
            .exclude(status__in=CLOSED).exclude(status='active').order_by('-pk').first())


def preview(plan):
    kind = 'dnsbl' if any(o.get('kind') == 'dnsbl' for o in plan.remote_objects) else 'alias'
    changes = {}
    for version, by_kind in CHANGES.items():
        if _key(applied_version(plan)) < _key(version):
            changes.update(by_kind.get(kind, {}))
    return {'profile': f'Actualización a {LATEST}', 'version': LATEST, 'networks': [], 'interface': '', 'rules': [],
            'update': {'kind': kind, 'changes': changes, 'plan': plan.pk, 'title': plan.title,
                       'summary': SUMMARY.get(LATEST, '')},
            'checks': ['Solo cambia los ajustes indicados en el objeto que creó el SOC con la propuesta original; '
                       'las reglas y las listas del operador no se tocan.',
                       f'Tras activarla, comprobar que el firewall sigue descargando la lista y confirmar en {CONFIRM_MINUTES} '
                       'minutos; si no se confirma, se vuelve a los valores anteriores.'],
            'zenarmor': [], 'suricata': []}


def create(plan, user=None):
    """Borrador de actualización de una regla activa (uno por regla, sin duplicar)."""
    existing = pending_update(plan)
    if existing:
        return existing
    update = ChangePlan.objects.create(device=plan.device, template=UPDATE_TEMPLATE, template_version=LATEST,
                                       title=f'Actualización a {LATEST}: {plan.title}',
                                       parameters={'plan': plan.pk, 'client': (plan.parameters or {}).get('client'),
                                                   'from': applied_version(plan), 'to': LATEST},
                                       preview=preview(plan), requested_by=user)
    audit('change.draft', update, {'template': UPDATE_TEMPLATE})
    return update


def prepare_all():
    """Prepara los borradores que falten. Devuelve cuántos se han creado."""
    created = 0
    for plan in ChangePlan._base_manager.filter(template__in=updatable_templates(), status='active').select_related('device'):
        if outdated(plan) and not pending_update(plan):
            create(plan)
            created += 1
    return created


def mark_applied(update, version):
    target = ChangePlan._base_manager.filter(pk=update.parameters.get('plan')).first()
    if target:
        target.parameters = {**(target.parameters or {}), 'version_applied': version}
        target.save(update_fields=['parameters'])

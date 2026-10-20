"""Versioned action and risk vocabulary for indexed and locally stored events.

An allowed/log-only action describes the observing engine, never the effective
decision of every firewall control or proof that an attack succeeded.
"""
import re

VERSION = 1
ACTION_VALUES = {
    'unifi': {'blocked': ('blocked', 'block', 'drop', 'dropped', 'deny', 'denied'),
              'allowed': ('allowed', 'allow', 'alert')},
    'suricata': {'blocked': ('blocked', 'block', 'drop', 'dropped', 'deny', 'denied'),
                 'allowed': ('allowed', 'allow', 'alert')},
    'hillstone': {'blocked': ('drop', 'dropped', 'deny', 'denied', 'blocked', 'block', 'block-ip', 'reset', 'reset-conn'),
                 'allowed': ('allow', 'allowed', 'alarm', 'log-only', 'log only')},
    'zenarmor': {'blocked': ('1', 'true'), 'allowed': ('0', 'false')},
}


def normalize_action(engine, value):
    key = str(value if value is not None else '').strip().casefold()
    return next((action for action, values in ACTION_VALUES.get(engine, {}).items() if key in values), 'unknown')


def family(event):
    text = (event.get('category', '') + ' ' + event.get('signature', '')).casefold()
    if event.get('category') == 'application_policy': return 'policy'
    if event.get('engine') == 'clamav' and event.get('security'): return 'malware'
    if any(t in text for t in ('botnet', 'command-and-control', 'c&c', 'dga', 'trojan', 'malware', 'keylogger', 'spyware', 'ransomware', 'coin miner')) or re.search(r'\bc2\b',text): return 'malware'
    if 'credential-theft' in text or 'credential theft' in text: return 'credential_theft'
    if 'phish' in text: return 'phishing'
    if any(t in text for t in ('scan', 'zmap', 'nmap', 'scanning')): return 'scan'
    return 'intrusion' if event.get('security') else 'system'


def metadata(event, vendor_severity=''):
    kind = family(event)
    urgent = kind != 'policy' and (event['level'] >= 12 or event.get('security') and (event['action'] == 'allowed' or kind in ('malware','credential_theft')))
    priority = 'critical' if urgent and kind == 'malware' and event['action'] == 'allowed' else 'high' if urgent else 'medium' if event.get('security') else 'low'
    return {'contract_version': VERSION, 'event_family': kind,
            'vendor_severity': re.sub(r'[\x00-\x1f\x7f]+', ' ', str(vendor_severity if vendor_severity is not None else '')).strip()[:40],
            'soc_priority': priority, 'priority_label': {'low':'Baja','medium':'Media','high':'Alta','critical':'Crítica'}[priority]}


def recommendation(event):
    kind = family(event)
    if kind == 'malware':
        return 'Identificar el equipo, aislarlo si se confirma compromiso, ejecutar un análisis con el antivirus/EDR y revisar persistencia, credenciales y conexiones recientes. Conservar las evidencias.'
    if kind in ('phishing','credential_theft'):
        return 'Revisar el equipo y el acceso al enlace. Si se introdujeron credenciales, cambiarlas, revocar sesiones y comprobar MFA.'
    if kind == 'policy':
        return 'Comprobar si la aplicación está autorizada. Revisar excepciones con el responsable; este bloqueo de política no demuestra una infección.'
    if kind == 'scan':
        return 'Revisar el servicio expuesto y sus registros, confirmar qué orígenes necesitan acceso y limitar la exposición. Un escaneo no demuestra una infección ni un acceso conseguido.'
    return 'Revisar el servicio y equipo afectados, actualizar el software y limitar la exposición a los accesos necesarios. Confirmar el impacto antes de cambiar reglas.'


def snapshot(event, device=None):
    result = {key: event[key] for key in ('contract_version', 'engine', 'security', 'category', 'signature', 'action', 'level', 'vendor_severity', 'soc_priority', 'priority_label', 'event_family')}
    if device is not None:
        result.update(device_id=device.pk, site_id=device.site_id, site_name=device.site.name, client_scope_id=device.site.client_id)
    return result


def _any(*clauses):
    return {'bool': {'should': list(clauses), 'minimum_should_match': 1}}


def _all(*clauses):
    return {'bool': {'filter': list(clauses)}}


def _not(clause):
    return {'bool': {'must_not': [clause]}}


def _values(field, values):
    # Case-insensitive full-field keyword regexp; no substring action guessing.
    def word(value):
        return ''.join('[' + c.lower() + c.upper() + ']' if c.isalpha() else re.escape(c) for c in value)
    return {'regexp': {field: '[ ]*(' + '|'.join(word(v) for v in values) + ')[ ]*'}}


def selectors():
    """Decoder precedence mirrors operations.normalize for supported Wazuh layouts."""
    unifi = _any({'prefix': {'decoder.name': 'unifi'}}, *({'exists': {'field': 'data.unifi.' + key}} for key in ('category', 'action', 'event_name', 'ips_signature')))
    hillstone = _any({'prefix': {'decoder.name': 'soc-hillstone'}}, {'term': {'decoder.name': 'hillstone'}})
    zenarmor = _any({'prefix': {'decoder.name': 'zenarmor'}}, {'term': {'rule.groups': 'zenarmor'}})
    clamav = _values('decoder.name', ('clamd', 'freshclam', 'clamav'))
    suricata = _any({'term': {'data.event_type': 'alert'}}, {'regexp': {'decoder.name': '.*[sS][uU][rR][iI][cC][aA][tT][aA].*'}})
    return unifi, hillstone, zenarmor, clamav, suricata


def security_filter():
    unifi,hillstone,zenarmor,clamav,suricata=selectors()
    return _any(
        _all(unifi,_values('data.unifi.category',('security',))),
        _all(_not(unifi),hillstone,_values('data.hillstone.category',('threat',))),
        _all(_not(_any(unifi,hillstone)),zenarmor,_any({'term':{'rule.groups':'zenarmor_security'}},{'regexp':{'data.security_tags':'.*[a-zA-Z].*'}})),
        _all(_not(_any(unifi,hillstone,zenarmor)),clamav,{'terms':{'rule.id':['52502','52511']}}),
        _all(_not(_any(unifi,hillstone,zenarmor,clamav)),suricata,_any({'term':{'data.event_type':'alert'}},*({'exists':{'field':'data.alert.'+key}} for key in ('signature','category','action','severity','signature_id')))),
    )


def action_filter(action):
    """Indexed action aliases share the Python vocabulary and vendor boundaries."""
    if action not in ('blocked', 'allowed'): raise ValueError('Acción no admitida.')
    from .hillstone_events import legacy_action_regexp
    unifi,hillstone,zenarmor,clamav,suricata=selectors()
    def legacy_pattern(wanted):
        # OpenSearch's case-insensitive option avoids duplicating every letter,
        # keeping the strict endpoint/layout validation below its 1,000-byte cap.
        pattern=re.sub(r'\[([a-z])([A-Z])\]',lambda m:m[1] if m[1].upper()==m[2] else m[0],legacy_action_regexp(wanted))
        pattern=pattern.replace(r'\r','\r').replace(r'\n','\n')
        size={'script':{'script':{'source':"doc.containsKey('data.hillstone.message') && doc['data.hillstone.message'].size() != 0 && doc['data.hillstone.message'].value.length() <= params.limit",'params':{'limit':16384}}}}
        return _all(size,{'regexp':{'data.hillstone.message':{'value':pattern,'case_insensitive':True}}})
    legacy = _all(_values('data.hillstone.category',('threat',)), _values('data.hillstone.code',('flow',)), legacy_pattern(action))
    parsed_layout = _all(_values('data.hillstone.code',('flow',)), legacy_pattern('any'))
    return _any(
        _all(unifi, _values('data.unifi.action', ACTION_VALUES['unifi'][action])),
        _all(_not(unifi), hillstone, _values('data.hillstone.category',('threat',)), _any(legacy, _all(_not(parsed_layout), _values('data.action', ACTION_VALUES['hillstone'][action])))),
        _all(_not(_any(unifi, hillstone)), zenarmor, _values('data.is_blocked', ACTION_VALUES['zenarmor'][action])),
        _all(_not(_any(unifi, hillstone, zenarmor, clamav)), suricata, _values('data.alert.action', ACTION_VALUES['suricata'][action])),
    )

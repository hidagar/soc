"""Read-only, allowlisted device facts. Unknown values never erase known facts."""
import hashlib
import json
import re
from datetime import timedelta
from django.db import transaction
from django.utils import timezone
from .models import Device

FIELDS = ('model', 'software_version', 'serial_number', 'zenarmor_version', 'zenarmor_edition')
LABELS = {'model': 'Modelo', 'software_version': 'Firmware / versión', 'serial_number': 'Número de serie',
          'zenarmor_version': 'Versión de Zenarmor', 'zenarmor_edition': 'Edición de Zenarmor'}


class InventoryError(Exception):
    pass


def clean(value):
    if not isinstance(value, str): return ''
    value = value.strip()
    if len(value) > 120 or any(ord(c) < 32 for c in value): return ''
    return '' if value.lower() in ('unknown', 'n/a', 'none', 'not specified', 'to be filled by o.e.m.', 'default string', 'system product name', 'system serial number', '00000000') else value


def provider(device):
    if device.management_method == 'ssh':
        row = getattr(device, 'ssh_connection', None)
        if row: return 'SSH', row
    names = {'unifi': ('UniFi API', 'unifi_cloud'), 'opnsense': ('OPNsense API', 'opnsense_api'),
             'hillstone': ('Hillstone API', 'hillstone_api'), 'grandstream_gcc': ('GDMS', 'gdms_cloud')}
    name, relation = names.get(device.vendor, ('', ''))
    row = getattr(device, relation, None) if relation else None
    if row and (not hasattr(row, 'client_scope_id') or row.client_scope_id == device.site.client_id): return name, row
    return '', None


def signature(device):
    name, row = provider(device)
    attrs = {f.attname: getattr(row, f.attname) for f in row._meta.fields if f.name not in ('last_ok', 'last_checked_at')} if row else {}
    data = [device.site.client_id, device.vendor, device.management_method, device.management_address, device.mac_address, name, attrs]
    return hashlib.sha256(json.dumps(data, sort_keys=True, default=str).encode()).hexdigest()


def facts(device):
    metadata = device.inventory_metadata if isinstance(device.inventory_metadata, dict) else {}
    fields = metadata.get('fields', {})
    return [{'label': LABELS[k], 'value': getattr(device, k) or 'Pendiente de descubrir',
             'source': ('Último dato conocido · ' if k in metadata.get('pending', []) and getattr(device, k) else '') + fields.get(k, {}).get('source', 'Sin verificar'),
             'checked_at': fields.get(k, {}).get('checked_at', '')}
            for k in FIELDS if not k.startswith('zenarmor') or device.zenarmor_enabled]


def opnsense_details(connection):
    from .provisioning import _api_request
    from .opnsense_api import discover_version
    details = {}
    try:
        data = _api_request(connection, '/api/core/firmware/info')
        details['software_version'] = discover_version(data)
        product = data.get('product')
        if not details['software_version'] and isinstance(product, dict): details['software_version'] = discover_version(product)
    except Exception: pass
    # systemInformation exposes installed product version, not hardware model.
    if not details.get('software_version'):
        try:
            data = _api_request(connection, '/api/diagnostics/system/systemInformation')
            for line in data.get('versions', []):
                match = re.match(r'^OPNsense\s+(\S+)', str(line))
                if match: details['software_version'] = match[1]; break
        except Exception: pass
    return details


def ssh_details(device, connection):
    from .ssh_connection import run_command
    def read(command):
        status, output, _ = run_command(connection, command)
        return output.strip() if status == 0 else ''
    if device.vendor == 'opnsense':
        version = read('opnsense-version -v').splitlines()
        match = re.match(r'^OPNsense\s+(\S+)', version[0]) if version else None
        return {'software_version': match[1] if match else '',
                'model': read('kenv -q smbios.system.product'), 'serial_number': read('kenv -q smbios.system.serial')}
    if device.vendor == 'hillstone':
        output = read('show version')
        values = {}
        patterns = {'software_version': r'^(?:StoneOS(?:\s+Software)?\s+Version|Software\s+Version|Version)\s*[:=]\s*(.+)$',
                    'model': r'^(?:Hardware\s+Model|Product\s+Model|Model|Platform)\s*[:=]\s*(.+)$',
                    'serial_number': r'^(?:Serial\s+Number|Serial\s+No\.?|S/N)\s*[:=]\s*(.+)$'}
        for key, pattern in patterns.items():
            match = re.search(pattern, output, re.I | re.M)
            if match: values[key] = match[1].strip()
        return values
    if device.vendor == 'unifi':
        output = read('cat /etc/board.info')
        board = dict(line.split('=', 1) for line in output.splitlines() if '=' in line)
        version = read('cat /etc/version')
        return {'model': board.get('board.name', ''), 'serial_number': board.get('board.serialno', ''),
                'software_version': version if re.search(r'\d+\.\d+', version) else ''}
    if device.vendor == 'grandstream_gcc':
        try: data = json.loads(read('ubus call system board'))
        except ValueError: return {}
        if not isinstance(data, dict) or not str(data.get('model', '')).upper().startswith(('GCC', 'GWN', 'GRANDSTREAM')): return {}
        return {'model': data.get('model'), 'serial_number': data.get('serial'), 'software_version': data.get('firmware_version')}
    return {}


def collect(device, source, connection):
    if source == 'SSH': return ssh_details(device, connection)
    if source == 'GDMS':
        from .gdms_api import discover_device
        return discover_device(connection, device.mac_address)
    if source == 'OPNsense API':
        details = opnsense_details(connection)
        if device.zenarmor_enabled:
            from .provisioning import _api_request
            try:
                zen = _api_request(connection, '/api/zenarmor/status/index')
                details['zenarmor_version'] = zen.get('version') or (zen.get('eastpect') or {}).get('version')
            except Exception: pass
            try:
                license = _api_request(connection, '/api/zenarmor/configuration/license_detail')
                if license.get('success') is True and str(license.get('license')).lower() in ('free', 'home', 'soho', 'business'):
                    details['zenarmor_edition'] = str(license['license']).capitalize()
            except Exception: pass
        return details
    if source == 'UniFi API':
        from .unifi_cloud import get_console_details, decrypt_api_key
        if not connection.remote_host_id: raise InventoryError('Selecciona primero la consola UniFi de este equipo.')
        return get_console_details(decrypt_api_key(connection.encrypted_api_key), connection.remote_host_id)
    if source == 'Hillstone API':
        from .hillstone_api import check_connection, decrypt
        return check_connection(connection.api_url, connection.username, decrypt(connection.encrypted_password), connection.ca_certificate)
    return {}


def refresh(device):
    device = Device.objects.select_related('site').get(pk=device.pk)
    source, connection = provider(device)
    before = signature(device)
    now = timezone.now()
    if device.inventory_checked_at and now - device.inventory_checked_at < timedelta(minutes=1):
        raise InventoryError('Espera un minuto entre consultas de inventario.')
    if not Device.objects.filter(pk=device.pk, inventory_checked_at=device.inventory_checked_at).update(inventory_checked_at=now):
        raise InventoryError('Ya hay otra consulta de inventario en curso.')
    values = {}
    sources = {}
    message = ''
    try:
        if not connection: raise InventoryError('Configura una conexión API o SSH para descubrir los datos.')
        details = collect(device, source, connection)
        sources = details.get('_sources', {})
        values = {key: clean(details.get(key)) for key in FIELDS if clean(details.get(key))}
        if not values: raise InventoryError('El equipo no ha facilitado datos de inventario compatibles. Revisa los permisos o el perfil de su versión.')
    except Exception as exc:
        from .gdms_api import GdmsError
        message = str(exc) if isinstance(exc, (InventoryError, GdmsError)) else 'No se pudo leer el inventario. Revisa acceso, permisos y compatibilidad del equipo.'
    with transaction.atomic():
        # Reserve the SQLite writer before reading the commit snapshot. Upgrading
        # a read transaction after a concurrent monitor write can fail instantly.
        if not Device.objects.filter(pk=device.pk, inventory_checked_at=now).update(inventory_checked_at=now):
            raise InventoryError('La consulta ha sido reemplazada por otra solicitud. Vuelve a comprobar.')
        current = Device.objects.select_for_update().select_related('site').get(pk=device.pk)
        if signature(current) != before:
            raise InventoryError('El equipo o su conexión ha cambiado durante la consulta. Repite la comprobación.')
        metadata = dict(current.inventory_metadata or {})
        field_info = dict(metadata.get('fields', {}))
        for key, value in values.items():
            setattr(current, key, value)
            field_info[key] = {'source': sources.get(key, source), 'checked_at': now.isoformat()}
        expected = ['model', 'software_version', 'serial_number']
        pending = [k for k in expected if k not in values]
        metadata.update({'fields': field_info, 'source': source, 'status': 'partial' if values and pending else 'ok' if values else 'pending',
                         'message': message or ('Hay datos que este acceso no facilita todavía.' if pending else ''), 'pending': pending})
        current.inventory_checked_at = now
        current.inventory_metadata = metadata
        current.save(update_fields=[*values, 'inventory_checked_at', 'inventory_metadata'])
    return current


def queue(device):
    Device.objects.filter(pk=device.pk).update(inventory_checked_at=None)


def refresh_due(limit=1):
    checked = 0
    for device in Device.objects.filter(active=True, site__active=True, site__client__active=True).exclude(integration='paused').order_by('inventory_checked_at', 'pk').select_related('site'):
        if device.inventory_checked_at and timezone.now() - device.inventory_checked_at < timedelta(hours=1): continue
        source, connection = provider(device)
        if not connection or not connection.last_ok: continue
        try: refresh(device)
        except (InventoryError, Device.DoesNotExist): pass
        checked += 1
        if checked >= limit: break
    return checked

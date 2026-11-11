"""Avisos de vulnerabilidad dirigidos: solo a los clientes cuyo firewall tiene una versión afectada.

1. **Catálogo** (`sync`): por cada producto vigilado se descargan de NVD sus CVE con los rangos de
   versiones afectadas, la gravedad CVSS y si CISA la marca como explotada activamente (KEV). Datos
   públicos: a NVD solo se envía el nombre del producto, nunca datos de clientes ni versiones de equipos.
   Una descarga incompleta no cuenta como actualizada (se repite en la siguiente pasada).
2. **Cruce** (`evaluate`): modelo y versión de cada firewall activo contra esos rangos. Solo cuentan las
   gravedades alta y crítica o las explotadas activamente. Si la versión no se puede comparar con
   seguridad, no se afirma nada: ni se abre ni se cierra.
3. **Revisión del SOC** (página «Vulnerabilidades»): publicar al cliente, con una nota, o descartar.
   Nada llega al cliente sin publicarlo (invariante 3).
4. **Cliente**: portal «Vulnerabilidades» y, si lo tiene activado, un correo sin datos técnicos que
   enlaza al portal. Se marca resuelta cuando el inventario muestra una versión corregida.
"""
import json
import os
import re
import time
from collections import defaultdict
from datetime import date, timedelta
from itertools import zip_longest
from urllib import error as url_error, request as url_request
from urllib.parse import urlencode

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.db import transaction
from django.http import HttpResponseForbidden
from django.shortcuts import redirect, render
from django.template.loader import render_to_string
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.views.decorators.cache import never_cache

from .models import Client, Device, DeviceExposure, OperationalIssue, VulnerabilityAdvisory, VulnerabilityRecord, WorkerState
from .security import audit

NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
PAGE = 2000
MAX_BYTES = 32 * 1024 * 1024
REFRESH = timedelta(hours=20)
STALE = timedelta(days=3)
BUDGET_SECONDS = 100
STATE = 'vulnerability-catalog'
ISSUE_REVIEW = 'vulnerabilities:review'
ISSUE_CATALOG = 'platform:vulnerability-catalog'
PRODUCT = re.compile(r'^[aoh]:[a-z0-9][a-z0-9._\-]{0,50}:[a-z0-9][a-z0-9._\-]{0,60}$')

# Consola UniFi (modelo que devuelve la nube de UniFi, normalizado) → producto en NVD. La versión que
# informa la consola es la de UniFi OS, la misma que usa NVD para estos productos.
UNIFI_MODELS = {
    'udmpromax': 'unifi_dream_machine_pro_max_firmware', 'udmpro': 'unifi_dream_machine_pro_firmware',
    'udmse': 'unifi_dream_machine_special_edition_firmware', 'udmspecialedition': 'unifi_dream_machine_special_edition_firmware',
    'udm': 'unifi_dream_machine_firmware', 'dreammachine': 'unifi_dream_machine_firmware',
    'udmbeast': 'unifi_dream_machine_beast_firmware', 'udr': 'unifi_dream_router_firmware', 'dreamrouter': 'unifi_dream_router_firmware',
    'udr7': 'unifi_dream_router_7_firmware', 'udr5gmax': 'unifi_dream_router_5g_max_firmware', 'udw': 'unifi_dream_wall_firmware',
    'ucgultra': 'unifi_cloud_gateway_ultra_firmware', 'ucgmax': 'unifi_cloud_gateway_max_firmware',
    'ucgfiber': 'unifi_cloud_gateway_fiber_firmware', 'ucgindustrial': 'unifi_cloud_gateway_industrial_firmware',
    'ux': 'unifi_express_firmware', 'express': 'unifi_express_firmware', 'ux7': 'unifi_express_7_firmware',
    'efg': 'enterprise_fortress_gateway_firmware', 'enterprisefortressgateway': 'enterprise_fortress_gateway_firmware',
}
SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, '': 4}
SEVERITY_LABEL = dict(VulnerabilityRecord.SEVERITIES)


class CatalogError(Exception):
    pass


class _NoRedirect(url_request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# --- Productos y versiones -------------------------------------------------------------------

def _model_key(model):
    return re.sub(r'[^a-z0-9]', '', str(model or '').lower())


def products_for(device):
    """Productos de NVD que describen el firewall. Vacío: el SOC no sabe cuál es (se indica en la página)."""
    if device.vulnerability_product:
        return [device.vulnerability_product] if PRODUCT.match(device.vulnerability_product) else []
    if device.vendor == 'opnsense':
        return ['a:opnsense:opnsense']
    if device.vendor == 'unifi':
        product = UNIFI_MODELS.get(_model_key(device.model))
        return ['o:ui:unifi_os'] + ([f'o:ui:{product}'] if product else [])
    return []


def _tokens(version):
    text = str(version or '').strip().lower()
    text = re.sub(r'^[^\d]*', '', text)  # «v4.1.13», «OPNsense 24.7»
    if not text:
        return None
    return [int(t) if t.isdigit() else t for t in re.findall(r'\d+|[a-z]+', text)]


def compare(a, b):
    """-1, 0 o 1; None si no se puede afirmar (formatos distintos). «24.7.5_1» > «24.7.5»."""
    ta, tb = _tokens(a), _tokens(b)
    if not ta or not tb:
        return None
    for x, y in zip_longest(ta, tb, fillvalue=0):
        if type(x) is not type(y):
            return None
        if x != y:
            return -1 if x < y else 1
    return 0


def in_range(version, rng):
    exact = rng.get('version', '*')
    if exact not in ('*', '-', ''):
        result = compare(version, exact)
        return None if result is None else result == 0
    if exact == '-':
        return None
    checks = [('si', lambda c: c >= 0), ('se', lambda c: c > 0), ('ei', lambda c: c <= 0), ('ee', lambda c: c < 0)]
    unknown = False
    for key, test in checks:
        if rng.get(key):
            result = compare(version, rng[key])
            if result is None:
                unknown = True
            elif not test(result):
                return False
    return None if unknown else True


def affects(record, version):
    results = [in_range(version, rng) for rng in record.ranges]
    if True in results:
        return True
    return None if None in results or not results else False


# --- Catálogo NVD ----------------------------------------------------------------------------

def _api_key():
    return os.environ.get('SOC_PORTAL_NVD_KEY', '').strip()


def _fetch(params):
    headers = {'Accept': 'application/json', 'User-Agent': 'ib-red-centro-soc/1'}
    if _api_key():
        headers['apiKey'] = _api_key()
    req = url_request.Request(NVD_URL + '?' + urlencode(params), headers=headers)
    try:
        with url_request.build_opener(_NoRedirect()).open(req, timeout=60) as response:
            raw = response.read(MAX_BYTES + 1)
    except url_error.HTTPError as exc:
        raise CatalogError(f'NVD respondió HTTP {exc.code}.') from None
    except (url_error.URLError, TimeoutError, OSError):
        raise CatalogError('No se pudo conectar con NVD.') from None
    if len(raw) > MAX_BYTES:
        raise CatalogError('Respuesta de NVD demasiado grande.')
    try:
        data = json.loads(raw)
    except ValueError:
        raise CatalogError('NVD devolvió datos no válidos.') from None
    if not isinstance(data, dict) or not isinstance(data.get('vulnerabilities'), list) or not isinstance(data.get('totalResults'), int):
        raise CatalogError('NVD devolvió datos inesperados.')
    return data


def _metric(cve):
    metrics = cve.get('metrics') or {}
    for key in ('cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
        rows = [m for m in metrics.get(key) or [] if isinstance(m, dict)]
        rows.sort(key=lambda m: m.get('type') != 'Primary')
        for row in rows:
            data = row.get('cvssData') or {}
            severity = str(data.get('baseSeverity') or row.get('baseSeverity') or '').upper()
            score = data.get('baseScore')
            if severity in SEVERITY_ORDER:
                return severity, float(score) if isinstance(score, (int, float)) else None
    return '', None


def _date(value):
    try:
        return date.fromisoformat(str(value)[:10]) if value else None
    except ValueError:
        return None


def parse(item, product):
    """Lo que interesa de una CVE para el producto, o None si no aplica (rechazada o sin rangos)."""
    cve = item.get('cve') if isinstance(item, dict) else None
    if not isinstance(cve, dict) or not re.match(r'^CVE-\d{4}-\d{4,}$', str(cve.get('id', ''))):
        return None
    if str(cve.get('vulnStatus', '')).lower() == 'rejected':
        return None
    ranges = []
    for conf in cve.get('configurations') or []:
        for node in (conf or {}).get('nodes') or []:
            for match in (node or {}).get('cpeMatch') or []:
                parts = str((match or {}).get('criteria', '')).split(':')
                if not match.get('vulnerable') or len(parts) < 6 or ':'.join(parts[2:5]) != product:
                    continue
                rng = {'version': parts[5][:60]}
                for key, field in (('si', 'versionStartIncluding'), ('se', 'versionStartExcluding'),
                                   ('ei', 'versionEndIncluding'), ('ee', 'versionEndExcluding')):
                    if match.get(field):
                        rng[key] = str(match[field])[:60]
                if rng not in ranges:
                    ranges.append(rng)
    if not ranges:
        return None
    severity, score = _metric(cve)
    fixes = [r['ee'] for r in ranges if r.get('ee')]
    fixed = ''
    for value in fixes:
        if not fixed or compare(value, fixed) == 1:
            fixed = value
    if not fixed:
        last = [r['ei'] for r in ranges if r.get('ei')]
        fixed = f'posterior a {last[-1]}' if last else ''
    summary = next((d.get('value', '') for d in cve.get('descriptions') or [] if d.get('lang') == 'en'), '')
    references = []
    for ref in cve.get('references') or []:
        url = str((ref or {}).get('url', ''))
        if url.startswith('https://') and set(ref.get('tags') or []) & {'Vendor Advisory', 'Patch', 'Release Notes'} and url not in references:
            references.append(url[:300])
    return {'cve_id': cve['id'], 'severity': severity, 'score': score, 'kev_added': _date(cve.get('cisaExploitAdd')),
            'published': _date(cve.get('published')), 'modified': parse_datetime(str(cve.get('lastModified') or '') + 'Z'),
            'summary': re.sub(r'[\x00-\x1f\x7f]+', ' ', str(summary))[:1000], 'ranges': ranges[:50],
            'fixed_version': fixed[:60], 'references': references[:5]}


def fetch_product(product, pause=0):
    """Todas las CVE del producto, o CatalogError si alguna página falla: no se guarda una lista a medias."""
    items, start = [], 0
    while True:
        data = _fetch({'virtualMatchString': 'cpe:2.3:' + product, 'resultsPerPage': PAGE, 'startIndex': start})
        items += data['vulnerabilities']
        start += len(data['vulnerabilities'])
        if start >= data['totalResults'] or not data['vulnerabilities']:
            return [row for row in (parse(item, product) for item in items) if row]
        if start > 20000:
            raise CatalogError('El producto tiene demasiadas CVE para vigilarlo así.')
        time.sleep(pause)


def watched_products():
    products = set()
    for device in Device._base_manager.filter(active=True):
        products.update(products_for(device))
    return sorted(products)


def sync(now=None, budget=BUDGET_SECONDS):
    """Actualiza los productos más antiguos dentro del tiempo disponible. Devuelve los actualizados."""
    now = now or timezone.now()
    state, _ = WorkerState.objects.get_or_create(name=STATE)
    synced = dict((state.details or {}).get('products') or {})
    pause = 0.8 if _api_key() else 6.5  # límites públicos de NVD: 50 o 5 peticiones cada 30 s
    started, done, errors = time.monotonic(), 0, []
    synced = {p: stamp for p, stamp in synced.items() if isinstance(stamp, str) and parse_datetime(stamp)}
    pending = [p for p in watched_products() if not synced.get(p) or now - parse_datetime(synced[p]) > REFRESH]
    pending.sort(key=lambda p: synced.get(p, ''))
    for product in pending:
        if done and time.monotonic() - started > budget:
            break
        if done:
            time.sleep(pause)
        try:
            rows = fetch_product(product, pause)
        except CatalogError as exc:
            errors.append(f'{product}: {exc}')
            continue
        with transaction.atomic():
            for row in rows:
                VulnerabilityRecord.objects.update_or_create(cve_id=row['cve_id'], product=product,
                                                             defaults={**row, 'fetched_at': now})
        synced[product] = now.isoformat()
        done += 1
    state.last_run_at = now
    state.error = '; '.join(errors)[:500]
    state.details = {**(state.details or {}), 'products': synced}
    state.save()
    oldest = min((parse_datetime(synced[p]) for p in watched_products() if synced.get(p)), default=None)
    if errors and (not oldest or now - oldest > STALE):
        from .operations import set_issue
        set_issue(ISSUE_CATALOG, 'No se actualiza el catálogo de vulnerabilidades',
                  details='Los avisos de vulnerabilidad se basan en datos de más de tres días. ' + state.error[:200], now=now)
    elif not errors:
        OperationalIssue.objects.filter(key=ISSUE_CATALOG, active=True).update(active=False, resolved_at=now)
    return done


def catalog_status():
    state = WorkerState.objects.filter(name=STATE).first()
    synced = (state.details or {}).get('products', {}) if state else {}
    products = watched_products()
    dates = [parse_datetime(synced[p]) for p in products if synced.get(p)]
    return {'products': products, 'synced': len(dates), 'oldest': min(dates) if dates else None,
            'error': state.error if state else '', 'records': VulnerabilityRecord.objects.filter(product__in=products).count(),
            'key': bool(_api_key())}


# --- Cruce con los firewalls -----------------------------------------------------------------

def evaluate(now=None):
    """Abre, mantiene o resuelve exposiciones según la versión actual. Devuelve cuántas abrió."""
    now = now or timezone.now()
    opened = 0
    records = defaultdict(list)
    for record in VulnerabilityRecord.objects.all():
        if record.relevant:
            records[record.product].append(record)
    existing, by_device = {}, defaultdict(list)
    for e in DeviceExposure._base_manager.select_related('record'):
        existing[(e.device_id, e.record_id)] = e
        by_device[e.device_id].append(e)
    for device in Device._base_manager.filter(active=True).select_related('site'):
        products = products_for(device)
        version = device.software_version.strip()
        for exposure in by_device.get(device.pk, []):
            if exposure.resolved_at is None and exposure.record.product not in products:
                exposure.resolved_at, exposure.resolved_version = now, version or 'otro modelo'
                exposure.save(update_fields=['resolved_at', 'resolved_version'])
        if not version:
            continue
        for product in products:
            for record in records.get(product, []):
                result = affects(record, version)
                exposure = existing.get((device.pk, record.pk))
                if result is True:
                    if exposure is None:
                        DeviceExposure._base_manager.create(client_id=device.site.client_id, device=device, record=record,
                                                            version=version[:120], first_seen=now, last_seen=now)
                        opened += 1
                    else:
                        exposure.last_seen, exposure.version = now, version[:120]
                        fields = ['last_seen', 'version']
                        if exposure.resolved_at:
                            exposure.resolved_at, exposure.resolved_version = None, ''  # volvió a una versión afectada
                            fields += ['resolved_at', 'resolved_version']
                        exposure.save(update_fields=fields)
                elif result is False and exposure is not None and exposure.resolved_at is None:
                    exposure.resolved_at, exposure.resolved_version = now, version[:120]
                    exposure.save(update_fields=['resolved_at', 'resolved_version'])
    pending = DeviceExposure._base_manager.filter(resolved_at__isnull=True, dismissed_at__isnull=True, advisory__isnull=True,
                                                  device__active=True).values('device').distinct().count()
    if pending:
        from .operations import set_issue
        kev = DeviceExposure._base_manager.filter(resolved_at__isnull=True, dismissed_at__isnull=True, advisory__isnull=True,
                                                  record__kev_added__isnull=False).exists()
        set_issue(ISSUE_REVIEW, f'Vulnerabilidades sin revisar en {pending} firewall' + ('s' if pending != 1 else ''),
                  details='Revisar en «Vulnerabilidades»: publicar al cliente o descartar.', severity='critical' if kev else 'warning', now=now)
    else:
        OperationalIssue.objects.filter(key=ISSUE_REVIEW, active=True).update(active=False, resolved_at=now)
    return opened


def run(now=None):
    now = now or timezone.now()
    error = None
    try:
        sync(now)
    except Exception as exc:  # el cruce sigue con el catálogo que ya hay
        error = exc
    opened = evaluate(now)
    if error:
        raise error
    return opened


def open_by_device(device_ids):
    """{firewall: 'published' | 'review'} con vulnerabilidades altas, críticas o explotadas sin resolver ni
    descartar. Lo publicado manda: el índice del cliente solo cuenta lo que el SOC le ha comunicado."""
    states = {}
    for device_id, advisory_id in DeviceExposure._base_manager.filter(
            device_id__in=device_ids, resolved_at__isnull=True, dismissed_at__isnull=True).values_list('device_id', 'advisory_id'):
        if advisory_id or device_id not in states:
            states[device_id] = 'published' if advisory_id else 'review'
    return states


def catalog_fresh(device, now=None):
    now = now or timezone.now()
    state = WorkerState.objects.filter(name=STATE).first()
    synced = (state.details or {}).get('products', {}) if state else {}
    products = products_for(device)
    return bool(products) and all(synced.get(p) and now - parse_datetime(synced[p]) <= STALE for p in products)


# --- Publicación y correo --------------------------------------------------------------------

def recipient(client):
    for value in (client.vulnerability_email, client.contact_email, client.report_email):
        try:
            validate_email(value)
            return value
        except ValidationError:
            continue
    return ''


def publish(client, cve_id, note, user, now=None):
    now = now or timezone.now()
    exposures = DeviceExposure._base_manager.filter(client=client, record__cve_id=cve_id, resolved_at__isnull=True,
                                                    dismissed_at__isnull=True, device__active=True)
    if not exposures.exists():
        return None, 0
    with transaction.atomic():
        advisory, created = VulnerabilityAdvisory._base_manager.get_or_create(
            client=client, cve_id=cve_id, defaults={'note': note, 'published_at': now, 'published_by': user})
        if not created:
            advisory.note = note
            advisory.save(update_fields=['note'])
        count = exposures.filter(advisory__isnull=True).update(advisory=advisory)
        address = recipient(client)
        if created and client.vulnerability_notices_enabled and address:
            advisory.notice_status, advisory.notice_recipient = 'queued', address
            advisory.save(update_fields=['notice_status', 'notice_recipient'])
    return advisory, count


def portal_url():
    from django.urls import reverse
    from .invitations import origin
    return origin() + reverse('customer_vulnerabilities')


def send_pending(limit=5, now=None):
    """Un correo por cliente con todos sus avisos en cola: varias CVE del mismo firewall no son varios correos."""
    from .mail_delivery import MailConfigurationError, MailDeliveryError, send_customer_email
    now = now or timezone.now()
    manager = VulnerabilityAdvisory._base_manager
    manager.filter(notice_status='sending', notice_attempted_at__lt=now - timedelta(minutes=10)).update(
        notice_status='uncertain', notice_error='El envío se interrumpió; comprobar en «Entrega y avisos» antes de reenviar.')
    sent = 0
    clients = list(manager.filter(notice_status='queued').order_by('client_id').values_list('client_id', flat=True).distinct()[:limit])
    for client in Client._base_manager.filter(pk__in=clients):
        queued = list(manager.filter(client=client, notice_status='queued'))
        rows, ready = [], []
        for advisory in queued:
            open_rows = list(advisory.exposures.filter(resolved_at__isnull=True, dismissed_at__isnull=True).select_related('record'))
            if client.active and client.vulnerability_notices_enabled and open_rows:
                ready.append(advisory)
                rows += open_rows
            else:
                manager.filter(pk=advisory.pk, notice_status='queued').update(notice_status='skipped',
                                                                             notice_error='Ya no aplica: resuelta o aviso desactivado.')
        if not ready:
            continue
        ids = [a.pk for a in ready]
        if manager.filter(pk__in=ids, notice_status='queued').update(notice_status='sending', notice_attempted_at=now) != len(ids):
            manager.filter(pk__in=ids, notice_status='sending', notice_attempted_at=now).update(notice_status='queued')
            continue  # otro proceso tomó alguno: se repite entero en la siguiente pasada
        record = min((e.record for e in rows), key=lambda r: SEVERITY_ORDER.get(r.severity, 9))
        context = {'client': client, 'severity': SEVERITY_LABEL.get(record.severity, '').lower(), 'count': len(ready),
                   'kev': any(e.record.kev_added for e in rows), 'devices': len({e.device_id for e in rows}), 'url': portal_url()}
        try:
            from .invitations import origin
            context['logo_url'] = origin() + '/static/brand/ibred-empresas-color.png'
            provider = send_customer_email(ready[0].notice_recipient, 'Aviso de vulnerabilidad · ib-red empresas',
                                           render_to_string('vulnerability_email.txt', context),
                                           render_to_string('vulnerability_email.html', context),
                                           delivery_context={'client': client, 'kind': 'vulnerability'})
        except MailConfigurationError:
            manager.filter(pk__in=ids).update(notice_status='failed', notice_error='El correo del SOC no está configurado y probado.')
        except MailDeliveryError:
            manager.filter(pk__in=ids).update(notice_status='uncertain', notice_error='SendGrid no confirmó la aceptación.')
        except Exception:
            manager.filter(pk__in=ids).update(notice_status='failed', notice_error='No se pudo preparar el aviso.')
        else:
            manager.filter(pk__in=ids).update(notice_status='accepted', notice_sent_at=now, provider_id=str(provider)[:180], notice_error='')
            sent += 1
    return sent


# --- Lo que ve el cliente --------------------------------------------------------------------

def portal_context(client):
    """Solo lo publicado y, de cada aviso, los firewalls del propio cliente. Agrupado por firewall: qué
    versión tiene, a cuál actualizar y qué vulnerabilidades corrige."""
    firewalls = {}
    rows = (DeviceExposure.objects.filter(client=client, advisory__client=client, dismissed_at__isnull=True)
            .select_related('device__site', 'record', 'advisory').order_by('device__name'))
    for e in rows:
        fw = firewalls.setdefault(e.device_id, {'name': e.device.name, 'site': e.device.site.name, 'version': e.version,
                                                'items': {}, 'notes': [], 'resolved_version': ''})
        item = fw['items'].get(e.record.cve_id)
        if item is None or SEVERITY_ORDER.get(e.record.severity, 9) < SEVERITY_ORDER.get(item['severity'], 9):
            fw['items'][e.record.cve_id] = item = {
                'cve_id': e.record.cve_id, 'severity': e.record.severity, 'severity_label': SEVERITY_LABEL.get(e.record.severity, ''),
                'score': e.record.score, 'kev': bool(e.record.kev_added), 'fixed': e.record.fixed_version,
                'published_at': e.advisory.published_at, 'resolved_at': e.resolved_at,
                'nvd_url': f'https://nvd.nist.gov/vuln/detail/{e.record.cve_id}'}
        if e.resolved_at is None:  # con dos productos, basta uno abierto para que siga pendiente
            item['resolved_at'] = None
            fw['version'] = e.version
        elif not fw['resolved_version'] or (e.resolved_at and e.resolved_version):
            fw['resolved_version'] = e.resolved_version
        if e.advisory.note and e.advisory.note not in fw['notes']:
            fw['notes'].append(e.advisory.note)
    result = []
    for fw in firewalls.values():
        items = sorted(fw['items'].values(), key=lambda i: (i['resolved_at'] is not None, SEVERITY_ORDER.get(i['severity'], 9), i['cve_id']))
        pending = [i for i in items if i['resolved_at'] is None]
        target = ''
        for i in pending:
            if i['fixed'] and not i['fixed'].startswith('posterior') and (not target or compare(i['fixed'], target) == 1):
                target = i['fixed']
        result.append({**fw, 'items': items, 'open': bool(pending), 'pending': len(pending), 'kev': any(i['kev'] for i in pending),
                       'severity': pending[0]['severity'] if pending else '', 'target': target,
                       'unknown_fix': any(not i['fixed'] or i['fixed'].startswith('posterior') for i in pending)})
    result.sort(key=lambda f: (not f['open'], not f['kev'], SEVERITY_ORDER.get(f['severity'], 9), f['name']))
    return {'firewalls': result, 'open_firewalls': sum(1 for f in result if f['open'])}


def open_count(client):
    """Firewalls del cliente con alguna vulnerabilidad publicada y sin corregir."""
    return (DeviceExposure.objects.filter(client=client, advisory__client=client, resolved_at__isnull=True, dismissed_at__isnull=True)
            .values('device').distinct().count())


# --- Página del SOC --------------------------------------------------------------------------

def groups(state='open'):
    """Exposiciones agrupadas por cliente y CVE, como se publican."""
    rows = DeviceExposure.objects.select_related('client', 'device__site', 'record', 'advisory').filter(device__active=True)
    if state == 'open':
        rows = rows.filter(resolved_at__isnull=True, dismissed_at__isnull=True)
    result = {}
    for e in rows:
        group = result.setdefault((e.client_id, e.record.cve_id), {'client': e.client, 'cve_id': e.record.cve_id, 'records': {},
                                                                   'exposures': [], 'advisory': None})
        group['records'][e.record.pk] = e.record
        group['exposures'].append(e)
        group['advisory'] = group['advisory'] or e.advisory
    for group in result.values():
        records = list(group['records'].values())
        group['record'] = min(records, key=lambda r: SEVERITY_ORDER.get(r.severity, 9))
        group['kev'] = any(r.kev_added for r in records)
        group['unpublished'] = sum(1 for e in group['exposures'] if e.open and e.advisory_id is None)
        group['open'] = any(e.open for e in group['exposures'])
        group['dismissed'] = all(e.dismissed_at for e in group['exposures'])
    by_client = {}
    for group in sorted(result.values(), key=lambda g: (not g['open'], not g['unpublished'], not g['kev'],
                                                         SEVERITY_ORDER.get(g['record'].severity, 9), g['cve_id'])):
        item = by_client.setdefault(group['client'].pk, {'client': group['client'], 'groups': [], 'unpublished': 0, 'kev': False})
        item['groups'].append(group)
        item['unpublished'] += 1 if group['unpublished'] else 0
        item['kev'] = item['kev'] or (group['kev'] and group['open'])
    return sorted(by_client.values(), key=lambda c: (not c['unpublished'], not c['kev'], c['client'].name))


def unmapped():
    """Firewalls activos que no se pueden vigilar: sin producto conocido o sin versión."""
    rows = []
    for device in Device.objects.filter(active=True).select_related('site__client').order_by('site__client__name', 'name'):
        products = products_for(device)
        if not products or not device.software_version.strip():
            rows.append({'device': device, 'products': products,
                         'reason': 'Sin versión en el inventario' if products else 'Sin producto conocido en NVD'})
    return rows


@login_required
@never_cache
def overview(request):
    if request.method == 'POST':
        action = request.POST.get('action', '')
        if action == 'publish_client':
            if not request.user.has_perm('core.change_incident'):
                return HttpResponseForbidden('Tu cuenta no tiene permiso para publicar vulnerabilidades.')
            client = Client.objects.filter(pk=request.POST.get('client', '0') if request.POST.get('client', '').isdigit() else 0).first()
            if not client:
                messages.error(request, 'Cliente no válido.')
                return redirect('vulnerabilities')
            note = request.POST.get('note', '').strip()[:1500]
            cves = sorted(set(DeviceExposure.objects.filter(client=client, resolved_at__isnull=True, dismissed_at__isnull=True,
                                                            advisory__isnull=True, device__active=True)
                              .values_list('record__cve_id', flat=True)))
            total = 0
            for cve_id in cves:
                total += publish(client, cve_id, note, request.user)[1]
            audit('vulnerability.publish', client, {'status': f'{len(cves)} CVE', 'count': total})
            messages.success(request, f'{len(cves)} vulnerabilidad{"es" if len(cves) != 1 else ""} publicada{"s" if len(cves) != 1 else ""} '
                             f'en el portal de {client.name}.' + (' El correo sale en el próximo minuto.' if client.vulnerability_notices_enabled else ''))
            return redirect('vulnerabilities')
        if action in ('publish', 'dismiss'):
            if not request.user.has_perm('core.change_incident'):
                return HttpResponseForbidden('Tu cuenta no tiene permiso para publicar o descartar vulnerabilidades.')
            client = Client.objects.filter(pk=request.POST.get('client', '0') if request.POST.get('client', '').isdigit() else 0).first()
            cve_id = request.POST.get('cve', '')
            if not client or not re.match(r'^CVE-\d{4}-\d{4,}$', cve_id):
                messages.error(request, 'Aviso no válido.')
                return redirect('vulnerabilities')
            if action == 'publish':
                note = request.POST.get('note', '').strip()[:1500]
                advisory, count = publish(client, cve_id, note, request.user)
                if advisory is None:
                    messages.error(request, 'Ya no hay firewalls afectados sin resolver: no hay nada que publicar.')
                else:
                    audit('vulnerability.publish', client, {'status': cve_id, 'count': count})
                    messages.success(request, f'{cve_id} publicada en el portal de {client.name}.'
                                     + (' El correo sale en el próximo minuto.' if advisory.notice_status == 'queued' else ''))
            else:
                reason = request.POST.get('reason', '').strip()[:240]
                if not reason:
                    messages.error(request, 'Indica por qué se descarta (uso interno).')
                    return redirect('vulnerabilities')
                count = DeviceExposure.objects.filter(client=client, record__cve_id=cve_id, resolved_at__isnull=True,
                                                      dismissed_at__isnull=True).update(
                    dismissed_at=timezone.now(), dismissed_by=request.user, dismiss_reason=reason)
                audit('vulnerability.dismiss', client, {'status': cve_id, 'count': count, 'reason': reason})
                messages.success(request, f'{cve_id} descartada para {client.name}. El cliente no la verá.')
            return redirect('vulnerabilities')
        if action == 'product':
            if not request.user.has_perm('core.change_device'):
                return HttpResponseForbidden('Tu cuenta no tiene permiso para cambiar equipos.')
            device = Device.objects.filter(pk=request.POST.get('device', '0') if request.POST.get('device', '').isdigit() else 0).first()
            value = request.POST.get('product', '').strip().lower()
            value = value[len('cpe:2.3:'):] if value.startswith('cpe:2.3:') else value
            value = ':'.join(value.split(':')[:3])
            if not device or (value and not PRODUCT.match(value)):
                messages.error(request, 'Indica el producto como parte:fabricante:producto, p. ej. o:hillstonenet:sc-6000-e3960_firmware.')
                return redirect('vulnerabilities')
            device.vulnerability_product = value
            device.save(update_fields=['vulnerability_product'])
            audit('device.update', device, {'fields': ['vulnerability_product']})
            messages.success(request, 'Producto guardado. El catálogo se descarga en la próxima pasada (cada hora).')
            return redirect('vulnerabilities')
        return HttpResponseForbidden('Acción no válida.')
    state = 'all' if request.GET.get('state') == 'all' else 'open'
    return render(request, 'vulnerabilities.html', {
        'clients': groups(state), 'state': state, 'unmapped': unmapped(), 'catalog': catalog_status(),
        'severity_label': SEVERITY_LABEL,
    })

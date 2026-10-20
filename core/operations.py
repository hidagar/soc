"""Vendor-neutral evidence and operational health. Never configure remote devices."""
import hashlib
import ipaddress
import json
import re
import socket
import ssl
import subprocess
from collections import defaultdict
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlsplit
from django.db import transaction
from django.db.models import F
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from .models import (Asset, Device, DeviceFeed, DeviceHealth, ExportConfiguration,
    FeedBucket, OperationalIssue, RecoverySettings, SecurityEvidence, WorkerState)

def clean(value, length=240):
    return re.sub(r'[\x00-\x1f\x7f]+',' ',str(value or '')).strip()[:length]

def ip(value):
    try:
        return str(ipaddress.ip_address(value))
    except (ValueError, TypeError):
        return None

def private(value):
    try:
        address = ipaddress.ip_address(value)
        networks=('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','fc00::/7')
        return any(address in ipaddress.ip_network(n) for n in networks if ipaddress.ip_network(n).version==address.version)
    except (ValueError, TypeError):
        return False

def normalize(source):
    data = source.get('data') if isinstance(source.get('data'),dict) else {}
    rule = source.get('rule') if isinstance(source.get('rule'),dict) else {}
    decoder_data = source.get('decoder') if isinstance(source.get('decoder'),dict) else {}
    decoder = decoder_data.get('name','')
    groups = rule.get('groups') if isinstance(rule.get('groups'),list) else []
    from .event_contract import normalize_action, metadata
    vendor_severity = ''
    engine = 'system'
    security = False
    category = ''
    signature = clean(rule.get('description'))
    action = 'unknown'
    src, dst, port = ip(data.get('srcip')), ip(data.get('dstip')), clean(data.get('dstport'),16)
    if 'unifi' in data or str(decoder).startswith('unifi'):
        engine = 'unifi'
        u = data.get('unifi') if isinstance(data.get('unifi'),dict) else {}
        category = clean(u.get('category'),80)
        security = category.lower() == 'security'
        signature = clean(u.get('ips_signature') or u.get('event_name') or signature)
        value = str(u.get('action','')).lower()
        action = normalize_action(engine, value)
        vendor_severity = u.get('risk', '')
    elif str(decoder).startswith('soc-hillstone') or str(decoder)=='hillstone':
        engine='hillstone'
        h=data.get('hillstone') if isinstance(data.get('hillstone'),dict) else {}
        # Event@SECURITY and AV signature updates are administrative activity.
        # Only the explicit Threat category establishes a security detection.
        security=str(h.get('category','')).casefold()=='threat'
        category=clean(h.get('code'),80) if security else ''
        signature=clean(h.get('message') or signature) if security else signature
        if security:
            value=str(data.get('action','')).lower()
            from .hillstone_events import flow as hillstone_flow,action as hillstone_action
            parsed=hillstone_flow(data)
            action=hillstone_action(value)
            if parsed:
                src,dst,port=parsed['src'],parsed['dst'],str(int(parsed['dport']))
                category=clean(parsed['type']+' / '+parsed['subtype'],80)
                signature=clean(parsed['signature'])
                action=hillstone_action(parsed['action'])
                vendor_severity = parsed['severity']
    elif str(decoder).startswith('zenarmor') or 'zenarmor' in groups:
        engine = 'zenarmor'
        src, dst = ip(data.get('ip_src_saddr')), ip(data.get('ip_dst_saddr'))
        port = clean(data.get('ip_dst_port') or data.get('dst_port') or data.get('dstport'),16)
        tags = data.get('security_tags') or []
        if isinstance(tags, str):
            try:
                tags = json.loads(tags)
            except ValueError:
                tags = [tags]
        if not isinstance(tags, list):
            tags = [str(tags)]
        tags=[str(t).strip() for t in tags if re.search('[a-zA-Z]',str(t))]
        category = clean(', '.join(str(t) for t in tags),80)
        is_blocked = normalize_action(engine,data.get('is_blocked')) == 'blocked'
        security = bool(tags) or 'zenarmor_security' in groups
        if not security and is_blocked:
            category = 'application_policy'
            security = True  # kept as evidence, excluded from threat counters
        signature = clean(data.get('threat_name') or data.get('security_category') or category or signature)
        action = normalize_action(engine, data.get('is_blocked'))
    elif str(decoder).lower() in ('clamd','freshclam','clamav'):
        engine = 'clamav'
        # Wazuh's virus group also contains restarts and updater errors. Only its
        # actual detection rules establish a malware observation; no inferred block.
        security = str(rule.get('id')) in ('52502','52511')
        category = 'malware' if security else ''
    elif data.get('event_type') == 'alert' or 'suricata' in str(decoder).lower():
        engine = 'suricata'
        alert = data.get('alert') if isinstance(data.get('alert'),dict) else {}
        security = bool(alert) or data.get('event_type') == 'alert'
        category = clean(alert.get('category'),80)
        signature = clean(alert.get('signature') or signature)
        src, dst = ip(data.get('src_ip') or src), ip(data.get('dest_ip') or dst)
        port = clean(data.get('dest_port') or port,16)
        value = str(alert.get('action','')).lower()
        action = normalize_action(engine, value)
        vendor_severity = alert.get('severity', '')
    try:
        level = max(0,min(65535,int(rule.get('level') or 0)))
    except (ValueError,TypeError):
        level = 0
    event = {'engine':engine,'security':security,'category':category,'signature':signature,
            'action':action,'source_ip':src,'destination_ip':dst,'destination_port':port,
            'level':level,'affected_ip':src if private(src) else dst if private(dst) else None}
    event.update(metadata(event, vendor_severity))
    return event

def source_map():
    grouped = defaultdict(list)
    for row in ExportConfiguration.objects.filter(device__active=True,device__site__active=True,
             device__site__client__active=True,receiver_ready=True,source_ip__isnull=False).select_related('device__site__client'):
        grouped[row.source_ip].append(row.device)
    from .secure_logs import active_channels
    for channel in active_channels().filter(receiver_ready=True).select_related('device__site__client'):
        if not any(d.pk==channel.device_id for d in grouped[channel.source_identity]):grouped[channel.source_identity].append(channel.device)
    unique, conflicts = {}, []
    for source, devices in grouped.items():
        if len(devices) == 1:
            unique[source] = devices[0]
        else:
            conflicts.extend(devices)
    return unique, conflicts

def recommendation(event):
    from .event_contract import recommendation as explain
    return explain(event)

@transaction.atomic
def ingest_events(events, now=None):
    now = now or timezone.now()
    owners, conflicts = source_map()
    OperationalIssue.objects.filter(key__endswith=':source-conflict',active=True).exclude(device__in=conflicts).update(active=False,resolved_at=now,checked_at=now)
    accepted = 0
    for device in conflicts:
        set_issue(f'device:{device.pk}:source-conflict','IP de origen compartida: atribución suspendida',device, severity='critical',now=now)
    for source in events:
        if not isinstance(source,dict):
            continue
        delivery=None
        if str(source.get('location','')).startswith('127.80.'):
            from .wazuh_delivery import identify,canonical
            delivery=identify(source)
            if delivery:
                if delivery.projected_at:continue
                source=canonical(source,delivery)
        device = owners.get(ip(source.get('location')))
        if device is None:
            agent_data=source.get('agent') if isinstance(source.get('agent'),dict) else {}
            agent = str(agent_data.get('id') or '')
            if agent and agent != '000':
                candidates = list(Device.objects.filter(active=True,log_method='wazuh_agent',wazuh_identifier=agent)[:2])
                device = candidates[0] if len(candidates) == 1 else None
        if device is None:
            continue
        try: stamp = parse_datetime(str(source.get('timestamp') or ''))
        except (ValueError,OverflowError): continue
        if stamp is None or timezone.is_naive(stamp) or stamp > now+timedelta(minutes=5) or stamp < now-timedelta(days=90):
            continue
        from .source_ownership import owns_at
        if ip(source.get('location')) in owners and not owns_at(ip(source.get('location')),device.site.client_id,stamp):
            continue
        from .vpn import record_log_transport
        record_log_transport(device,ip(source.get('location')),stamp,now)
        from .vpn_security import record as record_vpn_access
        record_vpn_access(source,device,stamp)
        event = normalize(source)
        if delivery:
            # Persist deduplication for every relayed native alert, including
            # non-security activity. The surrounding transaction includes feeds.
            from .models import SecureLogMessage
            SecureLogMessage.objects.filter(pk=delivery.pk).update(projected_at=now)
        identifier = str(source.get('id') or '')
        identity = json.dumps([device.pk,identifier,stamp.isoformat(),event],sort_keys=True)
        uid = hashlib.sha256(identity.encode()).hexdigest()
        # The local stream and indexer reconciliation can contain the same alert.
        # A replay must not inflate feed counters, coverage or incident occurrences.
        if event['security']:
            if SecurityEvidence.objects.filter(uid=uid).exists():continue
            # Older hashes included normalized fields. Parser improvements must
            # not duplicate an already stored physical Wazuh event.
            if identifier and SecurityEvidence.objects.filter(device=device,wazuh_id=identifier,observed_at=stamp).exists():continue
        feed, _ = DeviceFeed.objects.get_or_create(device=device,kind=event['engine'])
        feed.first_seen_at = min(feed.first_seen_at or stamp, stamp)
        feed.last_seen_at = max(feed.last_seen_at or stamp, stamp)
        if event['security'] and event['category'] != 'application_policy':
            feed.security_at = max(feed.security_at or stamp,stamp)
        feed.event_count += 1
        feed.save()
        hour = stamp.replace(minute=0,second=0,microsecond=0)
        bucket, _ = FeedBucket.objects.get_or_create(device=device,kind=event['engine'],hour=hour)
        FeedBucket.objects.filter(pk=bucket.pk).update(event_count=F('event_count')+1)
        health, _ = DeviceHealth.objects.get_or_create(device=device)
        if not health.last_log_at or stamp > health.last_log_at:
            health.last_log_at = stamp
            health.save(update_fields=['last_log_at','updated_at'])
        accepted += 1
        if not event['security']:
            continue
        asset = None
        if event['affected_ip']:
            asset, _ = Asset.objects.get_or_create(device=device,ip=event['affected_ip'])
            asset.last_seen_at = max(asset.last_seen_at,stamp)
            asset.save(update_fields=['last_seen_at'])
        from .event_contract import snapshot
        from .asset_identity import identity_snapshot
        from .asset_context import flow_projection
        values = {k:event[k] for k in ('engine','category','signature','action','source_ip','destination_ip','destination_port','level')}
        evidence, created = SecurityEvidence.objects.get_or_create(uid=uid,defaults={
            **values,'device':device,'asset':asset,'observed_at':stamp,'wazuh_id':clean(identifier,180),'client_scope_id':device.site.client_id,
            'recommendation':recommendation(event),'identity':identity_snapshot(asset,stamp),'flow':flow_projection(source),'interpretation':{**snapshot(event,device),'source_identity':ip(source.get('location'))}})
        if not created:
            continue
        if event['category'] != 'application_policy':
            health.security_verified_at = max(health.security_verified_at or stamp,stamp)
            health.security_evidence_uid = uid
            health.save(update_fields=['security_verified_at','security_evidence_uid','updated_at'])
        from .incident_episodes import attach_episode
        attach_episode(evidence,event)
    return accepted

def set_issue(key,title,device=None,details='',severity='warning',now=None):
    now = now or timezone.now()
    issue, created = OperationalIssue.objects.get_or_create(key=key,defaults={'device':device,'title':title,'details':details,'severity':severity,'checked_at':now})
    if not created:
        if not issue.active:
            issue.opened_at = now
            issue.notified_at = None
        issue.active = True
        issue.resolved_at = None
        issue.checked_at = now
        issue.title,issue.details,issue.severity = title,details,severity
        issue.save()
    return issue

def silence_threshold(device, health, now):
    if health.expected_silence_minutes:
        return timedelta(minutes=health.expected_silence_minutes)
    # Require a full seven-day history and observations in at least half the hours.
    rows = list(FeedBucket.objects.filter(device=device,hour__gte=now-timedelta(days=7)).order_by('hour').values_list('hour',flat=True).distinct())
    if len(rows) < 84 or not rows or rows[0] > now-timedelta(days=6):
        return None
    gaps = sorted((b-a).total_seconds() for a,b in zip(rows,rows[1:]))
    return timedelta(seconds=max(7200,min(86400,gaps[int(len(gaps)*.95)]*3)))

def evaluate_health(device,now=None):
    now = now or timezone.now()
    health, _ = DeviceHealth.objects.get_or_create(device=device)
    issues = []
    if device.integration == 'paused' or not device.active:
        health.status = 'paused'
    elif health.maintenance_until and health.maintenance_until > now:
        health.status = 'maintenance'
    else:
        if health.api_ok is False:
            issues.append(('api','Falla el acceso de gestión','critical',health.api_error))
        if health.checked_at and now-health.checked_at > timedelta(minutes=30):
            issues.append(('monitor','Comprobación de gestión atrasada','warning','Revisar el monitor del SOC.'))
        if health.certificate_expires and health.certificate_expires < now+timedelta(days=30):
            issues.append(('certificate','Certificado próximo a caducar','warning','Renovar el certificado y actualizar su confianza sin desactivar la validación TLS.'))
        for name, value in health.engines.items():
            if value.get('running') is False and value.get('configured') is not False:
                issues.append((name,'Motor detenido: '+name,'critical','Revisar el servicio en el firewall.'))
            if value.get('export') is False and value.get('configured') is not False:
                issues.append((name+'-export','Falta exportación de '+name,'warning','Completar el envío y verificar un evento real.'))
            if value.get('bypass'):
                issues.append((name+'-bypass','Inspección en bypass: '+name,'critical','Revisar por qué se está omitiendo la inspección.'))
        threshold = silence_threshold(device,health,now)
        if health.last_log_at and threshold and now-health.last_log_at > threshold:
            issues.append(('silence','Recepción de eventos interrumpida','critical','El silencio supera el umbral del equipo: '+str(int(threshold.total_seconds()/60))+' minutos.'))
        if not health.last_log_at:
            issues.append(('receipt','Recepción pendiente de comprobar','warning','La API conectada no confirma el envío de eventos.'))
        required={'unifi'} if device.vendor=='unifi' else set()
        if device.zenarmor_enabled: required.add('zenarmor')
        if health.engines.get('Suricata',{}).get('configured'): required.add('suricata')
        verified=set(DeviceFeed.objects.filter(device=device,security_at__isnull=False).values_list('kind',flat=True))
        complete=bool(verified) and required.issubset(verified)
        health.status = 'degraded' if issues else 'verified' if complete else 'receiving' if health.last_log_at else 'pending'
    health.issues = [{'code':i[0],'title':i[1],'severity':i[2],'details':i[3]} for i in issues]
    health.save()
    prefix = f'device:{device.pk}:health:'
    active_keys = []
    for code,title,severity,details in issues:
        key = prefix+code
        set_issue(key,title,device,details,severity,now)
        active_keys.append(key)
    OperationalIssue.objects.filter(device=device,key__startswith=prefix,active=True).exclude(key__in=active_keys).update(active=False,resolved_at=now,checked_at=now)
    return health

def observe_asset(device,address,name='',mac='',vlan='',source='api'):
    address = ip(address)
    if not address or not private(address):
        return
    asset,_ = Asset.objects.get_or_create(device=device,ip=address)
    from .asset_identity import update_identity
    update_identity(asset,name,mac,vlan,source)


def probe_device(device):
    from .provisioning import _api_request
    from .unifi_cloud import connector_json,decrypt_api_key,get_console_details
    from .ssh_connection import check_generic_connection
    from .protection import flag,ids_mode,selected,extra_opnsense,unifi_protection
    now = timezone.now()
    health,_ = DeviceHealth.objects.get_or_create(device=device)
    health.checked_at = now
    health.api_error = ''
    try:
        if device.management_method == 'ssh':
            connection = device.ssh_connection
            check_generic_connection(connection)
            health.api_ok = True
        elif device.management_method == 'api' and device.vendor == 'opnsense':
            connection = device.opnsense_api
            _api_request(connection,'/api/core/system/status')
            health.api_ok = True
            parsed = urlsplit(connection.api_url)
            context = ssl.create_default_context(cadata=connection.ca_certificate or None)
            with socket.create_connection((parsed.hostname,parsed.port or 443),timeout=5) as sock:
                with context.wrap_socket(sock,server_hostname=parsed.hostname) as tls:
                    expires = tls.getpeercert().get('notAfter')
                    if expires:
                        from datetime import datetime,timezone as utc
                        health.certificate_expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(expires),utc.utc)
            engines = {}
            try:
                ids = _api_request(connection,'/api/ids/settings/get').get('ids',{})
                general = ids.get('general',{})
                mode=general.get('mode')
                if isinstance(mode,dict): mode=','.join(k for k,v in mode.items() if isinstance(v,dict) and v.get('selected'))
                try:
                    state=_api_request(connection,'/api/ids/service/status').get('status')
                    running=state=='running' if isinstance(state,str) else None
                except Exception: running=None
                engines['Suricata'] = {'running': running, 'configured':flag(general.get('enabled')),
                    'export':flag(general.get('syslog_eve')),'mode':ids_mode(general),'interfaces':selected(general.get('interfaces'))[:250],
                    'interfaces_known':isinstance(general.get('interfaces'),(dict,str)) and
                        (not isinstance(general.get('interfaces'),dict) or all(isinstance(v,dict) and flag(v.get('selected')) is not None for v in general['interfaces'].values()))}
            except Exception:
                engines['Suricata'] = {'running':None,'check':'Sin permiso o datos para comprobar.'}
            # Discover an installed engine even if onboarding did not select it.
            # Missing endpoints/permissions are unknown, never proof of a stopped engine.
            try:
                zen = _api_request(connection,'/api/zenarmor/status/index')
                east = zen.get('eastpect',{})
                if isinstance(east,dict) and isinstance(east.get('status'),bool):
                    if not device.zenarmor_enabled:
                        device.zenarmor_enabled=True
                        device.save(update_fields=['zenarmor_enabled'])
                    bypass=east.get('bypass') if isinstance(east.get('bypass'),dict) else {}
                    engines['Zenarmor'] = {'running':east['status'],'configured':True,'bypass':flag(bypass.get('enabled'))}
                    from .zenarmor_scope import collect
                    engines['Zenarmor']['scope'] = collect(connection, zen, _api_request,
                        previous=health.engines.get('Zenarmor', {}).get('scope'), now=now)
                    database=zen.get('database',{})
                    engines['Base de informes Zenarmor'] = {'running':database.get('status') if isinstance(database.get('status'),bool) else None}
                    try:
                        stream = _api_request(connection,'/api/zenarmor/configuration/reporting_data').get('streamReporting',{})
                        enabled=flag(stream.get('enabled'))
                        indexes=stream.get('indexes',[])
                        engines['Zenarmor']['export']=False if enabled is False else bool('alert' in indexes) if enabled is True and isinstance(indexes,list) else None
                        from .protection import zenarmor_export_entitlement
                        engines['Zenarmor']['export_entitlement']=zenarmor_export_entitlement(connection,_api_request)
                    except Exception:
                        engines['Zenarmor']['check']='No se pudo comprobar la exportación.'
                elif device.zenarmor_enabled:
                    engines['Zenarmor'] = {'running':None,'check':'El motor no devolvió su estado.'}
            except Exception:
                if device.zenarmor_enabled:
                    engines['Zenarmor'] = {'running':None,'check':'No se pudo comprobar el motor.'}
            extra_opnsense(connection,engines,_api_request)
            previous_topology = health.engines.get('Suricata', {}).get('topology')
            if previous_topology:
                engines.setdefault('Suricata', {})['topology'] = previous_topology
            health.engines = engines
            health.protection_checked_at = now
            try:
                arp = _api_request(connection,'/api/diagnostics/interface/search_arp?rowCount=-1')
                for row in arp.get('rows',[] if isinstance(arp,dict) else []):
                    observe_asset(device,row.get('ip') or row.get('ipaddr'),row.get('hostname'),row.get('mac') or row.get('macaddr'),row.get('intf_description') or row.get('intf'),'arp')
                from .asset_identity import discover_dhcp
                discover_dhcp(device,connection,_api_request)
                health.inventory_checked_at = now
            except Exception:
                pass
        elif device.management_method == 'api' and device.vendor == 'grandstream_gcc':
            from .gdms_api import check_connection, decrypt
            connection = device.gdms_cloud
            if connection.client_scope_id != device.site.client_id:
                raise ValueError('GDMS connection belongs to a previous customer')
            check_connection(connection.region, connection.app_id, decrypt(connection.encrypted_secret),
                connection.restricted, connection.username,
                decrypt(connection.encrypted_password) if connection.restricted else '')
            health.api_ok = True
            health.engines = {'Grandstream GCC': {'configured': None, 'running': None,
                'check': 'Autenticación GDMS verificada. No acredita envío Syslog, recepción Wazuh ni inspección de amenazas.'}}
        elif device.management_method == 'api' and device.vendor == 'hillstone':
            from .hillstone_api import check_connection,decrypt
            connection=device.hillstone_api
            details=check_connection(connection.api_url,connection.username,decrypt(connection.encrypted_password),connection.ca_certificate)
            for field,value in details.items():setattr(device,field,value)
            if details:device.save(update_fields=list(details))
            health.api_ok=True
            health.engines={'Hillstone NGFW':{'configured':None,'running':None,'mode':'unknown',
                'check':'La autenticación REST está verificada. Esta consulta no acredita el motor IPS, sus firmas ni su modo de bloqueo.'}}
            health.protection_checked_at=now
        elif device.management_method == 'api' and device.vendor == 'unifi':
            connection = device.unifi_cloud
            key = decrypt_api_key(connection.encrypted_api_key)
            get_console_details(key,connection.remote_host_id)
            health.api_ok = True
            health.engines = unifi_protection(device,key,connection,connector_json)
            health.protection_checked_at = now
            try:
                result = connector_json(key,connection.remote_host_id,'/network/api/s/default/stat/sta')
                for row in result.get('data',[]):
                    if isinstance(row,dict):
                        observe_asset(device,row.get('ip') or row.get('fixed_ip'),row.get('name') or row.get('hostname'),row.get('mac'),row.get('vlan'),'unifi')
                health.inventory_checked_at = now
            except Exception:
                health.engines['Inventario'] = {'running':None,'check':'Consulta parcial; revisar permisos.'}
        else:
            health.api_ok = None
        if 'connection' in locals():
            connection.last_ok = health.api_ok is True
            connection.last_checked_at = now
            connection.save(update_fields=['last_ok','last_checked_at'])
    except Exception:
        health.api_ok = False
        health.api_error = 'No se pudo comprobar el acceso con las credenciales y la confianza guardadas. Revisar conexión, permisos y certificado.'
        if 'connection' in locals():
            connection.last_ok=False
            connection.last_checked_at=now
            connection.save(update_fields=['last_ok','last_checked_at'])
    health.save()
    if health.api_ok is True and device.management_method=='api':
        from .network_coverage import discover_networks
        discover_networks(device,health.engines,now)
    from .service_development import record_observation
    record_observation(device,health)
    return evaluate_health(device,now)

def read_receipts(path=Path('/var/ossec/logs/alerts/alerts.json'),limit=3000):
    state,_ = WorkerState.objects.get_or_create(name='receipts')
    stat = path.stat()
    identity = f'{stat.st_dev}:{stat.st_ino}'
    start = state.offset if state.inode == identity and stat.st_size >= state.offset else 0
    details=dict(state.details)
    skipping=bool(details.get('skipping_oversized')) if start else False
    invalid=oversized=read_bytes=0
    with path.open('rb') as stream:
        stream.seek(start)
        events = []
        end = start
        for _ in range(limit):
            line = stream.readline(1024*1024+1)
            if not line:break
            read_bytes+=len(line)
            if skipping or len(line)>1024*1024:
                if not skipping:oversized+=1
                skipping=not line.endswith(b'\n');end=stream.tell()
                if read_bytes>=16*1024*1024:break
                continue
            if not line.endswith(b'\n'):break
            end = stream.tell()
            try:
                event = json.loads(line)
                if isinstance(event,dict):
                    events.append(event)
                else:invalid+=1
            except (ValueError,UnicodeError):
                invalid+=1
            if read_bytes>=16*1024*1024:break
    with transaction.atomic():
        # Reserve SQLite's writer before ingest_events reads the ownership
        # catalogue. Independent workers must not upgrade a stale read snapshot.
        WorkerState.objects.filter(pk=state.pk).update(offset=F('offset'))
        count = ingest_events(events)
        state.inode,state.offset = identity,end
        state.last_run_at = state.last_success_at = timezone.now()
        state.error = ''
        state.details={**details,'skipping_oversized':skipping,'read_bytes':read_bytes,
            'remaining_bytes':max(0,stat.st_size-end),'invalid_json':invalid,'oversized_lines':oversized,
            'invalid_json_total':int(details.get('invalid_json_total',0))+invalid,
            'oversized_lines_total':int(details.get('oversized_lines_total',0))+oversized}
        state.save()
    return count

def reconcile_security(now=None,pages=3,page_size=200,state_name='security-reconciliation',initial_days=1,selected_sources=None,issue_suffix=''):
    """Recover indexed threats after outages/rotation without replaying urgent emails.

    Bounded search_after pages, transactional cursor and a ten-minute overlap.
    A fixed upper bound plus event identity prevents moving pages and duplicates.
    The first reconciliation reads the previous 24 hours; a stored checkpoint
    resumes older gaps, up to the configured evidence horizon (90 days here).
    """
    from .reporting import _search,indexer_authorization,security_filter
    now=now or timezone.now()
    state,_=WorkerState.objects.get_or_create(name=state_name)
    state.last_run_at=now; state.save(update_fields=['last_run_at'])
    owners,_=source_map()
    sources=sorted(owners)
    if selected_sources is not None:sources=[s for s in sources if s in selected_sources]
    issue_prefix='platform:reconciliation'+issue_suffix
    source_signature=hashlib.sha256(json.dumps([(s,owners[s].pk) for s in sources]).encode()).hexdigest()
    if not sources:
        state.last_success_at=now;state.error='';state.save();return 0
    details=dict(state.details)
    # Retain an in-flight backlog when sources change. New sources enter the
    # next fixed window; existing sources keep their committed progress.
    if not details.get('end'):
        previous=parse_datetime(details.get('completed_until',''))
        start=(previous-timedelta(minutes=10)) if previous else now-timedelta(days=initial_days)
        if start<now-timedelta(days=90):
            start=now-timedelta(days=90)
            set_issue(issue_prefix+'-history','Periodo de recuperación superior a 90 días',details='Revisar manualmente los índices históricos anteriores.',now=now)
        details={'start':start.isoformat(),'end':(now-timedelta(minutes=1)).isoformat(),'source_signature':source_signature,'sources':sources}
    window_sources=details.get('sources',sources)
    accepted=0
    try:
        authorization=indexer_authorization()
        for _ in range(pages):
            body={'size':page_size,'track_total_hits':False,
                'query':{'bool':{'filter':[{'terms':{'location':window_sources}},security_filter(),
                    {'range':{'timestamp':{'gte':details['start'],'lt':details['end']}}}]}},
                'sort':[{'timestamp':'asc'},{'id':{'order':'asc','unmapped_type':'keyword'}},{'_index':'asc'}]}
            if details.get('after'): body['search_after']=details['after']
            result=_search(body,authorization)
            if result.get('timed_out') or result.get('_shards',{}).get('failed',0):
                raise ValueError('La consulta del indexador fue parcial.')
            hits=result.get('hits',{}).get('hits')
            if not isinstance(hits,list): raise ValueError('Respuesta del indexador incompleta.')
            if hits and (not all(h.get('_source',{}).get('id') for h in hits) or len(hits[-1].get('sort',[]))!=3):
                raise ValueError('Falta una identidad estable para reanudar.')
            with transaction.atomic():
                WorkerState.objects.filter(pk=state.pk).update(offset=F('offset'))
                accepted+=ingest_events([h['_source'] for h in hits],now)
                if len(hits)<page_size:
                    details={'completed_until':details['end'],'source_signature':source_signature}
                    state.last_success_at=now
                else: details['after']=hits[-1]['sort']
                state.details=details;state.error='';state.save()
            if 'completed_until' in details: break
        if state.last_success_at and now-state.last_success_at>timedelta(hours=1):
            set_issue(issue_prefix+'-lag','Recuperación de alertas con retraso',details='El monitor está procesando el histórico pendiente.',now=now)
        else:
            OperationalIssue.objects.filter(key=issue_prefix+'-lag',active=True).update(active=False,resolved_at=now)
        OperationalIssue.objects.filter(key=issue_prefix+'-error',active=True).update(active=False,resolved_at=now)
    except Exception:
        state.error='No terminó la recuperación de alertas. Revisar acceso al indexador; el cursor se conserva.'
        state.save(update_fields=['error'])
        set_issue(issue_prefix+'-error','Recuperación de alertas pendiente',details=state.error,severity='critical',now=now)
    return accepted

def platform_health():
    import shutil
    now = timezone.now()
    for name in ('soc-portal','wazuh-manager','wazuh-indexer','soc-wazuh-https','soc-wazuh-https-db'):
        healthy = subprocess.run(['systemctl','is-active','--quiet',name],timeout=5).returncode == 0
        key = 'platform:'+name
        if not healthy:
            set_issue(key,'Servicio SOC detenido: '+name,severity='critical',now=now)
        else:
            OperationalIssue.objects.filter(key=key,active=True).update(active=False,resolved_at=now)
    usage = shutil.disk_usage('/srv/soc-portal/data')
    if usage.free / usage.total < .15:
        set_issue('platform:disk','Espacio libre inferior al 15 %',severity='critical',now=now)
    else:
        OperationalIssue.objects.filter(key='platform:disk',active=True).update(active=False,resolved_at=now)
    from .models import WeeklyReport,UrgentAlert,UrgentMonitorCursor
    if WeeklyReport.objects.exclude(last_send_error='').filter(week_start__gte=timezone.localdate()-timedelta(days=14)).exists() or UrgentAlert.objects.filter(status__in=['failed','uncertain'],observed_at__gte=now-timedelta(days=1)).exists():
        set_issue('platform:mail','Hay informes o avisos con errores de envío',details='Revisar Correo del SOC y Avisos urgentes.',now=now)
    else:
        OperationalIssue.objects.filter(key='platform:mail',active=True).update(active=False,resolved_at=now)
    cursor = UrgentMonitorCursor.objects.filter(pk=1).first()
    if not cursor or now-cursor.last_checked_at > timedelta(minutes=5):
        set_issue('platform:urgent-monitor','Monitor de avisos urgentes atrasado',severity='critical',now=now)
    else:
        OperationalIssue.objects.filter(key='platform:urgent-monitor',active=True).update(active=False,resolved_at=now)
    from .models import BackupRun
    latest=BackupRun.objects.filter(status__in=['verified','local_verified']).order_by('-created_at').first()
    if not latest or now-latest.created_at>timedelta(hours=30):
        set_issue('platform:backup-age','Copia reciente pendiente de verificar',severity='critical' if latest else 'warning',now=now)
    else:
        OperationalIssue.objects.filter(key='platform:backup-age',active=True).update(active=False,resolved_at=now)
    cfg=RecoverySettings.objects.filter(pk=1).first()
    if cfg and cfg.transport=='vm':
        from django.utils.dateparse import parse_datetime
        try:stamp=parse_datetime(cfg.vm_backup.get('vm_last_backup_at') or '')
        except (TypeError,ValueError):stamp=None
        declared=bool(stamp and timezone.is_aware(stamp) and timedelta(0)<=now-stamp<=timedelta(hours=30) and cfg.vm_backup.get('vm_offhost'))
        if not declared:
            set_issue('platform:backup-external','Copias de VM: datos pendientes de actualizar',severity='warning',details='Registrar en Copias y recuperación el destino externo y la última copia correcta. El SOC no consulta el hipervisor ni acredita su restauración.',now=now)
        else:OperationalIssue.objects.filter(key='platform:backup-external',active=True).update(active=False,resolved_at=now)
    elif not cfg or not cfg.enabled or not BackupRun.objects.filter(external_verified=True,created_at__gte=now-timedelta(hours=30)).exists():
        set_issue('platform:backup-external','Copia externa pendiente de verificar',severity='warning',details='Configurar el destino SFTP y comprobar una transferencia.',now=now)
    else:
        OperationalIssue.objects.filter(key='platform:backup-external',active=True).update(active=False,resolved_at=now)

def notify_issues(now=None):
    from .mail_delivery import send_report_email
    now = now or timezone.now()
    cfg = RecoverySettings.objects.filter(pk=1,notify_enabled=True).first()
    if not cfg or not cfg.operational_email:
        return 0
    # Persistently actionable, team-only notices; ordinary quiet security feeds are excluded.
    issues = list(OperationalIssue.objects.filter(active=True,notified_at__isnull=True,severity='critical',opened_at__lt=now-timedelta(minutes=5)).exclude(key__startswith='urgent-ack:')[:30])
    if not issues:
        return 0
    plain = 'Incidencias operativas del SOC:\n\n'+'\n'.join(i.title+' — '+(str(i.device) if i.device else 'Plataforma') for i in issues)+'\n\nRevisar https://soc.ibred.es/operations/health/'
    send_report_email(cfg.operational_email,'Centro SOC: revisión operativa necesaria',plain,'<p>Hay incidencias operativas que requieren revisión en el panel SOC.</p>')
    OperationalIssue.objects.filter(pk__in=[i.pk for i in issues]).update(notified_at=now)
    return len(issues)

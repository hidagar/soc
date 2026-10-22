"""Whitelisted jobs, each executed in a separate time-limited systemd process."""
from datetime import timedelta
import subprocess
import time
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from .models import WorkerState

# Interval seconds and display label. No untrusted argument becomes a unit name.
JOBS={
    'receipts':(60,'Lectura local de Wazuh'),
    'reconciliation':(60,'Recuperación por fuente'),
    'transport':(30,'Entrega de lotes HTTPS'),
    'geography':(120,'Mapa y geografía'),
    'databases':(3600,'Bases GeoIP y ASN'),
    'invitations':(60,'Invitaciones de usuarios'),
    'reports':(300,'Informes'),
    'inventory':(60,'Inventario y conectividad'),
    'exposure':(300,'Exposición de equipos'),
    'archives':(300,'Copias de configuración'),
    'attribution':(300,'Identidad de activos'),
    'zenarmor':(120,'Exportación Zenarmor'),
    'dashboards':(300,'Ámbitos de Wazuh'),
    'health':(60,'Salud de la plataforma'),
    'notifications':(60,'Avisos operativos'),
    'housekeeping':(3600,'Conservación y limpieza'),
    'reputation':(900,'Reputación CrowdSec'),
    'blocklists':(900,'Listas de bloqueo del SOC'),
    'crowdsec_lists':(300,'Listas de CrowdSec'),
}
BUDGET=180

def reconcile_sources(limit=3):
    from .operations import source_map,reconcile_security
    owners,_=source_map();groups={}
    for source,device in owners.items():groups.setdefault(device.pk,[]).append(source)
    legacy=WorkerState.objects.filter(pk='security-reconciliation').first()
    candidates=[]
    for device_id,sources in groups.items():
        name=f'source-reconciliation:{device_id}'
        # Seed each new cursor from the last global completed checkpoint, or
        # the beginning of its still-inflight window. Never reset to 24h.
        seed={}
        if legacy:
            stamp=legacy.details.get('start') or legacy.details.get('completed_until')
            if stamp:seed={'completed_until':stamp}
        state,_=WorkerState.objects.get_or_create(name=name,defaults={'details':seed})
        candidates.append((state,device_id,sources))
    candidates.sort(key=lambda r:(r[0].last_run_at or timezone.now()-timedelta(days=3650),r[1]))
    errors=[];accepted=0
    for state,device_id,sources in candidates[:limit]:
        accepted+=reconcile_security(pages=1,state_name=state.name,selected_sources=sources,issue_suffix=f':device:{device_id}')
        state.refresh_from_db()
        if state.error:errors.append(device_id)
    # Drain the already-open global window too: a retired source may exist only
    # in that checkpoint. Event identities prevent duplicates with new cursors.
    if legacy and legacy.details.get('end'):
        accepted+=reconcile_security(pages=1)
        legacy.refresh_from_db()
        if legacy.error:errors.append('legacy')
    if errors:raise RuntimeError('Una o más fuentes conservan una recuperación pendiente.')
    return accepted

def execute(name):
    from . import operations as op
    if name=='receipts':return op.read_receipts()
    if name=='reconciliation':return reconcile_sources()
    if name=='transport':
        from .log_delivery import deliver_due
        from .wazuh_delivery import run_cycle
        legacy=deliver_due(max_seconds=20)
        return legacy+run_cycle()
    if name=='geography':
        from .threat_map import backfill_map_history,enrich_geography
        backfill_map_history();return enrich_geography()
    if name=='databases':
        from .threat_map import update_geoip_database
        from .asn import update_database
        update_geoip_database();return update_database()
    if name=='invitations':
        from .invitations import send_pending
        return send_pending()
    if name=='reports':
        from .reporting import refresh_current_reports
        return refresh_current_reports()
    if name=='inventory':
        from .device_inventory import refresh_due
        from .models import Device,DeviceHealth
        refresh_due(limit=1);now=timezone.now();probed=0
        for device in Device.objects.filter(active=True,site__active=True,site__client__active=True).order_by('health__checked_at','pk'):
            health=DeviceHealth.objects.filter(device=device).first()
            if probed<3 and device.integration!='paused' and (not health or not health.checked_at or now-health.checked_at>timedelta(minutes=10)):
                op.probe_device(device);probed+=1
            else:op.evaluate_health(device,now)
        return probed
    if name=='exposure':
        from .exposure import refresh_due
        return refresh_due(limit=1)
    if name=='archives':
        from .configuration_archives import refresh_archives
        return refresh_archives(limit=1)
    if name=='attribution':
        from .asset_context import refresh_due
        return refresh_due(limit=1)
    if name=='zenarmor':
        from .zenarmor_export import refresh_due
        return refresh_due(limit=1)
    if name=='dashboards':
        from .wazuh_scoped import synchronize
        return synchronize()
    if name=='health':
        from .operations_suite import reconcile_validations
        op.platform_health();reconcile_validations();return check_health()
    if name=='notifications':
        from .delivery_tracking import escalate_unacknowledged
        escalate_unacknowledged();return op.notify_issues()
    if name=='housekeeping':
        from .vpn_security import VpnAccessEvent
        from .models import UserInvitation
        from .log_delivery import cleanup
        from .wazuh_delivery import prune_logs
        now=timezone.now()
        VpnAccessEvent.objects.filter(observed_at__lt=now-timedelta(days=90)).delete()
        UserInvitation.objects.filter(status='sending',attempted_at__lt=now-timedelta(minutes=10)).update(status='uncertain',error='El proceso se interrumpió; revisar antes de reenviar.')
        UserInvitation.objects.filter(expires_at__lte=now).exclude(encrypted_token='').update(encrypted_token='')
        prune_logs(now)
        from .reputation import prune
        prune(now)
        return cleanup(now)
    if name=='reputation':
        from .reputation import refresh
        return refresh()
    if name=='blocklists':
        from .blocklist import refresh_feeds
        return refresh_feeds()
    if name=='crowdsec_lists':
        from .crowdsec_catalog import refresh as refresh_lists
        return refresh_lists()
    raise ValueError('Trabajo no permitido.')

def run_job(name):
    if name not in JOBS:raise ValueError('Trabajo no permitido.')
    state,_=WorkerState.objects.get_or_create(name='job:'+name)
    previous=dict(state.details);failures=int(previous.get('consecutive_failures',0))
    if previous.get('running'):failures+=1
    state.last_run_at=timezone.now();state.error=''
    state.details={**previous,'running':True,'label':JOBS[name][1],'consecutive_failures':failures}
    state.save();started=time.monotonic()
    try:
        result=execute(name)
    except Exception as exc:
        failures+=1
        state.error='El trabajo no terminó. Se conserva su progreso; revisar el servicio protegido.'
        state.details.update(running=False,duration_ms=int((time.monotonic()-started)*1000),consecutive_failures=failures,error_type=type(exc).__name__,
            next_retry_at=(timezone.now()+timedelta(seconds=min(900,15*2**min(failures-1,6)))).isoformat())
        state.save();raise
    state.last_success_at=timezone.now();state.error=''
    state.details.update(running=False,duration_ms=int((time.monotonic()-started)*1000),consecutive_failures=0,next_retry_at=None,error_type='')
    # Only bounded scalar metrics, never vendor replies, messages or credentials.
    if isinstance(result,int):state.details['processed']=result
    state.save();return result

def dispatch(no_notify=False):
    now=timezone.now();count=0;failed=[]
    for name,(interval,_) in JOBS.items():
        if no_notify and name in ('notifications','invitations'):continue
        state=WorkerState.objects.filter(pk='job:'+name).first()
        retry=parse_datetime(state.details.get('next_retry_at') or '') if state else None
        due=retry if retry else (state.last_run_at+timedelta(seconds=interval) if state and state.last_run_at else now)
        if due>now:continue
        try:
            subprocess.run(['systemctl','start','--no-block',f'soc-job@{name}.service'],check=True,capture_output=True,timeout=5)
            count+=1
        except (OSError,subprocess.SubprocessError):failed.append(name)
    if failed:raise RuntimeError('No se pudieron iniciar todos los trabajos.')
    return count

def check_health(now=None):
    from .models import OperationalIssue
    from .operations import set_issue
    from .log_delivery import queue_summary
    now=now or timezone.now()
    receipts=WorkerState.objects.filter(pk='receipts').first()
    if receipts and (receipts.details.get('invalid_json') or receipts.details.get('oversized_lines')):
        set_issue('platform:receipt-format','Registros locales no interpretables',
            details='Se han contado entradas JSON inválidas o de más de 1 MiB. Revisar el origen; no se conservan sus contenidos en el panel.',now=now)
    elif receipts:OperationalIssue.objects.filter(key='platform:receipt-format',active=True).update(active=False,resolved_at=now)
    for name,(interval,label) in JOBS.items():
        if name=='health':continue
        row=WorkerState.objects.filter(pk='job:'+name).first();key='platform:job:'+name
        bad=(not row or not row.last_success_at or now-row.last_success_at>timedelta(seconds=max(600,interval*3+BUDGET))
            or bool(row.error) or (row.details.get('running') and row.last_run_at and now-row.last_run_at>timedelta(seconds=BUDGET+60)))
        if bad:set_issue(key,'Trabajo pendiente de revisión: '+label,details='Revisar la fecha de éxito, duración y reintentos en Salud del SOC.',now=now)
        else:OperationalIssue.objects.filter(key=key,active=True).update(active=False,resolved_at=now)
    # Device-scoped queue incidents remain visible to the corresponding team.
    from .models import SecureLogChannel
    for channel in SecureLogChannel.objects.select_related('device').all():
        summary=queue_summary(channel);key=f'device:{channel.device_id}:https-queue'
        if summary['review'] or (summary['oldest'] and now-summary['oldest']>timedelta(minutes=10)):
            set_issue(key,'Cola HTTPS pendiente de entrega o revisión',device=channel.device,
                details=f"Pendientes: {summary['pending']}; revisión: {summary['review']}. No se acredita recepción en Wazuh.",now=now)
        else:OperationalIssue.objects.filter(key=key,active=True).update(active=False,resolved_at=now)

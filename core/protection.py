"""Observed protection, declared requirements and evidence stay distinct."""
import hashlib
import json
from datetime import datetime,timedelta,timezone as utc
from django.utils import timezone
from .models import Incident

def flag(value):
    if value in (True,1,'1','true'):return True
    if value in (False,0,'0','false'):return False
    return None

def selected(value):
    if isinstance(value,dict):return [str(k) for k,v in value.items() if isinstance(v,dict) and flag(v.get('selected')) is True]
    if isinstance(value,str):return [v.strip() for v in value.split(',') if v.strip()]
    return []

def ids_mode(general):
    modes=selected(general.get('mode'))
    if len(modes)==1 and modes[0] in ('netmap','divert'):return 'ips'
    if modes==['pcap']:return 'ids'
    if not modes and 'ips' in general:
        value=flag(general.get('ips'))
        return 'ips' if value is True else 'ids' if value is False else 'unknown'
    return 'unknown'

def backend_date(value):
    if not isinstance(value,str):return None
    for fmt in ('%a %b %d %H:%M:%S UTC %Y','%a %b %d %H:%M:%S %Y'):
        try:return datetime.strptime(value.strip(),fmt).replace(tzinfo=utc.utc)
        except ValueError:pass
    return None

def zenarmor_export_entitlement(connection,api):
    try:
        data=api(connection,'/api/zenarmor/configuration/license_detail')
        if data.get('success') is not True:raise ValueError('Unverified license')
        edition=str(data.get('license') or '').casefold()
        if edition in ('soho','business'):return {'edition':edition,'eligible':True,'check':'Edición con exportación Syslog; comprobar destino, categoría Alerts y recepción.'}
        if edition in ('free','home'):return {'edition':edition,'eligible':False,'check':'Esta edición no incluye exportación Syslog de Zenarmor. El syslog general de OPNsense no la sustituye.'}
        return {'edition':'unknown','eligible':None,'check':'La API no devuelve una edición con exportación acreditada. Revisar la licencia y las funciones disponibles en Zenarmor.'}
    except Exception:
        return {'edition':'unknown','eligible':None,'check':'No se pudo comprobar la edición y su capacidad de exportación.'}

def extra_opnsense(connection,engines,api):
    """GET only: cached firmware catalogue, ClamAV service/signature metadata."""
    from .operations import clean
    try:
        general=api(connection,'/api/clamav/general/get').get('general',{})
        if not isinstance(general,dict) or flag(general.get('enabled')) is None:raise ValueError('Sin estado ClamAV.')
        cl={'configured':flag(general['enabled']),'running':None,'signature_updates':flag(general.get('fc_enabled'))}
        try:
            status=api(connection,'/api/clamav/service/status').get('status')
            cl['running']=True if status=='running' else False if status in ('stopped','disabled') else None
        except Exception:pass
        try:
            version=api(connection,'/api/clamav/service/version').get('version',{})
            if isinstance(version,dict):
                cl['version']=clean(version.get('clamav'),60)
                cl['daily']=clean(version.get('daily'),180)
                date=backend_date(cl['daily'].split('built on ',1)[-1])
                cl['daily_built_at']=date.isoformat() if date else None
                count=str(version.get('signatures','')).strip()
                cl['signatures']=int(count) if count.isdigit() else None
        except Exception:pass
        engines['ClamAV']=cl
    except Exception:
        engines['ClamAV']={'configured':None,'running':None,'check':'No se pudo comprobar el complemento: revisar instalación, permisos y API.'}
    try:
        data=api(connection,'/api/core/firmware/status')
        status=data.get('status')
        product=data.get('product') if isinstance(data.get('product'),dict) else {}
        engines['Firmware']={'running':None,'version':clean(data.get('product_version') or product.get('product_version') or product.get('version'),80),
            'updates_available':True if status=='update' else False if status in ('ok','up-to-date') else None,
            'catalogue_checked_at':backend_date(data.get('last_check')).isoformat() if backend_date(data.get('last_check')) else None,
            'reboot_required':flag(data.get('needs_reboot')),'check':'Resultado de la última consulta de actualizaciones realizada en OPNsense; no se inicia una nueva comprobación ni una actualización.'}
    except Exception:
        engines['Firmware']={'running':None,'updates_available':None,'check':'No se pudo leer el resultado guardado de actualizaciones.'}

def unifi_protection(device,key,connection,connector):
    try:
        data=connector(key,connection.remote_host_id,'/network/api/s/default/rest/setting')
        if data.get('meta',{}).get('rc','ok')!='ok' or not isinstance(data.get('data'),list):raise ValueError('Respuesta no válida.')
        ips=next((r for r in data['data'] if isinstance(r,dict) and r.get('key')=='ips'),{})
        mode=ips.get('ips_mode')
        return {'UniFi IPS':{'running':None,'configured':True if mode in ('ids','ips') else False if mode=='disabled' else None,
            'mode':mode if mode in ('ids','ips','disabled') else 'unknown','check':'Modo configurado en UniFi. La API consultada no acredita el estado del proceso ni la inspección de todas las redes.'}}
    except Exception:
        return {'UniFi IPS':{'running':None,'configured':None,'mode':'unknown','check':'No se pudo consultar el modo de protección de UniFi.'}}

def incident_key(device,code):
    return 'protection-'+hashlib.sha256(f'{device.pk}:{code}'.encode()).hexdigest()

def snapshot(device,now=None):
    from django.utils.dateparse import parse_datetime
    now=now or timezone.now()
    health=getattr(device,'health',None);policy=getattr(device,'protection_policy',None)
    engines=health.engines if health and isinstance(health.engines,dict) else {}
    feeds={f.kind:f for f in device.feeds.all()}
    paused=not device.active or not device.site.active or not device.site.client.active or device.integration=='paused'
    maintenance=bool(health and health.maintenance_until and health.maintenance_until>now)
    current=bool(health and health.api_ok is True and health.protection_checked_at and timedelta(0)<=now-health.protection_checked_at<=timedelta(minutes=30))
    controls=[];gaps=[];sources=[]
    def gap(code,title,severity,details,recommendation):
        if not paused and not maintenance:
            gaps.append({'code':code,'title':title,'severity':severity,'details':details,'recommendation':recommendation})
    if device.management_method in ('api','ssh'):
        if health and health.api_ok is False:gap('management','Acceso de gestión con error','high','La última consulta de gestión falló.','Revisar conexión, credenciales y confianza HTTPS/SSH desde la ficha del equipo.')
        elif not health or not health.checked_at or now-health.checked_at>timedelta(minutes=30):gap('management_stale','Comprobación de gestión pendiente o atrasada','medium','No hay una comprobación reciente del acceso.','Solicitar revisión del equipo y comprobar el monitor del SOC.')
    required_ips=bool(policy and policy.require_ips)
    def control(name,expected=False):
        value=engines.get(name,{})
        configured=value.get('configured');running=value.get('running')
        if name=='Zenarmor' and configured is None and running is True:configured=True
        expected=expected or configured is True
        if not expected:return None
        if not current:state='unknown';label='Estado actual sin comprobar'
        elif configured is False:state='disabled';label='Desactivado'
        elif running is False:state='stopped';label='Detenido'
        elif value.get('bypass') is True:state='bypass';label='Bypass activado'
        elif running is True:state='running';label='En ejecución'
        elif name=='UniFi IPS' and configured is True:state='configured';label='Configurado; ejecución sin comprobar'
        else:state='unknown';label='Sin comprobar'
        mode=value.get('mode','unknown')
        row={'name':name,'state':state,'label':label,'mode':mode,'value':value,'current':current}
        controls.append(row)
        if state in ('disabled','stopped','bypass'):gap(name+'-state',name+': '+label.lower(),'high','La configuración o el servicio no cumple la protección esperada.','Revisar el servicio, las interfaces y las excepciones antes de intervenir; confirmar su estado después.')
        elif state=='unknown':gap(name+'-unknown',name+': estado pendiente de comprobar','medium','No hay evidencia reciente suficiente para confirmar el motor.','Revisar permisos API y la configuración del motor. Si el acceso es manual/SSH, verificarlo en su consola.')
        if name in ('Suricata','UniFi IPS') and required_ips:
            if current and mode=='ids':gap('ips-mode','IPS requerido, pero el modo es IDS','high','El modo observado corresponde a detección.','Revisar compatibilidad de interfaces, firmas, excepciones y ventana de cambio antes de activar el bloqueo IPS.')
            elif not current or mode not in ('ips','ids'):gap('ips-mode-unknown','Modo IPS pendiente de comprobar','medium','No se ha acreditado que el bloqueo IPS esté configurado.','Comprobar el modo en el firewall y repetir la consulta.')
        return row
    if device.vendor=='opnsense':
        sur=control('Suricata',required_ips)
        zen=control('Zenarmor',bool(device.zenarmor_enabled or (policy and policy.require_zenarmor)))
        clam=control('ClamAV',bool(policy and policy.require_clamav))
        if zen:
            database=engines.get('Base de informes Zenarmor',{})
            if current and database.get('running') is False:gap('zenarmor-database','Base de informes Zenarmor detenida','medium','El motor y la base de informes son servicios distintos.','Revisar la base de informes y conservar los datos antes de repararla; comprobar que vuelve a registrar actividad.')
        for name,row,kind in [('Suricata',sur,'suricata'),('Zenarmor',zen,'zenarmor'),('ClamAV',clam,'clamav')]:
            if not row:continue
            feed=feeds.get(kind)
            sources.append({'name':name,'kind':kind,'feed':feed,'security_required':True,'export':row['value'].get('export') if current else None})
            if current and row['value'].get('export') is False:
                entitlement=row['value'].get('export_entitlement',{}) if name=='Zenarmor' else {}
                gap(kind+'-export','Exportación pendiente: '+name,'medium','El motor no tiene confirmada la exportación requerida.',entitlement.get('check') or 'Completar la exportación según el asistente y validar un evento real en Wazuh.')
            if not feed or not feed.security_at:gap(kind+'-evidence','Detección pendiente de validar: '+name,'medium','Aún no se ha recibido una detección de seguridad atribuida a este motor. Esto no significa que esté detenido.','Comprobar el envío y validar una prueba controlada autorizada o una detección real; no generar ataques contra el cliente.')
        if clam and current:
            c=clam['value']
            if c.get('signature_updates') is False:gap('clamav-updates','Actualización automática de firmas ClamAV desactivada','medium','Freshclam no figura habilitado.','Revisar la configuración de actualización de firmas y verificar una actualización correcta.')
            built=parse_datetime(c.get('daily_built_at') or '')
            if built and timezone.is_aware(built) and now-built>timedelta(hours=72):gap('clamav-signatures','Firmas diarias ClamAV con más de 72 horas','medium','Fecha de construcción observada: '+timezone.localtime(built).strftime('%d/%m/%Y %H:%M')+'.','Revisar conectividad y registros de Freshclam; comprobar la fecha de firmas tras la actualización.')
    elif device.vendor=='unifi':
        control('UniFi IPS',True)
        sources.append({'name':'Seguridad UniFi','kind':'unifi','feed':feeds.get('unifi'),'security_required':True,'export':None})
        if not feeds.get('unifi') or not feeds['unifi'].security_at:gap('unifi-evidence','Detección UniFi pendiente de validar','medium','Aún no se ha recibido una detección de seguridad de UniFi.','Revisar las categorías Security Detections del destino SIEM y validar un evento real.')
    elif device.vendor=='hillstone':
        control('Hillstone NGFW',True)
        feed=feeds.get('hillstone')
        sources.append({'name':'Amenazas Hillstone','kind':'hillstone','feed':feed,'security_required':True,'export':None})
        if not feed or not feed.security_at:
            gap('hillstone-evidence','Detección Hillstone pendiente de validar','medium','Se recibe actividad, pero aún no una amenaza explícita de Hillstone.','Validar una detección autorizada y su acción; un inicio de sesión o una actualización de antivirus no acredita el IPS.')
    elif device.vendor=='grandstream_gcc':
        gap('gcc-security-validation','Seguridad Grandstream GCC pendiente de validar','medium','El envío Syslog no acredita la interpretación de las amenazas del GCC.','Revisar modelo, firmware, licencia y módulos activos en la consola; validar una alerta real IDS/IPS o antimalware y su acción antes de presentar cobertura de ataques.')
    elif policy and (policy.require_ips or policy.require_zenarmor or policy.require_clamav):
        gap('unsupported','Protección declarada sin adaptador compatible','medium','El fabricante no dispone de comprobación automática de estos motores.','Verificar manualmente las funciones y documentar su cobertura.')
    if not controls:
        gap('engines-unverified','Protección del firewall pendiente de acreditar','medium','Recibir actividad no confirma que haya un motor de protección activo.','Declarar los requisitos del servicio y revisar los motores mediante API o su consola.')
    base_kind='unifi' if device.vendor=='unifi' else 'hillstone' if device.vendor=='hillstone' else 'system'
    sources.insert(0,{'name':'Actividad del firewall','kind':base_kind,'feed':feeds.get(base_kind),'security_required':False,'export':None})
    if not health or not health.last_log_at:gap('receipt','Recepción del equipo pendiente de validar','medium','No hay eventos atribuidos a este equipo.','Completar el asistente y verificar IP de origen, destino y recepción en Wazuh.')
    if health:
        for i in health.issues:
            if i.get('code')=='silence':gap('silence','Recepción supera el umbral de silencio','high',i.get('details',''),'Revisar transporte, rutas y receptor. No confundir la ausencia de ataques con una caída de envío.')
    firmware=engines.get('Firmware',{})
    catalogue=parse_datetime(firmware.get('catalogue_checked_at') or '')
    if device.vendor=='opnsense' and current:
        if firmware.get('updates_available') is True:
            gap('firmware-updates','Actualizaciones disponibles según OPNsense','medium','Resultado guardado de la consulta de actualizaciones. No implica que se haya comprobado hoy.','Revisar notas de versión, copia y ventana de mantenimiento antes de actualizar.')
        if not catalogue or not timezone.is_aware(catalogue) or now-catalogue>timedelta(days=7):
            gap('firmware-check','Comprobación de actualizaciones pendiente o antigua','medium','No se dispone de una consulta de catálogo de los últimos siete días.','Ejecutar la comprobación de actualizaciones desde OPNsense; el SOC leerá después ese resultado.')
    status='paused' if paused else 'maintenance' if maintenance else 'attention' if any(g['severity']=='high' for g in gaps) else 'partial' if gaps else 'observed'
    # Include declared requirements and observation times so obsolete forms cannot create stale cases.
    payload={'status':status,'gaps':gaps,'controls':[(r['name'],r['state'],r['mode']) for r in controls],
        'checked':health.protection_checked_at.isoformat() if health and health.protection_checked_at else None,
        'requirements':{'ips':required_ips,'zenarmor':bool(policy and policy.require_zenarmor),'clamav':bool(policy and policy.require_clamav)}}
    digest=hashlib.sha256(json.dumps(payload,sort_keys=True).encode()).hexdigest()
    linked={i.fingerprint:i for i in Incident.objects.filter(device=device,fingerprint__startswith='protection-')}
    for g in gaps:g['incident']=linked.get(incident_key(device,g['code']))
    return {'device':device,'health':health,'policy':policy,'controls':controls,'sources':sources,'gaps':gaps,'status':status,'attribution':getattr(device,'attribution_catalog',None),'zenarmor_export':getattr(device,'zenarmor_export_request',None),
        'label':{'paused':'Pausado','maintenance':'Mantenimiento','attention':'Requiere atención','partial':'Comprobaciones pendientes','observed':'Comprobaciones satisfechas'}[status],
        'current':current,'firmware':firmware,'catalogue':catalogue,'fingerprint':digest}

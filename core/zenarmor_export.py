"""Operator-authorized native Syslog setup; license required, no report DB scraping."""
import json
from datetime import timedelta
from django.utils import timezone
from .models import ZenarmorExportRequest,ExportConfiguration,FirewallOnboarding
from .security import audit,encrypt
from .protection import zenarmor_export_entitlement

class ExportError(Exception):pass

def queue(device,user=None):
    if FirewallOnboarding.objects.filter(device=device,method='https').exists():raise ExportError('Modo HTTPS: configura Zenarmor hacia el reenviador local indicado en el asistente.')
    if device.vendor!='opnsense' or device.management_method!='api' or not device.zenarmor_enabled:
        raise ExportError('Requiere OPNsense + Zenarmor con conexión API.')
    row,_=ZenarmorExportRequest.objects.get_or_create(device=device)
    row.status='queued';row.requested_at=timezone.now();row.requested_by=user
    row.checked_at=None;row.confirmed_at=None;row.note='Configuración solicitada. Se comprobarán licencia, destino y recepción por separado.'
    row.save();audit('zenarmor.export_requested',device)
    return row

def configure(row,api):
    from .provisioning import available_destinations,PORT
    device=row.device
    if FirewallOnboarding.objects.filter(device=device,method='https').exists():
        row.status='error';row.note='Modo HTTPS: configura Zenarmor hacia el reenviador local. No se cambia su destino mediante API.';return
    if device.vendor!='opnsense' or device.management_method!='api' or not device.zenarmor_enabled:raise ExportError('El equipo ya no tiene el perfil API OPNsense + Zenarmor.')
    connection=device.opnsense_api
    config=getattr(device,'export_configuration',None)
    if not config or config.status==ExportConfiguration.Status.CONFIGURING or (config.status==ExportConfiguration.Status.CONFIGURED and not config.receiver_ready):
        row.status='queued';row.note='Esperando que el asistente prepare el receptor y confirme el destino Syslog del SOC.';return
    if config.status!=ExportConfiguration.Status.CONFIGURED or config.destination not in available_destinations() or config.port!=PORT:
        raise ExportError('Completa primero el destino Syslog del SOC y la preparación del receptor.')
    entitlement=zenarmor_export_entitlement(connection,api)
    if entitlement['eligible'] is not True:
        row.status='waiting_license';row.note=entitlement['check'];return
    def read():
        stream=api(connection,'/api/zenarmor/configuration/reporting_data').get('streamReporting')
        fields={'enabled','syslogServerIpAddress','syslogServerPort','syslogServerProtocol','indexes'}
        if not isinstance(stream,dict) or set(stream)!=fields or not isinstance(stream['enabled'],bool):raise ExportError('Formato de exportación Zenarmor no compatible. Revisar versión.')
        indexes=stream['indexes']
        if not isinstance(indexes,list) or len(indexes)>5 or any(x not in ('alert','conn','web','dns','tls') for x in indexes):raise ExportError('Selección de datos desconocida; no se modifica.')
        return stream
    before=read()
    allowed=set(available_destinations())|{'soc.ibred.es'}
    if before['enabled'] and before['syslogServerIpAddress'] not in allowed:
        raise ExportError('Zenarmor ya envía a otro servidor. Se conserva ese destino; requiere revisión del operador.')
    wanted={**before,'enabled':True,'syslogServerIpAddress':config.destination,'syslogServerPort':PORT,
        'syslogServerProtocol':'UDP','indexes':list(dict.fromkeys(before['indexes']+['alert']))}
    def same(a,b):
        return a['enabled']==b['enabled'] and a['syslogServerIpAddress']==b['syslogServerIpAddress'] and str(a['syslogServerPort'])==str(b['syslogServerPort']) and str(a['syslogServerProtocol']).upper()==str(b['syslogServerProtocol']).upper() and set(a['indexes'])==set(b['indexes'])
    if not same(before,wanted):
        if read()!=before:raise ExportError('La configuración cambió durante la consulta. Revisa y vuelve a solicitarla.')
        config.refresh_from_db()
        if config.destination!=wanted['syslogServerIpAddress'] or not config.receiver_ready or config.status!=ExportConfiguration.Status.CONFIGURED:
            raise ExportError('El destino del SOC cambió durante la consulta. Revisa y vuelve a solicitarla.')
        row.encrypted_previous=encrypt(json.dumps(before));row.save(update_fields=['encrypted_previous'])
        result=api(connection,'/api/zenarmor/configuration/stream_reporting',{'streamReporting':wanted})
        if result.get('error') is not False:raise ExportError('Zenarmor no confirmó el guardado. Comprueba el estado antes de repetir; se conserva la copia previa cifrada.')
        if not same(read(),wanted):raise ExportError('La lectura posterior no coincide con el destino solicitado. Revisar; se conserva la copia previa cifrada.')
    row.status='configured';row.confirmed_at=timezone.now()
    row.note='Destino Syslog y Alerts confirmados por API. Falta validar una detección real en Wazuh; esto no acredita bloqueo.'
    audit('zenarmor.export_configured',device)

def refresh_due(limit=1):
    from .provisioning import _api_request
    now=timezone.now();count=0
    rows=ZenarmorExportRequest.objects.filter(status__in=('queued','waiting_license'),device__active=True,device__site__active=True,device__site__client__active=True).exclude(device__integration='paused').select_related('device').order_by('checked_at','pk')
    for row in rows:
        if row.checked_at and now-row.checked_at<timedelta(minutes=10):continue
        try:configure(row,_api_request)
        except ExportError as error:row.status='error';row.note=str(error)
        except Exception:row.status='error';row.note='No se pudo confirmar la configuración. Comprueba licencia, permisos, conexión y estado antes de repetir.'
        row.checked_at=now;row.save();count+=1
        if count>=limit:break
    return count

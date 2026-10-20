"""Root-only encrypted OPNsense backups and a redacted change summary."""
import base64
import hashlib
import os
import ssl
from datetime import timedelta
from pathlib import Path
from urllib import request
from xml.etree import ElementTree as ET
from django.utils import timezone
from .models import Device,ConfigurationArchive
from .security import audit
from .recovery import cipher

ROOT=Path('/var/lib/soc-recovery/firewalls')
LIMIT=16*1024*1024

def fetch_configuration(device):
    from .opnsense_api import validate_api_url,validate_ca_certificate,decrypt_credential,_NoRedirect
    if device.vendor!='opnsense':raise ValueError('unsupported')
    if device.management_method=='ssh':
        from .ssh_connection import run_command
        code,output,_=run_command(device.ssh_connection,'/bin/cat /conf/config.xml')
        if code!=0:
            code,output,_=run_command(device.ssh_connection,'sudo -n /bin/cat /conf/config.xml')
        if code!=0:raise ValueError('read denied')
        return output.encode('utf-8')
    if device.management_method!='api':raise ValueError('unsupported')
    conn=device.opnsense_api;base=validate_api_url(conn.api_url)
    ca=validate_ca_certificate(conn.ca_certificate)
    auth=base64.b64encode((decrypt_credential(conn.encrypted_api_key)+':'+decrypt_credential(conn.encrypted_api_secret)).encode()).decode()
    opener=request.build_opener(request.HTTPSHandler(context=ssl.create_default_context(cadata=ca or None)),_NoRedirect())
    req=request.Request(base+'/api/core/backup/download/this',headers={'Authorization':'Basic '+auth,'Accept':'application/xml'},method='GET')
    with opener.open(req,timeout=15) as response:
        if response.status!=200:raise ValueError('download')
        blob=response.read(LIMIT+1)
    if not blob or len(blob)>LIMIT:raise ValueError('size')
    return blob

def summarize_xml(blob):
    if b'<!DOCTYPE' in blob.upper() or b'<!ENTITY' in blob.upper():raise ValueError('unsafe XML')
    root=ET.fromstring(blob)
    if root.tag!='opnsense':raise ValueError('Not an OPNsense configuration')
    sections={'Reglas de firewall':'filter','Publicaciones NAT':'nat','Interfaces':'interfaces',
        'Suricata':'OPNsense/IDS','Zenarmor':'OPNsense/Zenarmor','Destinos de logs':'OPNsense/Syslog','Acceso de administración':'system/webgui'}
    summary={}
    for label,path in sections.items():
        node=root.find(path)
        # Only section hashes and counts reach the portal; never raw XML, secrets or values.
        summary[label]={'hash':hashlib.sha256(ET.tostring(node) if node is not None else b'').hexdigest(),
            'elements':sum(1 for _ in node.iter()) if node is not None else 0,'available':node is not None}
    return summary

def archive_device(device,now=None):
    if os.geteuid()!=0:raise PermissionError('Root service required')
    now=now or timezone.now()
    previous=device.configuration_archives.filter(status='saved').first()
    try:
        blob=fetch_configuration(device);summary=summarize_xml(blob)
        digest=hashlib.sha256(blob).hexdigest()
        changes=[label for label,item in summary.items() if previous and previous.summary.get(label)!=item]
        ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
        if ROOT.is_symlink() or ROOT.stat().st_mode & 0o077:raise PermissionError('Protected directory required')
        item=ConfigurationArchive.objects.create(device=device,status='saving',created_at=now,sha256=digest,summary=summary,changes=changes)
        destination=ROOT/(str(item.pk)+'.fernet')
        fd=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(cipher().encrypt(blob));stream.flush();os.fsync(stream.fileno())
        # Verify authenticated decryption before recording success.
        if hashlib.sha256(cipher().decrypt(destination.read_bytes())).hexdigest()!=digest:raise ValueError('verification')
        item.status='saved';item.note='Configuración completa cifrada; verificada por descifrado y hash. La restauración en un equipo no se ha probado.';item.save()
        from .operations import set_issue
        if changes:
            set_issue('device:'+str(device.pk)+':configuration-change','Cambio de configuración pendiente de revisión',device,
                details='Consultar Copias del firewall: '+', '.join(changes),now=now)
        issue_key='device:'+str(device.pk)+':configuration-backup'
        from .models import OperationalIssue
        OperationalIssue.objects.filter(key=issue_key,active=True).update(active=False,resolved_at=now)
        audit('firewall.backup_saved',item,{'sha256':digest,'count':len(changes)})
        old=list(device.configuration_archives.filter(status='saved').order_by('-created_at')[14:])
        for archived in old:
            (ROOT/(str(archived.pk)+'.fernet')).unlink(missing_ok=True)
            archived.status='pruned';archived.note='Retirada por retención; se conservan sus metadatos.';archived.save(update_fields=['status','note'])
        return item
    except Exception:
        from .operations import set_issue
        set_issue('device:'+str(device.pk)+':configuration-backup','Copia del firewall pendiente de completar',device,
            details='Revisar acceso y privilegio de descarga en Copias del firewall.',now=now)
        # No remote response or exception text containing configuration escapes to the UI.
        ConfigurationArchive.objects.filter(device=device,status='saving').update(status='failed',note='Copia incompleta; no usar para recuperación.')
        return ConfigurationArchive.objects.create(device=device,status='failed',created_at=now,note='No se pudo obtener o verificar la copia. Revisar acceso API, privilegio de descarga y almacenamiento protegido.')

def refresh_archives(now=None,limit=1):
    now=now or timezone.now();count=0
    for device in Device.objects.filter(active=True,site__active=True,site__client__active=True,vendor='opnsense',management_method__in=('api','ssh')).exclude(integration='paused').order_by('pk'):
        health=getattr(device,'health',None)
        if health and health.maintenance_until and health.maintenance_until>now:continue
        last=device.configuration_archives.first()
        if last and now-last.created_at<timedelta(hours=24 if last.status=='saved' else 6):continue
        archive_device(device,now);count+=1
        if count>=limit:break
    return count

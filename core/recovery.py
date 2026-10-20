"""Encrypted consistent backups, pinned SFTP transfer and isolated restore checks."""
import hashlib
import io
import json
import os
import sqlite3
import tarfile
import tempfile
import struct
import shutil
from contextlib import closing
from datetime import timedelta
from pathlib import Path,PurePosixPath
import paramiko
from cryptography.fernet import Fernet
from django.utils import timezone
from django.db import connection
from .models import BackupRun,RecoverySettings,SecurityEvidence,FeedBucket,AuthAttempt,WorkerState
from .security import decrypt,audit

ROOT=Path('/var/lib/soc-recovery')
KEY=Path('/etc/soc-portal/recovery.key')
DB=Path('/srv/soc-portal/data/portal.sqlite3')

def cipher():
    return Fernet(KEY.read_bytes().strip())

def file_hash(path):
    value=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''): value.update(chunk)
    return value.hexdigest()

def encrypt_file(source,destination):
    """Bounded-memory authenticated frames; sequence and final digest prevent truncation/reordering."""
    box=cipher(); digest=hashlib.sha256(); sequence=0
    fd=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with Path(source).open('rb') as stream,os.fdopen(fd,'wb') as output:
        output.write(b'SOCBAK2\n')
        for chunk in iter(lambda:stream.read(1024*1024),b''):
            digest.update(chunk)
            token=box.encrypt(b'D'+struct.pack('>Q',sequence)+chunk)
            output.write(struct.pack('>I',len(token))+token); sequence+=1
        token=box.encrypt(b'E'+struct.pack('>Q',sequence)+digest.digest())
        output.write(struct.pack('>I',len(token))+token)

def decrypt_file(source,destination):
    box=cipher(); digest=hashlib.sha256(); sequence=0
    stream=io.BytesIO(source) if isinstance(source,bytes) else Path(source).open('rb')
    with stream,Path(destination).open('wb') as output:
        if stream.read(8)!=b'SOCBAK2\n': raise ValueError('Formato de copia incorrecto.')
        while True:
            size=stream.read(4)
            if len(size)!=4: raise ValueError('Copia truncada.')
            length=struct.unpack('>I',size)[0]
            if not 1<=length<=2*1024*1024: raise ValueError('Trama incorrecta.')
            token=stream.read(length)
            if len(token)!=length: raise ValueError('Trama truncada.')
            plain=box.decrypt(token)
            if len(plain)<9 or struct.unpack('>Q',plain[1:9])[0]!=sequence: raise ValueError('Orden de copia incorrecto.')
            if plain[0:1]==b'E':
                if plain[9:]!=digest.digest() or stream.read(1): raise ValueError('Integridad de copia incorrecta.')
                break
            if plain[0:1]!=b'D': raise ValueError('Trama incorrecta.')
            output.write(plain[9:]); digest.update(plain[9:]); sequence+=1

def sftp_connect(cfg):
    from .ssh_connection import validate_host,validate_port
    host,port=validate_host(cfg.hostname),validate_port(cfg.port)
    if not cfg.verified or not cfg.host_key_base64: raise ValueError('Verifica la huella del destino externo.')
    import base64
    key=paramiko.PKey.from_type_string(cfg.host_key_type,base64.b64decode(cfg.host_key_base64,validate=True))
    ssh=paramiko.SSHClient()
    ssh.get_host_keys().add(host if port==22 else f'[{host}]:{port}',key.get_name(),key)
    ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
    ssh.connect(host,port=port,username=cfg.username,password=decrypt(cfg.encrypted_password),
        allow_agent=False,look_for_keys=False,timeout=10,auth_timeout=10,banner_timeout=10)
    return ssh

def transfer(cfg,path):
    remote=PurePosixPath(cfg.remote_path)
    if not remote.is_absolute() or '..' in remote.parts: raise ValueError('Usa un directorio remoto absoluto sin ..')
    destination=str(remote/path.name)
    ssh=sftp_connect(cfg)
    try:
        with ssh.open_sftp() as sftp:
            sftp.get_channel().settimeout(30)
            sftp.put(str(path),destination+'.part',confirm=True)
            digest=hashlib.sha256()
            with sftp.open(destination+'.part','rb') as stream:
                for chunk in iter(lambda:stream.read(1024*1024),b''): digest.update(chunk)
            if digest.hexdigest()!=file_hash(path): raise ValueError('La copia externa no coincide.')
            sftp.rename(destination+'.part',destination)
            # Delete only old backup filenames created by this service, within this pinned directory.
            import re
            cutoff=(timezone.now()-timedelta(days=cfg.retention_days)).timestamp()
            for row in sftp.listdir_attr(str(remote)):
                if re.fullmatch(r'soc-backup-\d{8}T\d{6}Z-[0-9]+\.socbak',row.filename) and row.st_mtime<cutoff:
                    sftp.remove(str(remote/row.filename))
    finally: ssh.close()

def validate_archive(encrypted):
    with tempfile.TemporaryDirectory(prefix='soc-restore-check-') as directory:
        decrypted=Path(directory)/'archive.tar.gz'
        decrypt_file(encrypted,decrypted)
        return validate_tar(decrypted,directory)

def validate_tar(decrypted,directory):
    hashes={}; manifest=None; path=Path(directory)/'verify.sqlite3';firewalls_checked=0
    # Stream once: seeking separately through every compressed member is quadratic.
    with tarfile.open(decrypted,mode='r|gz') as archive:
        for entry in archive:
            path=PurePosixPath(entry.name)
            if path.is_absolute() or '..' in path.parts or not entry.isfile(): raise ValueError('Contenido de copia no permitido.')
            if entry.name in hashes or entry.name=='manifest.json' and manifest is not None: raise ValueError('Contenido duplicado.')
            if entry.name=='manifest.json':
                if entry.size>4*1024*1024:raise ValueError('Manifest too large')
                manifest=json.load(archive.extractfile(entry)); continue
            digest=hashlib.sha256()
            db_output=None
            firewall=entry.name.startswith('firewalls/encrypted/')
            if firewall and entry.size>32*1024*1024:raise ValueError('Firewall archive too large')
            firewall_parts=[]
            if entry.name=='portal.sqlite3': db_output=(Path(directory)/'verify.sqlite3').open('xb')
            try:
                with archive.extractfile(entry) as stream:
                    for chunk in iter(lambda:stream.read(1024*1024),b''):
                        digest.update(chunk)
                        if db_output: db_output.write(chunk)
                        if firewall:firewall_parts.append(chunk)
            finally:
                if db_output: db_output.close()
            hashes[entry.name]=digest.hexdigest()
            if firewall:
                from .configuration_archives import summarize_xml
                summarize_xml(cipher().decrypt(b''.join(firewall_parts)))
                firewalls_checked+=1
        if not isinstance(manifest,dict) or hashes!=manifest.get('files'): raise ValueError('Integridad de archivo incorrecta.')
        from .recovery_components import verify_profile
        coverage=verify_profile(manifest,hashes)
        if 'config/soc-portal/portal.env' not in hashes: raise ValueError('Falta el material de recuperación de claves.')
        if 'portal.sqlite3' not in hashes: raise ValueError('Falta la base de datos.')
        path=Path(directory)/'verify.sqlite3'
        path.chmod(0o600)
        with closing(sqlite3.connect(f'file:{path}?mode=ro',uri=True)) as connection:
            if connection.execute('PRAGMA integrity_check').fetchone()[0]!='ok': raise ValueError('La base de datos no es íntegra.')
            if connection.execute('PRAGMA foreign_key_check').fetchone(): raise ValueError('Referencias de datos inválidas.')
            migrations=connection.execute('SELECT count(*) FROM django_migrations').fetchone()[0]
        return {'files':len(hashes)+1,'migrations':migrations,'database_integrity':'ok','encrypted':True,'firewall_xml_checked':firewalls_checked,**coverage}

class HashingReader:
    def __init__(self,stream):
        self.stream=stream
        self.digest=hashlib.sha256()
    def read(self,size=-1):
        chunk=self.stream.read(size)
        self.digest.update(chunk)
        return chunk

def native_snapshot():
    from .indexer_admin import admin_request
    from .recovery_components import selected_indices
    indices=selected_indices(admin_request('/_cat/indices?format=json&expand_wildcards=all'))
    name='soc-'+timezone.now().strftime('%Y%m%d%H%M%S')
    response=admin_request('/_snapshot/soc_recovery/'+name+'?wait_for_completion=true',{'indices':','.join(indices),'ignore_unavailable':False,'include_global_state':False},method='PUT',timeout=180)
    snapshot=response.get('snapshot',{})
    if snapshot.get('state')!='SUCCESS' or sorted(snapshot.get('indices',[]))!=indices: raise ValueError('El indexador no confirmó su snapshot completo.')
    return name

def test_indexer_restore(name):
    from .indexer_admin import admin_request
    import secrets
    import re
    if not re.fullmatch(r'soc-\d{14}',name):raise ValueError('Invalid snapshot name')
    from .recovery_components import selected_indices
    snapshots=admin_request('/_snapshot/soc_recovery/'+name).get('snapshots',[])
    if len(snapshots)!=1 or snapshots[0].get('state')!='SUCCESS':raise ValueError('Snapshot not verified')
    expected=selected_indices([{'index':n} for n in snapshots[0].get('indices',[])])
    if sorted(snapshots[0]['indices'])!=expected:raise ValueError('Snapshot includes unsupported indices')
    prefix='soc-restore-check-'+secrets.token_hex(8)+'-'
    try:
        answer=admin_request('/_snapshot/soc_recovery/'+name+'/_restore',{
            'indices':','.join(expected),'include_global_state':False,'include_aliases':False,
            'rename_pattern':'(.+)','rename_replacement':prefix+'$1',
            'index_settings':{'index.number_of_replicas':0}},timeout=90)
        if not answer.get('accepted'): raise ValueError('Restauración de prueba rechazada.')
        health=admin_request('/_cluster/health/'+prefix+'*?expand_wildcards=all&wait_for_status=yellow&wait_for_no_initializing_shards=true&timeout=60s',timeout=70)
        if health.get('timed_out') or health.get('status')=='red': raise ValueError('Las réplicas de prueba no pudieron recuperarse.')
        admin_request('/'+prefix+'*/_refresh?expand_wildcards=all',method='POST')
        rows=admin_request('/_cat/indices/'+prefix+'*?format=json&expand_wildcards=all')
        if not isinstance(rows,list) or not rows: raise ValueError('No se restauraron índices de prueba.')
        if sorted(r['index'] for r in rows)!=sorted(prefix+n for n in expected): raise ValueError('Ámbito de restauración incorrecto o incompleto.')
        saved=sum(n.startswith(('.kibana','.opensearch_dashboards')) for n in expected)
        return {'native_restore':'ok','native_restore_profile':2,'restored_indices':len(rows),'restored_saved_object_indices':saved,'restored_docs':sum(int(r.get('docs.count') or 0) for r in rows)}
    finally:
        # Unique, controlled prefix; never delete the live Wazuh indices.
        admin_request('/'+prefix+'*?expand_wildcards=all',method='DELETE')

def make_backup(run):
    cfg,_=RecoverySettings.objects.get_or_create(pk=1)
    ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
    run.status='running'; run.save()
    if connection.vendor!='sqlite':
        # Copiar el archivo SQLite abandonado daría una copia "verificada" sin los datos reales.
        run.status='failed'; run.error='La copia del portal aún no admite PostgreSQL. Usar el procedimiento manual documentado.'; run.save()
        return
    try:
        snapshot_name=native_snapshot()
        with tempfile.TemporaryDirectory(dir=ROOT,prefix='build-') as directory:
            database=Path(directory)/'portal.sqlite3'
            with closing(sqlite3.connect(DB)) as source,closing(sqlite3.connect(database)) as target: source.backup(target)
            files={'portal.sqlite3':database}
            roots=[(Path('/etc/soc-portal'),'config/soc-portal'),(Path('/etc/wireguard'),'config/wireguard'),
                (Path('/etc/wazuh-indexer'),'config/indexer'),(Path('/etc/nginx'),'config/nginx'),
                (Path('/var/ossec/etc'),'config/wazuh'),(Path('/srv/soc-portal'),'code/portal'),
                (Path('/var/lib/wazuh-indexer/soc-snapshots'),'indexer/snapshots'),
                (Path('/var/lib/soc-recovery/firewalls'),'firewalls/encrypted'),
                (Path('/etc/wazuh-dashboard'),'config/dashboard'),
                (Path('/var/ossec/api/configuration'),'config/wazuh-api'),
                (Path('/var/lib/soc-wazuh-https/var/ossec/etc'),'config/wazuh-https'),
                (Path('/etc/netplan'),'config/netplan'),
                (Path('/var/lib/soc-portal/flow-observations'),'data/flow-observations')]
            for root,prefix in roots:
                for path in root.rglob('*'):
                    relative=path.relative_to(root)
                    if path.is_symlink() or not path.is_file() or any(v in relative.parts for v in ('data','staticfiles','__pycache__','.git')): continue
                    if path==KEY: continue # The wrapping key must live outside its own backup.
                    if path.name.startswith('rbac.db'):continue # Snapshot the DB separately; never restore stale WAL/journal files.
                    files[prefix+'/'+relative.as_posix()]=path
            for path in Path('/etc/systemd/system').glob('soc-*.service'):
                if path.is_file() and not path.is_symlink(): files['config/systemd/'+path.name]=path
            for path in Path('/etc/systemd/system').glob('soc-*.timer'):
                if path.is_file() and not path.is_symlink(): files['config/systemd/'+path.name]=path
            sso_unit=Path('/etc/systemd/system/wazuh-dashboard-sso.service')
            if sso_unit.is_file():files['config/systemd/'+sso_unit.name]=sso_unit
            for pattern in ('soc-*.service.d/*','soc-*.timer.d/*','wazuh-dashboard*.service.d/*'):
                for path in Path('/etc/systemd/system').glob(pattern):
                    if path.is_file() and not path.is_symlink():files['config/systemd/'+path.relative_to('/etc/systemd/system').as_posix()]=path
            installer=Path('/home/deploy/soc-setup/wazuh-install-files.tar')
            if installer.is_file():files['config/bootstrap/wazuh-install-files.tar']=installer
            from .recovery_components import export_live_security,selected_indices,PROFILE
            from .indexer_admin import admin_request
            files.update(export_live_security(directory,admin_request))
            rbac=Path('/var/ossec/api/configuration/security/rbac.db')
            if rbac.is_file():
                rbac_copy=Path(directory)/'rbac.db'
                with closing(sqlite3.connect(f'file:{rbac}?mode=ro',uri=True)) as source,closing(sqlite3.connect(rbac_copy)) as target: source.backup(target)
                files['config/wazuh-api/security/rbac.db']=rbac_copy
            snapshot=admin_request('/_snapshot/soc_recovery/'+snapshot_name)['snapshots'][0]
            manifest={'profile':PROFILE,'created_at':timezone.now().isoformat(),'indexer_snapshot':snapshot_name,'indexer_indices':sorted(snapshot['indices']),'files':{}}
            tar_path=Path(directory)/'archive.tar.gz'
            with tarfile.open(tar_path,mode='w:gz') as archive:
                for name,source_path in files.items():
                    with source_path.open('rb') as source:
                        reader=HashingReader(source)
                        archive.addfile(archive.gettarinfo(str(source_path),arcname=name,fileobj=source),reader)
                        manifest['files'][name]=reader.digest.hexdigest()
                content=json.dumps(manifest,sort_keys=True).encode()
                entry=tarfile.TarInfo('manifest.json');entry.size=len(content);entry.mode=0o600
                archive.addfile(entry,io.BytesIO(content))
            path=ROOT/(timezone.now().strftime('soc-backup-%Y%m%dT%H%M%SZ-')+str(run.pk)+'.socbak')
            encrypt_file(tar_path,path)
            run.filename,run.size,run.sha256=path.name,path.stat().st_size,file_hash(path)
            run.details=validate_archive(path)
            run.details['indexer_snapshot']=snapshot_name
            inventory=hashlib.sha256(json.dumps(manifest['indexer_indices']).encode()).hexdigest()
            if not BackupRun.objects.filter(details__native_restore='ok',details__native_restore_profile=2,details__native_restore_inventory=inventory,restore_tested_at__gte=timezone.now()-timedelta(days=30)).exists():
                run.details.update(test_indexer_restore(snapshot_name))
                run.details['native_restore_inventory']=inventory
                run.restore_tested_at=timezone.now()
            run.details['integrity_checked_at']=timezone.now().isoformat()
            if cfg.enabled and cfg.transport=='sftp':
                transfer(cfg,path); run.external_verified=True
            run.status='verified' if run.external_verified else 'local_verified'
            run.error=''; run.save()
            audit('backup.verified',run,{'sha256':run.sha256})
        retention(cfg)
    except Exception:
        run.status='failed'; run.error='No terminó la copia o su verificación. Revisar destino, huella, snapshot y espacio.'; run.save()
        from .operations import set_issue
        set_issue('platform:backup','Copia de seguridad fallida',severity='critical')
        raise
    else:
        from .models import OperationalIssue
        OperationalIssue.objects.filter(key='platform:backup',active=True).update(active=False,resolved_at=timezone.now())

def retention(cfg):
    import re
    cutoff=timezone.now()-timedelta(days=cfg.retention_days)
    for run in BackupRun.objects.filter(created_at__lt=cutoff,status__in=['verified','local_verified']):
        # Keep the latest successful copy even when maintenance has suspended new backups.
        if not BackupRun.objects.filter(created_at__gt=run.created_at,status__in=['verified','local_verified']).exists(): continue
        path=ROOT/run.filename
        if path.parent.resolve()!=ROOT.resolve() or not path.name.startswith('soc-backup-'): continue
        path.unlink(missing_ok=True)
        run.status='expired'; run.save(update_fields=['status'])
    SecurityEvidence.objects.filter(observed_at__lt=timezone.now()-timedelta(days=cfg.evidence_days),incident__isnull=True).delete()
    FeedBucket.objects.filter(hour__lt=timezone.now()-timedelta(days=cfg.evidence_days)).delete()
    AuthAttempt.objects.filter(occurred_at__lt=timezone.now()-timedelta(days=1)).delete()
    # Native snapshots age out through the repository API, never by deleting repository files.
    from .indexer_admin import admin_request
    snapshots=admin_request('/_snapshot/soc_recovery/_all').get('snapshots',[])
    for snap in snapshots:
        if re.fullmatch(r'soc-\d{14}',snap.get('snapshot','')) and snap.get('end_time_in_millis',0)<cutoff.timestamp()*1000 and len(snapshots)>1:
            admin_request('/_snapshot/soc_recovery/'+snap['snapshot'],method='DELETE')

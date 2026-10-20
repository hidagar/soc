"""Local ASN lookups. Only the root worker downloads the public monthly dataset."""
import ipaddress
import os
import re
from datetime import datetime,timedelta,timezone as utc
from pathlib import Path
from django.utils import timezone

DATABASE='/srv/soc-portal/data/geoip-asn.mmdb'
MAX_COMPRESSED=32*1024*1024
MAX_DATABASE=64*1024*1024

def database_path():return Path(os.environ.get('SOC_ASN_DATABASE',DATABASE))

def values(row):
    if not isinstance(row,dict):return None
    number=row.get('autonomous_system_number')
    if isinstance(number,bool) or not isinstance(number,int) or not 0<number<2**32:return None
    organization=row.get('autonomous_system_organization')
    if not isinstance(organization,str):organization=''
    organization=re.sub(r'[\x00-\x1f\x7f]',' ',organization).strip()[:240]
    return {'number':number,'label':f'AS{number}','organization':organization}

def database_stamp(reader,now):
    stamp=datetime.fromtimestamp(reader.metadata().build_epoch,utc.utc)
    if stamp>now+timedelta(days=1):raise ValueError('Future ASN database')
    return stamp

def lookup(address):
    result={'status':'unavailable'}
    try:ip=ipaddress.ip_address(address)
    except (ValueError,TypeError):return {'status':'invalid'}
    if not ip.is_global:return {'status':'private'}
    try:
        import maxminddb
        with maxminddb.open_database(str(database_path())) as reader:
            now=timezone.now();stamp=database_stamp(reader,now)
            result.update(database_date=stamp.date().isoformat(),stale=now-stamp>timedelta(days=62))
            row=values(reader.get(str(ip)))
            if row:result.update(status='found',**row)
            else:result['status']='unknown'
    except Exception:
        # An unavailable optional dataset must never prevent event investigation.
        result={'status':'unavailable'}
    return result

def update_database():
    import gzip,io,tempfile,urllib.request
    from .models import WorkerState
    now=timezone.now();path=database_path()
    state,_=WorkerState.objects.get_or_create(name='asn-database')
    if state.last_run_at and timedelta(0)<=now-state.last_run_at<timedelta(hours=24):return False
    state.last_run_at=now;state.save(update_fields=['last_run_at'])
    temporary=None
    try:
        import maxminddb
        if path.exists():
            try:
                with maxminddb.open_database(str(path)) as reader:
                    stamp=database_stamp(reader,now)
                    current=stamp.strftime('%Y-%m')==now.strftime('%Y-%m') and values(reader.get('8.8.8.8')) is not None
                if current:
                    state.last_success_at=now;state.error='';state.save();return True
            except Exception:pass
        request=urllib.request.Request(f'https://download.db-ip.com/free/dbip-asn-lite-{now:%Y-%m}.mmdb.gz',headers={'User-Agent':'ib-red-SOC/1.0 (+https://soc.ibred.es)'})
        with urllib.request.urlopen(request,timeout=30) as response:
            compressed=response.read(MAX_COMPRESSED+1)
        if len(compressed)>MAX_COMPRESSED:raise ValueError('Oversized ASN download')
        with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as source:
            content=source.read(MAX_DATABASE+1)
        if len(content)>MAX_DATABASE:raise ValueError('Oversized ASN database')
        # Same filesystem for atomic replacement; the previous valid file stays live.
        with tempfile.NamedTemporaryFile(dir=path.parent,delete=False) as target:
            temporary=Path(target.name);target.write(content)
        with maxminddb.open_database(str(temporary)) as reader:
            stamp=database_stamp(reader,now)
            if now-stamp>timedelta(days=62):raise ValueError('Old ASN dataset')
            if 'asn' not in str(reader.metadata().database_type).lower():raise ValueError('Wrong database type')
            if not values(reader.get('8.8.8.8')) or not values(reader.get('2001:4860:4860::8888')):raise ValueError('Missing ASN fields')
        # This file contains public network allocations, never customer addresses.
        os.chmod(temporary,0o644);os.replace(temporary,path);temporary=None
        state.last_success_at=now;state.error='';state.details={'provider':'DB-IP ASN Lite','database_date':stamp.isoformat(),'release':now.strftime('%Y-%m')};state.save()
        return True
    except Exception:
        state.error='Actualización ASN pendiente; se conserva la última base válida.';state.save(update_fields=['error'])
        return False
    finally:
        if temporary:temporary.unlink(missing_ok=True)

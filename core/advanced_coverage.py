"""Readonly capabilities, with complete paginated reads and explicit gaps."""
import time
from django.utils import timezone
from .zenarmor_scope import digest

def collect_unifi(connection,previous=None,now=None):
    from .unifi_cloud import decrypt_api_key,connector_json
    from .unifi_zone_scope import integration_json,catalogue,identity
    now=now or timezone.now();previous=previous if isinstance(previous,dict) else {}
    result={'schema':1,'checked_at':now.isoformat(),'acl':{'status':'unavailable'},'upnp':{'status':'unavailable'}}
    key=decrypt_api_key(connection.encrypted_api_key)
    try:
        deadline=time.monotonic()+45
        read=lambda p,o,l:integration_json(key,connection.remote_host_id,p,o,l)
        sites=catalogue(read,'/v1/sites',deadline)
        local=[s for s in sites if s.get('internalReference')=='default']
        if len(local)!=1:raise ValueError('Ambiguous site')
        path='/v1/sites/'+identity(local[0].get('id'))+'/acl-rules'
        first=catalogue(read,path,deadline);second=catalogue(read,path,deadline)
        def project(rows):
            ids=[identity(r.get('id')) for r in rows]
            if len(set(ids))!=len(ids):raise ValueError('Duplicate ACL')
            return {'count':len(rows),'fingerprint':digest(sorted(rows,key=lambda r:r['id']))}
        a,b=project(first),project(second)
        if a!=b:raise ValueError('Changing ACL')
        result['acl']={'status':'checked',**b,'last_success_at':now.isoformat()}
    except Exception:
        if previous.get('acl',{}).get('status')=='checked':result['acl']['historical']=previous['acl']
        elif previous.get('acl',{}).get('historical'):result['acl']['historical']=previous['acl']['historical']
    try:
        def read_settings():
            data=connector_json(key,connection.remote_host_id,'/network/api/s/default/rest/setting')
            rows=data.get('data')
            if data.get('meta',{}).get('rc')!='ok' or not isinstance(rows,list) or len(rows)>250:raise ValueError('settings')
            usg=[r for r in rows if isinstance(r,dict) and r.get('key')=='usg']
            if len(usg)!=1 or not isinstance(usg[0].get('upnp_enabled'),bool):raise ValueError('state unknown')
            return {k:usg[0].get(k) for k in ('upnp_enabled','upnp_secure_mode','upnp_nat_pmp_enabled','upnp_wan_interface')}
        a,b=read_settings(),read_settings()
        if a!=b:raise ValueError('Changing UPnP')
        result['upnp']={'status':'checked','enabled':b['upnp_enabled'],'fingerprint':digest(b),'last_success_at':now.isoformat(),
            'runtime_mappings':'unavailable'}
    except Exception:
        old=previous.get('upnp',{})
        if old.get('status')=='checked':result['upnp']['historical']=old
        elif old.get('historical'):result['upnp']['historical']=old['historical']
    return result

def snapshot(device):
    from datetime import timedelta
    from django.utils.dateparse import parse_datetime
    check=getattr(device,'exposure_check',None)
    data=check.coverage.get('advanced',{}) if check else {}
    try:
        stamp=parse_datetime(data.get('checked_at',''))
        current=bool(stamp and timezone.is_aware(stamp) and timedelta(0)<=timezone.now()-stamp<=timedelta(hours=12)
            and device.active and device.site.active and device.site.client.active and device.integration!='paused')
    except (TypeError,ValueError):current=False
    return {'data':data,'current':current}

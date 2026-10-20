"""Known local XML bypass flags only; SSO exemptions are not packet exemptions."""
from .zenarmor_scope import digest


def project(root):
    nodes=root.findall('OPNsense/Zenarmor')
    if len(nodes)!=1:return {'status':'unavailable','global_exemptions':'unavailable'}
    node=nodes[0];result={'status':'partial','global_exemptions':'unavailable'}
    for path,key in (('bypass/enable','configured_bypass'),('general/hwbypass','hardware_bypass')):
        rows=node.findall(path)
        if len(rows)!=1 or len(rows[0]) or (rows[0].text or '').strip() not in ('true','false'):
            result[key]=None
        else:result[key]=rows[0].text.strip()=='true'
    result['fingerprint']=digest({k:result[k] for k in ('configured_bypass','hardware_bypass')})
    return result


def snapshot(device,now=None):
    from datetime import timedelta
    from django.utils import timezone
    now=now or timezone.now();catalog=getattr(device,'attribution_catalog',None)
    current=bool(catalog and catalog.status in ('checked','partial') and catalog.last_success_at
        and timedelta(0)<=now-catalog.last_success_at<=timedelta(minutes=45)
        and device.active and device.site.active and device.site.client.active and device.integration!='paused')
    data=catalog.data.get('zenarmor_bypass',{}) if catalog else {}
    flags=[]
    for key,label in (('configured_bypass','Bypass del motor configurado'),('hardware_bypass','Bypass de hardware configurado')):
        value=data.get(key)
        flags.append({'label':label,'state':('Activado' if value else 'Desactivado') if current and isinstance(value,bool) else 'Sin comprobar'})
    return {'current':current,'flags':flags,'checked_at':catalog.last_success_at if catalog else None,
        'fingerprint':data.get('fingerprint') if current else None}

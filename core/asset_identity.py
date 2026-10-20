"""Bounded discovery and event-time identity; IP ownership is not permanent."""
import re
from datetime import timedelta
from django.utils import timezone

def identity_snapshot(asset, stamp):
    if asset is None:return {}
    recent=bool(asset.identified_at and stamp-timedelta(days=1)<=asset.identified_at<=stamp+timedelta(minutes=5))
    confident=not asset.identity_conflict and recent and bool(asset.name or asset.discovered_name)
    return {'label':asset.label if confident else asset.ip,'source':asset.source,
        'confidence':'manual' if confident and asset.name else 'recent' if confident else 'unknown',
        'mac':asset.mac if recent else '', 'identified_at':asset.identified_at.isoformat() if asset.identified_at else '',
        'critical':asset.critical if confident else False,'function':asset.function if confident else ''}

def update_identity(asset,name='',mac='',vlan='',source='api',now=None):
    now=now or timezone.now()
    name=str(name or '').strip()[:160]
    mac=str(mac or '').strip().lower().replace('-',':')
    if not re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}',mac):mac=''
    changed=bool(mac and asset.mac and mac!=asset.mac.lower())
    if changed:
        asset.identity_history=(asset.identity_history+[{'at':now.isoformat(),'previous_mac':asset.mac,'previous_name':asset.discovered_name,'mac':mac}])[-10:]
        asset.identity_conflict=True
        asset.discovered_name=''
    if name:asset.discovered_name=name
    if mac:asset.mac=mac
    if vlan:asset.vlan=str(vlan)[:40]
    if name or mac:asset.identified_at=now
    asset.source=source[:24];asset.last_seen_at=max(asset.last_seen_at,now);asset.save()

def discover_dhcp(device,connection,api_request):
    # Versions without Kea or without ACLs remain unknown; ARP still runs separately.
    try:
        result=api_request(connection,'/api/kea/leases4/search?rowCount=500')
        rows=result.get('rows') if isinstance(result,dict) else None
        if not isinstance(rows,list):return 0
        from .operations import observe_asset
        count=0
        for row in rows[:500]:
            if not isinstance(row,dict):continue
            # Keep only explicitly active leases where the API provides that field.
            if row.get('state') not in (None,0,'0','active'):continue
            observe_asset(device,row.get('address') or row.get('ip_address') or row.get('ip'),
                row.get('hostname') or row.get('client_hostname'),row.get('hwaddr') or row.get('hw_address'),source='dhcp')
            count+=1
        return count
    except Exception:return 0

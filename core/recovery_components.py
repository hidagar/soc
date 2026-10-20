"""Explicit recovery coverage; secrets stay inside the encrypted archive."""
import json,re,os
from pathlib import Path

PROFILE=2
SECURITY_KINDS=('securityconfig','roles','rolesmapping','actiongroups','internalusers','tenants')
INDEX_NAME=re.compile(r'(?:wazuh-alerts-[a-zA-Z0-9_.-]+|soc-customer-[1-9][0-9]*-events|\.kibana[a-zA-Z0-9_.-]*|\.opensearch_dashboards[a-zA-Z0-9_.-]*)\Z')
REQUIRED=(
    'config/soc-portal/portal.env','code/portal/manage.py',
    'config/dashboard/opensearch_dashboards.yml','config/dashboard/opensearch_dashboards_sso.yml',
    'config/systemd/wazuh-dashboard-sso.service','config/nginx/snippets/soc-wazuh-auth-key.conf',
    'config/indexer/certs/admin.pem','config/indexer/certs/admin-key.pem',
    'config/bootstrap/wazuh-install-files.tar',
)+tuple('config/live-security/'+kind+'.json' for kind in SECURITY_KINDS)

def selected_indices(rows):
    if not isinstance(rows,list) or len(rows)>10000:raise ValueError('Invalid index catalogue')
    names=sorted({r['index'] for r in rows if isinstance(r,dict) and isinstance(r.get('index'),str) and INDEX_NAME.fullmatch(r['index'])})
    if not any(n.startswith('wazuh-alerts-') for n in names):raise ValueError('No alert indices')
    if not any(n.startswith(('.kibana','.opensearch_dashboards')) for n in names):raise ValueError('Saved objects index missing')
    return names

def export_live_security(directory,api):
    result={}
    for kind in SECURITY_KINDS:
        payload=api('/_plugins/_security/api/'+kind)
        if not isinstance(payload,dict):raise ValueError('Invalid security export')
        encoded=json.dumps(payload,sort_keys=True).encode()
        if len(encoded)>16*1024*1024:raise ValueError('Oversized security export')
        path=Path(directory)/(kind+'.json')
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'wb') as f:f.write(encoded)
        result['config/live-security/'+kind+'.json']=path
    return result

def verify_profile(manifest,hashes):
    if manifest.get('profile')!=PROFILE:return {}
    missing=[name for name in REQUIRED if name not in hashes]
    # Base del portal: copia SQLite o pg_dump, según el motor en uso.
    if missing or not {'portal.sqlite3','portal.pgdump'}&set(hashes):raise ValueError('Recovery components missing')
    indices=manifest.get('indexer_indices')
    if selected_indices([{'index':n} for n in indices or []])!=indices:raise ValueError('Incomplete snapshot inventory')
    return {'profile':PROFILE,'coverage':{'portal':True,'dashboard_config':True,'sso_config':True,'live_security_export':True,
        'alerts_indices':sum(n.startswith('wazuh-alerts-') for n in indices),
        'saved_object_indices':sum(n.startswith(('.kibana','.opensearch_dashboards')) for n in indices)}}

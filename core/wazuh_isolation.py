"""Real negative checks using the proxy identity, no fake security documents."""
import json,urllib.request,urllib.error
from .wazuh_scoped import names
from .indexer_tls import context

def proxy_get(path,cid,*,dashboard=False,tenant=None,method='GET'):
    n=names(cid)
    headers={'x-soc-wazuh-user':f'soc-c{cid}-isolation-check','x-soc-wazuh-roles':n['role']+',soc_portal_scoped',
        'x-forwarded-for':'127.0.0.1','securitytenant':tenant or n['tenant'],'osd-xsrf':'true'}
    base='https://127.0.0.1:5602/wazuh' if dashboard else 'https://127.0.0.1:9200'
    ctx=context('/etc/wazuh-dashboard/certs/root-ca.pem' if dashboard else '/etc/wazuh-indexer/certs/root-ca.pem')
    try:
        with urllib.request.urlopen(urllib.request.Request(base+path,headers=headers,method=method),context=ctx,timeout=20) as response:
            raw=response.read(1_000_001)
            if len(raw)>1_000_000:raise ValueError('Oversized response')
            return response.status,json.loads(raw)
    except urllib.error.HTTPError as exc:return exc.code,{}

def verify_isolation(cid):
    n=names(cid)
    status,info=proxy_get('/_plugins/_security/authinfo',cid)
    if status!=200 or set(info.get('roles',[]))!={n['role'],'soc_portal_scoped'}:raise ValueError('Unexpected effective roles')
    status,_=proxy_get('/wazuh-alerts-*/_count',cid)
    if status!=403:raise ValueError('Raw indices are not denied')
    # Use the same aggregate endpoint exposed to Discover; cannot enumerate peers.
    status,_=proxy_get('/soc-customer-*/_count',cid)
    if status!=403:raise ValueError('Wildcard index query is not denied')
    status,data=proxy_get('/'+n['index']+'/_search?size=0',cid)
    if status!=200 or data.get('timed_out') or data.get('_shards',{}).get('failed'):raise ValueError('Own index unavailable')
    status,data=proxy_get('/api/saved_objects/_find?type=dashboard&per_page=100',cid,dashboard=True)
    objects=data.get('saved_objects',[])
    if status!=200 or not objects or any(obj.get('id')!=n['dashboard'] for obj in objects):raise ValueError('Tenant object scope not isolated')
    status,_=proxy_get('/api/saved_objects/dashboard/soc-general',cid,dashboard=True,tenant='global')
    if status not in (403,404):raise ValueError('Global tenant not denied')
    # This ID cannot be a real evidence UID (those are 64 hexadecimal characters).
    status,_=proxy_get('/'+n['index']+'/_doc/soc-readonly-permission-check',cid,method='DELETE')
    if status!=403:raise ValueError('Projection writes are not denied')
    return True

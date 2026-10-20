"""Per-customer read-only projection. Raw Wazuh indices are never granted.

SecurityEvidence ownership is frozen at ingestion; older records without a
frozen owner are omitted until an operator reviews them. Each customer gets an
exact index, DLS and an independent saved-object tenant.
"""
import hashlib,json,re,ssl,urllib.request,urllib.error
from datetime import timedelta
from django.utils import timezone
from .models import Client,SecurityEvidence,WorkerState
from .indexer_admin import admin_request

VERSION=1
OBJECT_VERSION=3
def names(client_id):
    if isinstance(client_id,bool) or not isinstance(client_id,int) or client_id<1:raise ValueError('Invalid scope')
    return {'index':f'soc-customer-{client_id}-events','role':f'soc_customer_{client_id}_reader','tenant':f'soc_customer_{client_id}','dashboard':f'soc-customer-{client_id}'}

def role_definition(client_id):
    n=names(client_id)
    return {'cluster_permissions':['cluster_composite_ops_ro'],'index_permissions':[{'index_patterns':[n['index']],
        'dls':json.dumps({'term':{'soc.client_id':client_id}}),'allowed_actions':['read']}],
        'tenant_permissions':[{'tenant_patterns':[n['tenant']],'allowed_actions':['kibana_all_read']}]}

def binding_ready(client_id):
    row=WorkerState.objects.filter(pk='wazuh-customer-'+str(client_id)).first()
    return bool(row and not row.error and row.details.get('version')==VERSION and row.details.get('ready') is True and row.last_success_at
        and timedelta(0)<=timezone.now()-row.last_success_at<=timedelta(minutes=15))

def document(evidence):
    cid=evidence.client_scope_id
    if not cid:raise ValueError('No frozen owner')
    # No raw log, usernames, MACs, current DHCP names, credentials or internal notes.
    return {'timestamp':evidence.observed_at.isoformat(),'soc':{'client_id':cid,'device_id':evidence.device_id,'uid':evidence.uid,'action':evidence.action},
        'rule':{'level':evidence.level,'description':evidence.signature},'decoder':{'name':evidence.engine},
        'location':str(evidence.device_id),'data':{'srcip':evidence.source_ip,'dstip':evidence.destination_ip,
            'unifi':{'action':evidence.action}},'category':evidence.category}

MAPPING={'dynamic':'strict','properties':{'timestamp':{'type':'date'},'soc':{'properties':{'client_id':{'type':'long'},'device_id':{'type':'long'},'uid':{'type':'keyword'},'action':{'type':'keyword'}}},
    'rule':{'properties':{'level':{'type':'integer'},'description':{'type':'keyword'}}},'decoder':{'properties':{'name':{'type':'keyword'}}},
    'location':{'type':'keyword'},'category':{'type':'keyword'},'data':{'properties':{'srcip':{'type':'ip'},'dstip':{'type':'ip'},'unifi':{'properties':{'action':{'type':'keyword'}}}}}}}

def bulk_publish(rows):
    from .indexer_tls import context
    ctx=context();ctx.load_cert_chain('/etc/wazuh-indexer/certs/admin.pem','/etc/wazuh-indexer/certs/admin-key.pem')
    lines=[]
    for e in rows:
        lines.extend((json.dumps({'index':{'_index':names(e.client_scope_id)['index'],'_id':e.uid}}),json.dumps(document(e))))
    req=urllib.request.Request('https://127.0.0.1:9200/_bulk?refresh=wait_for',data=('\n'.join(lines)+'\n').encode(),headers={'Content-Type':'application/x-ndjson'},method='POST')
    with urllib.request.urlopen(req,context=ctx,timeout=30) as r:raw=r.read(2_000_001)
    if len(raw)>2_000_000:raise ValueError('Oversized bulk response')
    response=json.loads(raw)
    if response.get('errors') or len(response.get('items',[]))!=len(rows):raise ValueError('Projection not confirmed')
    if any(item.get('index',{}).get('status') not in (200,201) for item in response['items']):raise ValueError('Projection rejected')
    SecurityEvidence.objects.filter(uid__in=[e.uid for e in rows]).update(wazuh_published_at=timezone.now())

def sync_client(client):
    n=names(client.pk);prefix='/_plugins/_security/api/'
    state,_=WorkerState.objects.get_or_create(pk='wazuh-customer-'+str(client.pk))
    state.last_run_at=timezone.now()
    try:
        try:admin_request('/'+n['index'])
        except urllib.error.HTTPError as exc:
            if exc.code!=404:raise
            admin_request('/'+n['index'],{'settings':{'index.number_of_shards':1,'index.number_of_replicas':0},'mappings':MAPPING},method='PUT')
            SecurityEvidence.objects.filter(client_scope_id=client.pk).update(wazuh_published_at=None)
        wanted=role_definition(client.pk)
        admin_request(prefix+'tenants/'+n['tenant'],{'description':'ib-red empresas · cliente '+str(client.pk)},method='PUT')
        admin_request(prefix+'roles/'+n['role'],wanted,method='PUT')
        admin_request(prefix+'rolesmapping/'+n['role'],{'backend_roles':[n['role']],'users':[],'hosts':[]},method='PUT')
        actual=admin_request(prefix+'roles/'+n['role']).get(n['role'],{})
        observed={k:actual.get(k) for k in wanted}
        observed['index_permissions']=[{k:p.get(k) for k in ('index_patterns','dls','allowed_actions')} for p in actual.get('index_permissions',[])]
        if observed!=wanted:raise ValueError('Role verification failed')
        objects_revision=hashlib.sha256((str(OBJECT_VERSION)+client.name).encode()).hexdigest()
        if state.details.get('objects_revision')!=objects_revision:
            from .wazuh_tenant_objects import sync_objects
            sync_objects(client)
        from .wazuh_isolation import verify_isolation
        verify_isolation(client.pk)
        state.details={'version':VERSION,'ready':True,'objects_revision':objects_revision,'isolation_checked_at':timezone.now().isoformat()}
        state.error='';state.last_success_at=timezone.now()
    except Exception:
        state.error='No se ha confirmado aislamiento, índice y objetos del cliente.';state.details={**state.details,'ready':False}
    state.save()
    return not state.error

def synchronize(limit=3):
    now=timezone.now()
    clients=list(Client.objects.filter(active=True).order_by('pk'))
    states={row.name:row for row in WorkerState.objects.filter(name__startswith='wazuh-customer-')}
    clients.sort(key=lambda c:(states.get('wazuh-customer-'+str(c.pk)).last_run_at if states.get('wazuh-customer-'+str(c.pk)) and states['wazuh-customer-'+str(c.pk)].last_run_at else now-timedelta(days=3650),c.pk))
    ready=[]
    checked=0
    for client in clients:
        state=states.get('wazuh-customer-'+str(client.pk))
        if checked<limit and (not state or not state.last_run_at or now-state.last_run_at>=timedelta(minutes=5)):
            sync_client(client);checked+=1
        if binding_ready(client.pk):ready.append(client.pk)
    from .models import RecoverySettings
    cfg=RecoverySettings.objects.filter(pk=1).first()
    cutoff=now-timedelta(days=cfg.evidence_days if cfg else 90)
    rows=list(SecurityEvidence.objects.filter(client_scope_id__in=ready,wazuh_published_at=None,observed_at__gte=cutoff).select_related('device').order_by('observed_at','uid')[:500])
    if rows:bulk_publish(rows)
    # Independent projection follows the configured evidence horizon, even when
    # the incident itself remains retained in the portal for case management.
    retention,_=WorkerState.objects.get_or_create(name='wazuh-projection-retention')
    if not retention.last_success_at or now-retention.last_success_at>=timedelta(days=1):
        for cid in ready:
            response=admin_request('/'+names(cid)['index']+'/_delete_by_query?conflicts=proceed',{'query':{'range':{'timestamp':{'lt':cutoff.isoformat()}}}},timeout=30)
            if response.get('timed_out') or response.get('failures'):raise ValueError('Projection retention not confirmed')
        if len(ready)==len(clients):retention.last_success_at=now;retention.save(update_fields=['last_success_at'])
    return len(rows)

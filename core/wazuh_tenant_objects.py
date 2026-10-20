"""Tenant-local objects generated from the corporate dashboard components."""
import importlib.util,json
from pathlib import Path
from urllib.parse import quote
from .wazuh_scoped import names

def load(name):
    path=Path(__file__).resolve().parent.parent/'deploy'/(name+'.py')
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

def sync_objects(client):
    sync=load('sync_wazuh_dashboards');design=load('soc_dashboard_design')
    n=names(client.pk);auth=sync.credentials()
    def api(kind,oid,body=None):
        path='/api/saved_objects/'+kind+'/'+quote(oid,safe='')
        return sync.request(path+('?overwrite=true' if body is not None else ''),auth,'POST' if body is not None else 'GET',body,tenant=n['tenant'])
    fields=[]
    labels={'timestamp':'Fecha','soc.client_id':'Empresa (ID)','soc.device_id':'Firewall (ID)','soc.action':'Acción registrada','rule.level':'Prioridad Wazuh','rule.description':'Detección','decoder.name':'Motor','location':'Firewall (ID)','data.srcip':'IP de origen','data.dstip':'Destino observado','data.unifi.action':'Acción registrada'}
    for name,kind in [('timestamp','date'),('soc.client_id','number'),('soc.device_id','number'),('soc.action','string'),('rule.level','number'),('rule.description','string'),('decoder.name','string'),('location','string'),('data.srcip','ip'),('data.dstip','ip'),('data.unifi.action','string')]:
        fields.append({'name':name,'type':kind,'searchable':True,'aggregatable':True,'readFromDocValues':True,'customLabel':labels[name]})
    format_map={'soc.action':{'id':'static_lookup','params':{'lookupEntries':[{'key':'allowed','value':'Permitida'},{'key':'blocked','value':'Bloqueada'},{'key':'unknown','value':'Sin confirmar'}],'unknownKeyValue':'Sin confirmar'}}}
    body={'attributes':{'title':n['index'],'timeFieldName':'timestamp','fields':json.dumps(fields),'fieldFormatMap':json.dumps(format_map)},'references':[]}
    if api('index-pattern',n['index'],body)[0] not in (200,201):raise ValueError('Tenant index pattern not confirmed')
    objects=design.build(sync,'customer-'+str(client.pk),client.name,set())
    for kind,oid,body in objects:
        for reference in body.get('references',[]):
            if reference['type']=='index-pattern':reference['id']=n['index']
        source=body['attributes'].get('kibanaSavedObjectMeta',{}).get('searchSourceJSON')
        if source:
            value=json.loads(source)
            value['query']['query']=value['query']['query'].replace('location: "__soc_sin_origen__"','soc.client_id: '+str(client.pk))
            value['query']['query']=value['query']['query'].replace('data.unifi.action','soc.action')
            body['attributes']['kibanaSavedObjectMeta']['searchSourceJSON']=json.dumps(value)
        if kind=='visualization':
            state=json.loads(body['attributes']['visState'])
            if oid.endswith('-blocked'):
                state['title']='Bloqueos registrados';body['attributes']['title']=state['title']
            if state['type']=='markdown':
                state['params']['markdown']=('![ib-red empresas](https://soc.ibred.es/static/brand/ibred-empresas-dashboard.png)\n\n### Seguridad gestionada · '+client.name+'\n\nConsulta las detecciones de tu empresa. Un cero no acredita ausencia de amenazas. [Informes y seguimiento](https://soc.ibred.es/cliente/).')
                if oid.endswith('-help'):
                    state['params']['markdown']='### Cómo interpretar el dashboard\nLos eventos proceden de evidencias normalizadas del SOC y tienen atribución de empresa conservada. El nivel indica prioridad; no confirma compromiso. Un bloqueo de aplicaciones no acredita malware. Se muestran direcciones observadas, sin deducir el equipo interno detrás de NAT.\n\nLa vista usa la retención de evidencias configurada en el SOC (por defecto, 90 días). No contiene todos los logs informativos ni notas internas. [Consultar informes y seguimiento](https://soc.ibred.es/cliente/).'
            body['attributes']['visState']=json.dumps(state)
            body['attributes']['uiStateJSON']=json.dumps({'vis':{'colors':{'Informativos · 0–7':'#0B612D','Prioritarios · 8–11':'#00A82D','Críticos · 12–16':'#B33642'}}})
        if kind=='search':body['attributes']['columns']=['timestamp','rule.level','rule.description','soc.device_id','data.dstip','soc.action']
        if kind=='dashboard':body['attributes']['description']='Detecciones atribuidas a esta empresa; índice y tenant aislados. No incluye todos los logs informativos.'
        if api(kind,oid,body)[0] not in (200,201):raise ValueError('Tenant object not confirmed')
    code,obj=api('dashboard',n['dashboard'])
    if code!=200 or not obj.get('references'):raise ValueError('Tenant dashboard missing')

"""ib-red Wazuh native visualizations; no permissions or index writes."""
import json
from pathlib import Path
import html

def scope_query(sources):
    return '('+' or '.join('location: '+json.dumps(ip) for ip in sorted(sources))+')' if sources else 'location: "__soc_sin_origen__"'

def agg(kind,schema,params=None,id='1'):
    return {'id':id,'enabled':True,'type':kind,'schema':schema,'params':params or {}}

def visualization(s,title,query,kind,aggs,params):
    return {'attributes':{'title':title,'description':'ib-red empresas · datos recibidos durante el intervalo seleccionado.',
        'visState':json.dumps({'title':title,'type':kind,'params':params,'aggs':aggs},ensure_ascii=False),
        'uiStateJSON':json.dumps({'vis':{'colors':{'Detecciones':'#0B612D','Críticas':'#b33642','Bloqueadas':'#00A82D'}}}),
        'version':1,'kibanaSavedObjectMeta':{'searchSourceJSON':s.search_source(query)}},'references':s.index_reference()}

def filters(items):
    return {'filters':[{'input':{'query':q,'language':'kuery'},'label':label} for label,q in items]}

def build(s,slug,title,sources,clients=None,has_geo=False):
    q=scope_query(sources);objects=[];panels=[];refs=[]
    def add(key,label,kind,aggs,params,x,y,w,h,query=None):
        oid=f'soc-design-{slug}-{key}'
        objects.append(('visualization',oid,visualization(s,label,query or q,kind,aggs,params)))
        idx=str(len(panels)+1);ref='panel_'+idx
        panels.append({'panelIndex':idx,'gridData':{'x':x,'y':y,'w':w,'h':h,'i':idx},'embeddableConfig':{},'panelRefName':ref,'version':'7.10.0'})
        refs.append({'name':ref,'type':'visualization','id':oid})
    name=html.escape(title)
    add('brand','ib-red empresas · Centro SOC','markdown',[],{'markdown':f'![ib-red empresas](https://soc.ibred.es/static/brand/ibred-empresas-dashboard.png)\n\n## {name} · Seguridad gestionada\nResumen de eventos recibidos. Ajusta el periodo en la esquina superior derecha. **Un cero no demuestra ausencia de ataques ni recepción continua.**','fontSize':12,'openLinksInNewTab':True},0,0,48,10)
    metric_params={'addTooltip':True,'addLegend':False,'type':'metric','metric':{'percentageMode':False,'useRanges':False,'colorSchema':'Green to Red','metricColorMode':'None','colorsRange':[{'from':0,'to':10000}],'labels':{'show':False},'invertColors':False,'style':{'bgFill':'#ECF4E8','bgColor':False,'labelColor':False,'subText':'','fontSize':34}}}
    for i,(key,label,extra) in enumerate([('events','Eventos recibidos',''),('priority','Detecciones · nivel ≥ 8',' and rule.level >= 8'),('critical','Críticas · nivel ≥ 12',' and rule.level >= 12'),('blocked','Bloqueos registrados · UniFi',' and data.unifi.action: "blocked"')]):
        add(key,label,'metric',[agg('count','metric')],metric_params,i*12,10,12,9,query=q+extra)
    levels=[('Informativos · 0–7','rule.level < 8'),('Prioritarios · 8–11','rule.level >= 8 and rule.level < 12'),('Críticos · 12–16','rule.level >= 12')]
    add('trend','Evolución de eventos','histogram',[agg('count','metric'),agg('date_histogram','segment',{'field':'timestamp','interval':'auto','min_doc_count':1,'extended_bounds':{}},'2'),agg('filters','group',filters(levels),'3')],{'addTooltip':True,'addLegend':True,'legendPosition':'bottom','type':'histogram','grid':{'categoryLines':False,'style':{'color':'#D7EAD9'}},'categoryAxes':[{'id':'CategoryAxis-1','type':'category','position':'bottom','show':True,'style':{},'scale':{'type':'linear'},'labels':{'show':True,'truncate':100},'title':{}}],'valueAxes':[{'id':'ValueAxis-1','name':'LeftAxis-1','type':'value','position':'left','show':True,'style':{},'scale':{'type':'linear','mode':'normal'},'labels':{'show':True,'rotate':0,'filter':False,'truncate':100},'title':{'text':'Eventos'}}],'seriesParams':[{'show':True,'type':'histogram','mode':'stacked','data':{'label':'Eventos','id':'1'},'valueAxis':'ValueAxis-1'}]},0,19,32,17)
    add('severity','Distribución por prioridad','pie',[agg('count','metric'),agg('filters','segment',filters(levels),'2')],{'addTooltip':True,'addLegend':True,'legendPosition':'bottom','isDonut':True,'labels':{'show':False}},32,19,16,17)
    def table(key,label,field,x,y,w,query=None):
        add(key,label,'table',[agg('count','metric'),agg('terms','bucket',{'field':field,'size':8,'order':'desc','orderBy':'1'},'2')],{'perPage':8,'showPartialRows':False,'showMetricsAtAllLevels':False,'sort':{'columnIndex':1,'direction':'desc'},'showTotal':False},x,y,w,17,query)
    table('rules','Detecciones más frecuentes · nivel ≥ 8','rule.description',0,36,24,q+' and rule.level >= 8')
    table('targets','Destinos identificados · nivel ≥ 8','data.dstip',24,36,24,q+' and rule.level >= 8')
    if has_geo:
        add('map','Orígenes geolocalizados · datos disponibles','tile_map',[agg('count','metric'),agg('geohash_grid','segment',{'field':'GeoLocation.location','precision':2,'useGeocentroid':True,'isFilteredByCollar':True},'2')],{'mapType':'Scaled Circle Markers','isDesaturated':True,'addTooltip':True,'heatClusterSize':1.5,'legendPosition':'bottomright','mapZoom':2,'mapCenter':[15,0],'wms':{'enabled':False}},0,53,32,19,q+' and rule.level >= 8')
        table('countries','Países de origen · geolocalización disponible','GeoLocation.country_name',32,53,16,q+' and rule.level >= 8')
    else:
        table('sources','Orígenes identificados · nivel ≥ 8','data.srcip',0,53,24,q+' and rule.level >= 8')
        table('engines','Fuentes de detección','decoder.name',24,53,24)
    y=72
    if clients:
        add('clients','Detecciones por cliente · nivel ≥ 8','pie',[agg('count','metric'),agg('filters','segment',filters([(c['name'],scope_query(c['sources'])) for c in clients]),'2')],{'addTooltip':True,'addLegend':True,'legendPosition':'right','isDonut':True,'labels':{'show':False}},0,y,24,16,q+' and rule.level >= 8')
        add('origins','Orígenes con eventos · intervalo seleccionado','metric',[agg('cardinality','metric',{'field':'location'})],metric_params,24,y,24,16)
        y+=16
    search_id=f'soc-alerts-{slug}'
    search=s.search_object('ib-red · '+title+' · Eventos',q)
    search['attributes']['description']='Eventos del cliente; ordenar y filtrar por prioridad, equipo y acción.'
    search['attributes']['columns']=['timestamp','rule.level','rule.description','location','data.dstip','data.unifi.action']
    objects.append(('search',search_id,search))
    idx=str(len(panels)+1);ref='panel_'+idx
    panels.append({'panelIndex':idx,'gridData':{'x':0,'y':y,'w':48,'h':23,'i':idx},'embeddableConfig':{},'panelRefName':ref,'version':'7.10.0'})
    refs.append({'name':ref,'type':'search','id':search_id})
    add('help','Cómo interpretar esta vista','markdown',[],{'markdown':'### Interpretación y seguimiento\n**Eventos recibidos** incluye actividad informativa. **Detecciones** aplica nivel ≥ 8; no equivale a ataques confirmados. **Bloqueos** cuenta únicamente acciones explícitas `blocked` de UniFi; otros fabricantes requieren campos validados. Las tablas de IP y el mapa muestran solo datos disponibles. La geolocalización es aproximada.\n\nPara incidencias, dispositivos, cobertura y recomendaciones: [abrir Centro SOC](https://soc.ibred.es/gestion/). Estas vistas son internas: el filtro por cliente no sustituye los permisos de acceso.','fontSize':12,'openLinksInNewTab':True},0,y+23,48,11)
    dashboard={'attributes':{'title':'ib-red empresas · '+title,'description':f'Seguridad gestionada · {len(sources)} origen(es) configurado(s). Filtros por IP verificada; vista interna SOC.','hits':0,'panelsJSON':json.dumps(panels),'optionsJSON':json.dumps({'useMargins':True,'hidePanelTitles':False}),'version':1,'timeRestore':True,'timeFrom':'now-7d','timeTo':'now','refreshInterval':{'pause':True,'value':60000},'kibanaSavedObjectMeta':{'searchSourceJSON':s.search_source(q,with_index=False)}},'references':refs}
    objects.append(('dashboard','soc-'+slug,dashboard))
    return objects

def sync(s):
    clients=s.clients_and_sources();auth=s.credentials()
    status,index=s.request('/api/saved_objects/index-pattern/'+s.INDEX_PATTERN,auth)
    if status!=200:raise RuntimeError('Missing Wazuh index pattern')
    fields=json.loads(index['attributes'].get('fields','[]'))
    geo=any(f['name']=='GeoLocation.location' and f['type']=='geo_point' and f.get('aggregatable') for f in fields)
    objects=[]
    for c in clients:objects.extend(build(s,'client-'+c['code'],c['name'],c['sources'],has_geo=geo))
    all_sources=set().union(*(c['sources'] for c in clients)) if clients else set()
    objects.extend(build(s,'general','SOC general',all_sources,clients,geo))
    # Preserve originals once for recovery before updating the existing portal links.
    backup=Path('/home/deploy/soc-dashboard-design-originals.json')
    if not backup.exists():
        originals=[]
        for kind,oid,_ in objects:
            status,body=s.request(f'/api/saved_objects/{kind}/{oid}',auth)
            if status==200:originals.append({'type':kind,'id':oid,'attributes':body['attributes'],'references':body.get('references',[])})
        import os
        fd=os.open(backup,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as f:json.dump(originals,f)
    for kind,oid,body in objects:
        print(kind,oid,s.upsert(auth,kind,oid,body,list(body['attributes'])))
    print('Dashboards:',len(clients)+1,'Geo support:',geo,'Objects:',len(objects))

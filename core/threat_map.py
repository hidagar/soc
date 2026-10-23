"""Local GeoIP enrichment and scoped, bounded geography of real SOC evidence."""
import ipaddress
import os
import hashlib
import json
from pathlib import Path
from collections import Counter
from datetime import timedelta,datetime,timezone as dt_timezone
from django.contrib.auth.decorators import login_required
from django.views.decorators.cache import never_cache
from django.http import JsonResponse
from django.shortcuts import get_object_or_404,render
from django.utils import timezone
from django.urls import reverse
from django.db.models import Q, Count
from django.db.models import F
from .models import Client,SecurityEvidence,WorkerState

GEO_DB='/etc/soc-portal/geoip-country.mmdb'

def update_geoip_database():
    """Monthly public dataset download; no customer addresses leave the VM."""
    import gzip,io,tempfile,urllib.request
    import maxminddb
    now=timezone.now()
    path=Path(os.environ.get('SOC_GEOIP_DATABASE',GEO_DB))
    state,_=WorkerState.objects.get_or_create(name='geo-database')
    if state.last_run_at and now-state.last_run_at<timedelta(hours=24):
        return
    state.last_run_at=now;state.save()
    temporary=None
    try:
        if path.exists():
            with maxminddb.open_database(str(path)) as reader:
                built=reader.metadata().build_epoch
            if datetime.fromtimestamp(built,dt_timezone.utc).strftime('%Y-%m')==now.strftime('%Y-%m'):
                state.last_success_at=now;state.error='';state.save();return
        url=f'https://download.db-ip.com/free/dbip-country-lite-{now:%Y-%m}.mmdb.gz'
        request=urllib.request.Request(url,headers={'User-Agent':'IBRed-SOC/1.0 (+https://soc.ibred.es)'})
        with urllib.request.urlopen(request,timeout=25) as response:
            compressed=response.read(15*1024*1024+1)
        if len(compressed)>15*1024*1024:raise ValueError('Dataset demasiado grande')
        with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as source:
            content=source.read(32*1024*1024+1)
        if len(content)>32*1024*1024:raise ValueError('Dataset demasiado grande')
        path.parent.mkdir(parents=True,exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=path.parent,delete=False) as target:
            temporary=Path(target.name);target.write(content)
        with maxminddb.open_database(str(temporary)) as reader:
            built=reader.metadata().build_epoch
            if now-datetime.fromtimestamp(built,dt_timezone.utc)>timedelta(days=62):raise ValueError('Dataset antiguo')
            if not reader.get('8.8.8.8'):raise ValueError('Dataset inválido')
        os.chmod(temporary,0o600);os.replace(temporary,path);temporary=None
        state.last_success_at=now;state.error='';state.details={'provider':'DB-IP Lite','release':now.strftime('%Y-%m')};state.save()
    except Exception:
        state.error='Actualización GeoIP pendiente; se conserva la última base válida.';state.save()
    finally:
        if temporary:temporary.unlink(missing_ok=True)

def backfill_map_history():
    from .operations import reconcile_security,source_map
    state=WorkerState.objects.filter(name='map-history').first()
    owners,_=source_map()
    signature=hashlib.sha256(json.dumps([(s,owners[s].pk) for s in sorted(owners)]).encode()).hexdigest()
    if state and state.details.get('completed_until') and state.details.get('source_signature')==signature:
        return 0
    return reconcile_security(pages=2,state_name='map-history',initial_days=30)

def public_ip(value):
    try:
        address=ipaddress.ip_address(value)
        return str(address) if address.is_global else None
    except (ValueError,TypeError):
        return None

def peer_for(event):
    source=public_ip(event.source_ip)
    destination=public_ip(event.destination_ip)
    if source:
        return source,'inbound' if event.destination_ip and not destination else 'external','source'
    if destination:
        return destination,'outbound','destination'
    return None,'internal','none'

def enrich_geography(limit=500):
    """Root worker only. Never contacts an IP lookup service."""
    state,_=WorkerState.objects.get_or_create(name='geography')
    now=timezone.now();state.last_run_at=now
    path=Path(os.environ.get('SOC_GEOIP_DATABASE',GEO_DB))
    try:
        import maxminddb
        with maxminddb.open_database(str(path)) as reader:
            built=reader.metadata().build_epoch
            shapes=json.loads((Path(__file__).resolve().parent.parent/'static/maps/world.json').read_text())
            positions={f['properties']['code']:f['properties'] for f in shapes['features']}
            recent=SecurityEvidence.objects.filter(Q(geography={})|Q(geography__database_epoch__isnull=True)|~Q(geography__database_epoch=built),observed_at__gte=now-timedelta(days=90)).exclude(category='application_policy').order_by('-observed_at')[:limit]
            count=0
            for event in recent:
                peer,direction,role=peer_for(event)
                geo={'status':'internal' if not peer else 'unknown','peer_ip':peer,'direction':direction,'role':role,'database_epoch':built}
                row=reader.get(peer) if peer else None
                if row:
                    country=row.get('country') or row.get('registered_country') or {}
                    location=row.get('location') or {}
                    code=country.get('iso_code')
                    lat,lon=location.get('latitude'),location.get('longitude')
                    shape=positions.get(code,{})
                    if lat is None and shape.get('label'):
                        lon,lat=shape['label']
                    if code and isinstance(lat,(int,float)) and isinstance(lon,(int,float)) and -90<=lat<=90 and -180<=lon<=180:
                        geo.update(status='located',country_code=code,country=shape.get('name') or country.get('names',{}).get('es') or country.get('names',{}).get('en') or code,lat=lat,lon=lon,accuracy_km=location.get('accuracy_radius'))
                SecurityEvidence.objects.filter(pk=event.pk).update(geography=geo)
                count+=1
        state.last_success_at=now;state.error=''
        state.details={'database_date':datetime.fromtimestamp(built,dt_timezone.utc).isoformat(),'provider':'DB-IP Lite','updated':count}
        state.save()
        return count
    except Exception:
        state.error='Geolocalización pendiente: revisar la base GeoIP local y el servicio protegido.'
        state.save()
        return 0

def filters(request):
    client_id=request.GET.get('client','')
    client=get_object_or_404(Client,pk=client_id) if client_id.isdigit() else None
    days=int(request.GET.get('days','7')) if request.GET.get('days','7') in ('1','7','30') else 7
    action=request.GET.get('action','all')
    if action not in ('all','blocked','allowed','unknown'):action='all'
    direction=request.GET.get('direction','all')
    if direction not in ('all','inbound','outbound','external','internal'):direction='all'
    return client,days,action,direction

def map_data(client=None,days=7,action='all',direction='all',with_recent=True):
    now=timezone.now();start=now-timedelta(days=days)
    qs=SecurityEvidence.objects.filter(client_scope_id=F('device__site__client_id'),observed_at__gte=start,observed_at__lte=now).exclude(category='application_policy')
    if client:qs=qs.filter(client_scope_id=client.pk)
    if action!='all':qs=qs.filter(action=action)
    if direction!='all':qs=qs.filter(geography__direction=direction)
    recent_window=now-timedelta(minutes=15)
    totals=qs.aggregate(total=Count('uid'),recent_total=Count('uid',filter=Q(observed_at__gte=recent_window)),
        recent_allowed=Count('uid',filter=Q(observed_at__gte=recent_window,action='allowed')),
        recent_critical=Count('uid',filter=Q(observed_at__gte=recent_window,level__gte=12)))
    total=totals['total']
    # Solo los campos que se agregan: cargar 20 000 objetos con sus relaciones en cada consulta del mapa era lento.
    rows=list(qs.order_by('-observed_at').values_list('observed_at','action','engine','geography')[:20000])
    countries={};points={};actions=Counter();engines=Counter();flow=Counter();timeline=Counter();recent=[]
    for observed_at,event_action,engine,g in rows:
        g=g if isinstance(g,dict) else {};actions[event_action]+=1;engines[engine]+=1
        status=g.get('status','pending');flow[status]+=1
        timeline[timezone.localtime(observed_at).strftime('%d/%m')]+=1
        if status=='located':
            code=g['country_code']
            c=countries.setdefault(code,{'code':code,'name':g['country'],'count':0,'blocked':0,'allowed':0})
            c['count']+=1
            if event_action in ('blocked','allowed'):c[event_action]+=1
            key=(code,g.get('direction','external'),event_action)
            p=points.setdefault(key,{'code':code,'country':g['country'],'lat':g['lat'],'lon':g['lon'],'direction':g.get('direction','external'),'action':event_action,'count':0,'recent_count':0,'latest_at':observed_at.isoformat()})
            p['count']+=1
            if observed_at>=recent_window:p['recent_count']+=1
    # Los 20 últimos con su detalle, solo para el personal del SOC.
    for e in (qs.select_related('device__site__client','asset').order_by('-observed_at')[:20] if with_recent else ()):
        g=e.geography if isinstance(e.geography,dict) else {};status=g.get('status','pending')
        recent.append({'uid':e.uid,'observed_at':e.observed_at.isoformat(),'level':e.level,'contract_version':e.interpretation.get('contract_version'),'soc_priority':e.interpretation.get('soc_priority'),'vendor_severity':e.interpretation.get('vendor_severity'),'country_code':g.get('country_code',''),'client_id':e.client_scope_id,'time':timezone.localtime(e.observed_at).strftime('%d/%m %H:%M'),'client':e.device.site.client.name,'site':e.interpretation.get('site_name') or e.device.site.name,'device':e.device.name,'signature':e.signature,'action':e.action,'country':g.get('country') or ('Red privada' if status=='internal' else 'Sin ubicación'),'direction':g.get('direction','pending'),'peer':g.get('peer_ip') or '', 'asset':e.identified_label,'asset_ip':e.asset.ip if e.asset else '', 'incident_url':reverse('incident_detail',args=[e.incident_id]) if e.incident_id else ''})
    state=WorkerState.objects.filter(name='geography').first()
    history=WorkerState.objects.filter(name='map-history').first()
    return {'generated_at_iso':now.isoformat(),'watch':{'window_minutes':15,'total':totals['recent_total'],'allowed':totals['recent_allowed'],'critical':totals['recent_critical']},'generated_at':timezone.localtime(now).strftime('%H:%M:%S'),'client':client.name if client else 'Clientes autorizados','days':days,'total':total,'displayed':len(rows),'limited':total>len(rows),'blocked':actions['blocked'],'allowed':actions['allowed'],'unknown_action':len(rows)-actions['blocked']-actions['allowed'],'located':flow['located'],'private':flow['internal'],'unknown_location':flow['unknown'],'pending':flow['pending'],'countries':sorted(countries.values(),key=lambda x:-x['count']),'points':list(points.values()),'engines':dict(engines),'timeline':[{'date':timezone.localtime(now-timedelta(days=i)).strftime('%d/%m'),'count':timeline[timezone.localtime(now-timedelta(days=i)).strftime('%d/%m')]} for i in reversed(range(days+1))],'recent':recent,'geo_database':state.details.get('database_date','')[:10] if state else '', 'geo_error':state.error if state else 'Geolocalización pendiente','history_pending':not history or not history.details.get('completed_until'),'last_event':timezone.localtime(rows[0][0]).strftime('%d/%m %H:%M') if rows else None}

@login_required
@never_cache
def threat_map(request):
    client,days,action,direction=filters(request)
    return render(request,'threat_map.html',{'map_client':client,'clients':Client.objects.all(),'days':days,'action':action,'direction':direction,'map_payload':map_data(client,days,action,direction)})

@login_required
@never_cache
def threat_map_data(request):
    client,days,action,direction=filters(request)
    return JsonResponse(map_data(client,days,action,direction))

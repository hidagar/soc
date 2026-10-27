"""Bounded investigation of normalized evidence; no external IP lookups."""
import ipaddress
from collections import Counter
from datetime import timedelta
from urllib.parse import urlencode
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.shortcuts import render, get_object_or_404
from django.http import Http404
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET
from .models import Client, SecurityEvidence, CustomerTask

LIMIT=10000

def selection(request):
    raw=request.GET.get('client','')
    if raw and (not raw.isdigit() or len(raw)>10):raise Http404
    client=get_object_or_404(Client,pk=raw) if raw else None
    days=int(request.GET.get('days','7')) if request.GET.get('days','7') in ('1','7','30') else 7
    country=request.GET.get('country','').upper()
    if country and (len(country)!=2 or not country.isascii() or not country.isalpha()):raise Http404
    action=request.GET.get('action','all')
    if action not in ('all','blocked','allowed','unknown'):action='all'
    return client,days,country,action

def evidence_queryset(client=None,days=7,country='',action='all'):
    now=timezone.now()
    qs=SecurityEvidence.objects.filter(client_scope_id__isnull=False,observed_at__gte=now-timedelta(days=days),observed_at__lte=now).exclude(category='application_policy')
    if client:qs=qs.filter(client_scope_id=client.pk)
    # A reassigned firewall must not expose its new customer's name or inventory.
    from django.db.models import F
    qs=qs.filter(client_scope_id=F('device__site__client_id'))
    if country:qs=qs.filter(geography__country_code=country)
    if action!='all':qs=qs.filter(action=action)
    return qs

def ip_url(address,client_id=None,days=7):
    return reverse('ip_investigation')+'?'+urlencode({'ip':address,'days':days,**({'client':client_id} if client_id else {})})

def summarize(qs):
    return {'total':qs.count(),'blocked':qs.filter(action='blocked').count(),
        'allowed':qs.filter(action='allowed').count(),'unknown':qs.exclude(action__in=['blocked','allowed']).count(),
        'devices':qs.values('device_id').distinct().count(),
        'identified':qs.filter(identity__confidence__in=['manual','recent']).values('device_id','identity__label').distinct().count()}

@login_required
@never_cache
@require_GET
def explore(request):
    client,days,country,action=selection(request)
    qs=evidence_queryset(client,days,country,action)
    direction=request.GET.get('direction','all')
    if direction in ('inbound','outbound','external','internal'):qs=qs.filter(geography__direction=direction)
    else:direction='all'
    from django.core.paginator import Paginator
    page=Paginator(qs.select_related('device__site__client').order_by('-observed_at','uid'),50).get_page(request.GET.get('page'))
    for e in page:
        e.source_url=ip_url(e.source_ip,e.client_scope_id,days) if e.source_ip else ''
        e.destination_url=ip_url(e.destination_ip,e.client_scope_id,days) if e.destination_ip else ''
    params=request.GET.copy();params.pop('page',None)
    return render(request,'security_explore.html',{'selected':client,'clients':Client.objects.all(),'days':days,'country':country,'action':action,'direction':direction,'metrics':summarize(qs),'page':page,'query':params.urlencode()})

@login_required
@never_cache
@require_GET
def ip_detail(request):
    try:address=str(ipaddress.ip_address(request.GET.get('ip','')))
    except ValueError:raise Http404
    client,days,_,_=selection(request)
    qs=evidence_queryset(client,days).filter(Q(source_ip=address)|Q(destination_ip=address))
    if not qs.exists():raise Http404
    count=qs.count()
    rows=list(qs.select_related('device__site__client','asset').order_by('-observed_at','uid')[:LIMIT])
    timeline=Counter();ports=Counter();engines=Counter();targets={};countries=Counter();recommendations=Counter()
    for e in rows:
        timeline[timezone.localtime(e.observed_at).strftime('%Y-%m-%d')]+=1
        if e.destination_port:ports[e.destination_port]+=1
        engines[e.engine]+=1
        if e.geography.get('peer_ip')==address and e.geography.get('country'):countries[e.geography['country']]+=1
        counterpart=e.destination_ip if e.source_ip==address else e.source_ip
        if counterpart:
            key=(e.device_id,counterpart)
            item=targets.setdefault(key,{'ip':counterpart,'device':e.device.name,'site':e.device.site.name,'client':e.device.site.client.name,'count':0,'identity':set(),'url':ip_url(counterpart,e.client_scope_id,days)})
            item['count']+=1
            if e.asset_id and e.asset.ip==counterpart and e.identity.get('confidence') in ('recent','manual'):
                item['identity'].add(e.identity.get('label',''))
        if e.recommendation:recommendations[e.recommendation]+=1
    for item in targets.values():item['identity']=' / '.join(sorted(filter(None,item['identity']))) or 'Identidad histórica sin confirmar'
    chart=[]
    now=timezone.now()
    for i in reversed(range(days+1)):
        key=timezone.localtime(now-timedelta(days=i)).strftime('%Y-%m-%d')
        chart.append({'date':key,'count':timeline[key],'height':max(3,round(timeline[key]/max(1,*timeline.values())*90))})
    from .asn import lookup as asn_lookup
    from .reputation import lookup as reputation_lookup
    # Acceso directo para bloquearla en la lista de cada cliente afectado (solo IPs públicas y con permiso).
    block_clients=[]
    if ipaddress.ip_address(address).is_global and request.user.has_perm('core.manage_operations'):
        ids=set(qs.order_by().values_list('client_scope_id',flat=True).distinct())
        block_clients=[{'name':c.name,'url':reverse('blocklist_detail',args=[c.pk])+'?'+urlencode({'network':address})+'#bloqueo-manual'}
                       for c in Client.objects.filter(pk__in=ids,active=True).order_by('name')]
    return render(request,'ip_investigation.html',{'block_clients':block_clients,'asn':asn_lookup(address),'reputation':reputation_lookup(address),'address':address,'public':ipaddress.ip_address(address).is_global,'selected':client,'days':days,
        'metrics':summarize(qs),'limited':count>LIMIT,'sample':len(rows),'first':qs.order_by('observed_at').first().observed_at,'last':rows[0].observed_at,
        'events':rows[:100],'targets':sorted(targets.values(),key=lambda x:-x['count'])[:50],'timeline':chart,'ports':ports.most_common(12),
        'engines':engines.most_common(),'countries':list(countries),'recommendations':[r for r,_ in recommendations.most_common(3)]})

def customer_security_summary(client):
    qs=evidence_queryset(client,7)
    result=summarize(qs)
    result['tasks']=CustomerTask.objects.filter(incident__client=client,visible=True,status__in=['pending','rework','submitted']).count()
    result['last']=qs.order_by('-observed_at').values_list('observed_at',flat=True).first()
    return result

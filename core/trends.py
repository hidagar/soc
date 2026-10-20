from datetime import datetime,time,timedelta
from django.contrib.auth.decorators import login_required
from django.db.models import Count,Q
from django.db.models.functions import TruncDate
from django.shortcuts import get_object_or_404,render
from django.utils import timezone
from .models import Client,SecurityEvidence,IncidentAction,FeedBucket

def period_metrics(rows,start,end):
    data=rows.filter(observed_at__gte=start,observed_at__lt=end).aggregate(total=Count('uid'),blocked=Count('uid',filter=Q(action='blocked')),allowed=Count('uid',filter=Q(action='allowed')),assets=Count('asset',distinct=True))
    return data

def trend_context(client,now=None):
    now=now or timezone.now()
    today=timezone.localdate(now);monday=today-timedelta(days=today.weekday())
    start=timezone.make_aware(datetime.combine(monday,time.min))
    previous_start=start-timedelta(days=7);previous_end=now-timedelta(days=7)
    rows=SecurityEvidence.objects.filter(device__site__client=client).exclude(category='application_policy')
    current=period_metrics(rows,start,now)
    previous=period_metrics(rows,previous_start,previous_end)
    comparisons=[]
    for key,label in [('total','Detecciones recibidas'),('blocked','Bloqueadas'),('allowed','Permitidas'),('assets','Equipos identificados afectados')]:
        old,new=previous[key],current[key]
        comparisons.append({'label':label,'current':new,'previous':old,'difference':new-old,'percent':round((new-old)*100/old,1) if old else None})
    weeks=[]
    for i in reversed(range(8)):
        s=start-timedelta(days=7*i);e=min(s+timedelta(days=7),now)
        m=period_metrics(rows,s,e)
        hours=FeedBucket.objects.filter(device__site__client=client,hour__gte=s,hour__lt=e).values('hour').distinct().count()
        weeks.append({'start':timezone.localdate(s),'count':m['total'],'blocked':m['blocked'],'allowed':m['allowed'],'observed':bool(hours or m['total']),'hours':hours,'provisional':i==0})
    peak=max([w['count'] for w in weeks]+[1])
    for w in weeks:w['height']=max(2,round(w['count']/peak*100))
    assets=list(rows.filter(observed_at__gte=start,observed_at__lt=now,asset__isnull=False).values('asset_id','asset__name','asset__discovered_name','asset__ip','device__site__name').annotate(count=Count('uid'),allowed=Count('uid',filter=Q(action='allowed'))).order_by('-allowed','-count')[:10])
    for a in assets:a['label']=a['asset__name'] or a['asset__discovered_name'] or a['asset__ip']
    repeating=rows.filter(observed_at__gte=now-timedelta(days=30),observed_at__lt=now).values('device__name','asset__ip','signature').annotate(count=Count('uid'),days=Count(TruncDate('observed_at'),distinct=True)).filter(days__gte=2).order_by('-days','-count')[:10]
    actions=IncidentAction.objects.filter(incident__client=client)
    return {'client':client,'current_start':monday,'previous_start':timezone.localdate(previous_start),'current_end':timezone.localtime(now),'previous_end':timezone.localtime(previous_end),'comparisons':comparisons,'weeks':weeks,'top_assets':assets,'repeating':repeating,'pending_actions':actions.exclude(status__in=['done','cancelled']).count(),'overdue_actions':actions.exclude(status__in=['done','cancelled']).filter(due_at__lt=now).count(),'completed_actions':actions.filter(status='done',completed_at__gte=start,completed_at__lt=now).count()}

@login_required
def client_trends(request,client_pk):
    return render(request,'client_trends.html',trend_context(get_object_or_404(Client,pk=client_pk)))

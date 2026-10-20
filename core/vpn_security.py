"""VPN access observations, separate from threat and tunnel-health counters."""
import hashlib, json, re
from collections import defaultdict, Counter
from datetime import timedelta
import os
from django.contrib.auth.decorators import login_required
from django.db import models
from django.db.models import F
from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET
from .scope import ScopedManager

class VpnAccessEvent(models.Model):
    uid=models.CharField(max_length=64,primary_key=True)
    device=models.ForeignKey('core.Device',on_delete=models.PROTECT)
    client_scope_id=models.PositiveBigIntegerField(db_index=True,editable=False)
    observed_at=models.DateTimeField(db_index=True)
    peer_ip=models.GenericIPAddressField(null=True)
    outcome=models.CharField(max_length=12)
    protocol=models.CharField(max_length=24)
    country=models.CharField(max_length=2,blank=True)
    objects=ScopedManager()
    customer_lookup='client_scope_id'
    def save(self,*args,**kwargs):
        if not self._state.adding:
            previous=type(self)._base_manager.filter(pk=self.pk).values_list('client_scope_id',flat=True).first()
            if previous is not None and previous!=self.client_scope_id:raise ValueError('La empresa histórica del acceso VPN no puede cambiar.')
        super().save(*args,**kwargs)
    class Meta:ordering=['-observed_at']

def parse(source):
    from .operations import ip
    data=source.get('data') if isinstance(source.get('data'),dict) else {}
    rule=source.get('rule') if isinstance(source.get('rule'),dict) else {}
    decoder=source.get('decoder') if isinstance(source.get('decoder'),dict) else {}
    groups=rule.get('groups') if isinstance(rule.get('groups'),list) else []
    name=str(decoder.get('name','')).casefold()
    protocol=str(data.get('protocol') or data.get('service') or '').casefold()
    # Require a VPN-specific decoder, group or explicit service before reading outcome.
    known={'openvpn','ipsec','wireguard','sslvpn','ssl-vpn','l2tp'}
    matches=sorted(known.intersection({name,protocol,*[str(g).casefold() for g in groups]}))
    if not matches:return None
    value=str(data.get('status') or data.get('action') or '').casefold()
    outcome='failed' if value in ('failed','failure','authentication_failed','login_failed','auth_failed') else 'success' if value in ('success','authenticated','authentication_success','login_success') else 'unknown'
    # Wazuh authentication groups are explicit outcomes; never infer from severity.
    if outcome=='unknown':
        failed='authentication_failed' in groups
        success='authentication_success' in groups
        if failed!=success:outcome='failed' if failed else 'success'
    return {'protocol':matches[0],'peer_ip':ip(data.get('srcip') or data.get('src_ip') or data.get('remote_ip')),'outcome':outcome}

def record(source,device,stamp):
    row=parse(source)
    if row is None:return
    # No usernames, messages, credentials, or full raw records are persisted.
    uid=hashlib.sha256(json.dumps([device.pk,source.get('id'),stamp.isoformat(),row],sort_keys=True).encode()).hexdigest()
    if VpnAccessEvent.objects.filter(pk=uid).exists():return
    country=''
    if row['peer_ip']:
        from .threat_map import public_ip,GEO_DB
        if public_ip(row['peer_ip']):
            try:
                import maxminddb
                with maxminddb.open_database(os.environ.get('SOC_GEOIP_DATABASE',GEO_DB)) as reader:
                    geo=reader.get(row['peer_ip']) or {}
                    country=(geo.get('country') or {}).get('iso_code','')
            except (OSError,ValueError,ImportError):pass
    VpnAccessEvent.objects.create(uid=uid,device=device,client_scope_id=device.site.client_id,observed_at=stamp,country=country if re.fullmatch('[A-Z]{2}',str(country)) else '',**row)

def analysis(rows,start):
    peers=defaultdict(list)
    historical_countries=defaultdict(set)
    for row in rows:
        if row.observed_at<start and row.country:historical_countries[row.device_id].add(row.country)
    for row in rows:
        if row.peer_ip:peers[(row.device_id,row.peer_ip)].append(row)
    notices=[]
    for (_,peer),events in peers.items():
        events.sort(key=lambda e:(e.observed_at,e.uid))
        recent=[e for e in events if e.observed_at>=start]
        if not recent:continue
        failures=[];burst=None;follow=None
        for e in events:
            failures=[f for f in failures if e.observed_at-f.observed_at<=timedelta(minutes=15)]
            if e.outcome=='failed':
                failures.append(e)
                if len(failures)>=5 and e.observed_at>=start:burst=(len(failures),e)
            elif e.outcome=='success' and len(failures)>=5 and e.observed_at>=start:follow=e
        device=recent[-1].device
        if burst:notices.append({'peer':peer,'device':device,'title':'Fallos de autenticación repetidos','detail':f'Al menos {burst[0]} fallos desde esta IP en una ventana de 15 minutos. Revisar credenciales y accesos autorizados.','at':burst[1].observed_at})
        if follow:notices.append({'peer':peer,'device':device,'title':'Acceso correcto después de fallos desde la misma IP','detail':'Coincidencia temporal por IP y firewall; no se acredita que sea la misma cuenta. Comprobar el acceso antes de concluir compromiso.','at':follow.observed_at})
        if not any(e.observed_at<start for e in events):notices.append({'peer':peer,'device':device,'title':'Origen sin antecedentes en la ventana disponible','detail':'No observado en el histórico cargado anterior al periodo. Puede ser un acceso habitual sin datos anteriores; no implica amenaza.','at':recent[-1].observed_at})
        new_countries={e.country for e in recent if e.country}-historical_countries[device.pk]
        if historical_countries[device.pk] and new_countries:
            notices.append({'peer':peer,'device':device,'title':'País sin antecedentes en el histórico del firewall','detail':'País aproximado: '+', '.join(sorted(new_countries))+'. Contrastar el acceso con el cliente. Una VPN, proxy o cambio de GeoIP puede explicar la diferencia; no se atribuye a una cuenta.','at':recent[-1].observed_at})
    return sorted(notices,key=lambda n:n['at'],reverse=True)[:100]

@login_required
@never_cache
@require_GET
def dashboard(request):
    from .investigation import selection
    from .models import Client
    client,days,_,_=selection(request)
    now=timezone.now();start=now-timedelta(days=days)
    qs=VpnAccessEvent.objects.filter(client_scope_id=F('device__site__client_id'),observed_at__gte=start-timedelta(days=30),observed_at__lte=now)
    if client:qs=qs.filter(client_scope_id=client.pk)
    total=qs.count()
    rows=list(qs.select_related('device__site__client').order_by('-observed_at','uid')[:10000])
    current=[e for e in rows if e.observed_at>=start]
    counts=Counter(e.outcome for e in current)
    return render(request,'vpn_security.html',{'selected':client,'clients':Client.objects.all(),'days':days,'counts':dict(counts),'total':len(current),
        'limited':total>10000,'events':current[:100],'notices':analysis(rows,start),'last':current[0].observed_at if current else None})

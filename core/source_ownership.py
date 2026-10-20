"""Time-bounded source ownership shared by reporting and alert attribution."""
import hashlib,json
from datetime import datetime,timedelta
from django.db import transaction
from django.db.models import F,Q
from django.utils import timezone
from .models import SourceOwnership,ExportConfiguration,SecureLogChannel,WorkerState,SecurityEvidence


def desired():
    owners={}
    known=SourceOwnership._base_manager.values_list('source',flat=True)
    # Lifecycle maintenance must see conflicting sources outside the request's
    # scope. It returns no customer data to a view.
    # A temporarily unready receiver/reprovision does not transfer ownership.
    # A never-verified new source cannot obtain an initial historical binding.
    exports=ExportConfiguration._base_manager.filter(Q(receiver_ready=True)|Q(source_ip__in=known)).exclude(source_ip=None)
    for source,cid in exports.values_list('source_ip','device__site__client_id'):
        owners.setdefault(source,set()).add(cid)
    channels=SecureLogChannel._base_manager.filter(Q(receiver_ready=True)|Q(source_identity__in=known)).filter(client_scope_id=F('device__site__client_id'))
    for source,cid in channels.values_list('source_identity','client_scope_id'):
        owners.setdefault(source,set()).add(cid)
    return {source:next(iter(ids)) if len(ids)==1 else None for source,ids in owners.items()}


def capture(sender=None,instance=None,raw=False,**kwargs):
    if instance is not None and not raw:instance._soc_sources_before=desired()


def synchronize(sender=None,instance=None,expected_before=None,raw=False,**kwargs):
    if raw:return
    before=expected_before if expected_before is not None else getattr(instance,'_soc_sources_before',None)
    wanted=desired()
    current={r.source:r for r in SourceOwnership._base_manager.filter(valid_until=None)}
    # Only record sources changed by this lifecycle operation. An unrelated save
    # must never silently legalize an earlier untracked bulk reassignment.
    if before is None:
        if {s:r.client_scope_id for s,r in current.items()}!=wanted:
            raise ValueError('El historial de fuentes requiere una revisión explícita.')
        return
    changes={s for s in set(wanted)|set(before) if (s in wanted)!=(s in before) or wanted.get(s)!=before.get(s)}
    if not changes:return
    with transaction.atomic():
        WorkerState.reserve('source-ownership-lock')
        wanted=desired();now=timezone.now()
        current={r.source:r for r in SourceOwnership._base_manager.filter(valid_until=None)}
        for source in changes:
            old=current.get(source)
            if old and source in wanted and old.client_scope_id==wanted[source]:continue
            if old is None and source not in wanted:continue
            if old is not None and (source not in before or old.client_scope_id!=before[source]):
                raise ValueError('Hay una reasignación anterior sin fecha verificada.')
            if old is None and source in before:
                raise ValueError('Falta el periodo de propiedad anterior.')
            if old:SourceOwnership._base_manager.filter(pk=old.pk).update(valid_until=now)
            if source in wanted:SourceOwnership._base_manager.create(source=source,client_scope_id=wanted[source],valid_from=now)


def report_scope(client,week):
    start=timezone.make_aware(datetime.combine(week,datetime.min.time()));end=start+timedelta(days=7)
    rows=list(SourceOwnership._base_manager.filter(client_scope_id=client.pk,valid_from__lt=end).filter(Q(valid_until=None)|Q(valid_until__gt=start)).order_by('source','valid_from','pk'))
    wanted=desired()
    current={r.source:r for r in SourceOwnership._base_manager.filter(valid_until=None)}
    sources={r.source for r in rows}|{s for s,cid in wanted.items() if cid==client.pk}
    # Bulk updates bypass lifecycle signals: refuse rather than invent a cutover.
    for source in sources:
        row=current.get(source)
        if (source in wanted and (row is None or row.client_scope_id!=wanted[source])) or (source not in wanted and row is not None):
            raise ValueError('El historial de propiedad de la fuente requiere revisión.')
    clauses=[];manifest=[]
    for r in rows:
        low=max(start,r.valid_from);high=min(end,r.valid_until or end)
        clauses.append({'bool':{'filter':[{'term':{'location':r.source}},{'range':{'timestamp':{'gte':low.isoformat(),'lt':high.isoformat()}}}]}})
        manifest.append([r.source,r.client_scope_id,low.isoformat(),high.isoformat()])
    fingerprint=hashlib.sha256(json.dumps(manifest,sort_keys=True).encode()).hexdigest()
    return sorted({r.source for r in rows}),{'bool':{'should':clauses,'minimum_should_match':1}} if clauses else {'match_none':{}},fingerprint


def owns_at(source,client_id,stamp):
    return SourceOwnership._base_manager.filter(source=source,client_scope_id=client_id,valid_from__lte=stamp).filter(Q(valid_until=None)|Q(valid_until__gt=stamp)).exists()


def coverage_metadata(client,week):
    start=timezone.make_aware(datetime.combine(week,datetime.min.time()));end=start+timedelta(days=7)
    rows=list(SourceOwnership._base_manager.filter(client_scope_id=client.pk,valid_from__lt=end).filter(Q(valid_until=None)|Q(valid_until__gt=start)))
    limited=False;pending=False
    for source in {r.source for r in rows}:
        first=min(r.valid_from for r in rows if r.source==source)
        if first<=start:continue
        limited=True
        devices=ExportConfiguration._base_manager.filter(source_ip=source,device__site__client_id=client.pk).values_list('device_id',flat=True)
        # Old evidence remains intact. It cannot be presented as zero detections
        # simply because its source predates the confirmed ownership baseline.
        if SecurityEvidence._base_manager.filter(device_id__in=devices,observed_at__gte=start,observed_at__lt=first).exists():pending=True
    return {'ownership_limited':limited,'ownership_pending':pending}

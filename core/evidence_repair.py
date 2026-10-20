"""Reinterpret an existing physical Wazuh alert without replacing its identity."""
from django.db import transaction
from django.db.models import F
from django.utils.dateparse import parse_datetime
from .models import SecurityEvidence,Asset
from .operations import normalize,ip,recommendation,source_map


@transaction.atomic
def repair_hillstone(evidence,source):
    # Reserve SQLite's writer before reading; avoid a read-to-write lock upgrade
    # while the independent mail/receiver workers are writing concurrently.
    SecurityEvidence.objects.filter(pk=evidence.pk).update(wazuh_published_at=F('wazuh_published_at'))
    # of=('self',): PostgreSQL no admite FOR UPDATE sobre el lado nulo del LEFT JOIN de asset.
    row=SecurityEvidence.objects.select_for_update(of=('self',)).select_related('device__site__client','asset').get(pk=evidence.pk)
    owner=source_map()[0].get(ip(source.get('location')))
    if (not owner or owner.pk!=row.device_id or row.client_scope_id!=owner.site.client_id
            or str(source.get('id') or '')!=row.wazuh_id
            or parse_datetime(str(source.get('timestamp') or ''))!=row.observed_at):
        raise ValueError('Physical event identity or historical owner does not match')
    from .hillstone_events import flow
    if not flow(source.get('data',{})):return False
    event=normalize(source)
    if event['engine']!='hillstone' or not event['security']:return False
    if row.asset_id and row.asset.ip!=event['affected_ip']:
        raise ValueError('Conflicting identified asset: manual review required')
    fields=('category','signature','action','source_ip','destination_ip','destination_port','level')
    from .asset_context import flow_projection
    projected={**row.flow,**flow_projection(source)}
    changed=any(getattr(row,key)!=event[key] for key in fields) or projected!=row.flow
    if not changed:return False
    geography_changed=(row.source_ip,row.destination_ip)!=(event['source_ip'],event['destination_ip'])
    for key in fields:setattr(row,key,event[key])
    if event['affected_ip'] and not row.asset_id:
        row.asset,_=Asset.objects.get_or_create(device=row.device,ip=event['affected_ip'])
        from .asset_identity import identity_snapshot
        row.identity=identity_snapshot(row.asset,row.observed_at)
    row.flow=projected;row.recommendation=recommendation(event)
    if geography_changed:row.geography={}
    row.wazuh_published_at=None
    row.save(update_fields=[*fields,'flow','identity','asset','recommendation','geography','wazuh_published_at'])
    if not row.incident_id:
        from .incident_episodes import attach_episode
        attach_episode(row,event)
    return True

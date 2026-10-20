import hashlib,json
from datetime import timedelta
from django.db import transaction
from django.db.models import Q,Min,Max,Count
from .models import Incident,IncidentUpdate,SecurityEvidence
from .security import audit

@transaction.atomic
def attach_episode(evidence,event):
    if event['category']=='application_policy':return None
    device=evidence.device;stamp=evidence.observed_at
    key=hashlib.sha256(json.dumps([device.site.client_id,device.pk,event['affected_ip'],event['engine'],event['category'],event['signature']],ensure_ascii=False).encode()).hexdigest()
    window=stamp-timedelta(hours=24)
    # Never merge different customers, affected IPs, engines or signatures.
    matching=SecurityEvidence.objects.filter(client_scope_id=device.site.client_id,device=device,asset=evidence.asset,engine=evidence.engine,
        category=evidence.category,signature=evidence.signature,observed_at__gte=window,observed_at__lte=stamp+timedelta(hours=24))
    recent=matching.exclude(incident=None).values_list('incident_id',flat=True)
    candidates=Incident.objects.filter(client=device.site.client,device=device).filter(Q(episode_key=key)|Q(pk__in=recent))
    candidate=candidates.filter(Q(last_seen_at__gte=window)|Q(observed_at__gte=window)).filter(observed_at__lte=stamp+timedelta(hours=24)).order_by('-last_seen_at','-pk').first()
    from .event_contract import metadata
    severity=event.get('soc_priority') or metadata(event)['soc_priority']
    urgent=severity in ('high','critical')
    if not candidate and not urgent and matching.count()<5:return None
    if candidate is None:
        candidate=Incident.objects.create(client=device.site.client,site=device.site,device=device,
            title=(event['signature'] or 'Detección de seguridad')[:220],
            description='Detección recibida desde '+event['engine']+'. Equipo: '+evidence.identified_label+'. Revisar las evidencias y su acción.',
            severity=severity,observed_at=stamp,last_seen_at=stamp,episode_key=key,
            fingerprint=hashlib.sha256((key+'|'+evidence.uid).encode()).hexdigest(),
            recommendation=evidence.recommendation,wazuh_alert_id=evidence.wazuh_id)
        IncidentUpdate.objects.create(incident=candidate,text='Caso creado con evidencia del firewall. Las repeticiones del mismo patrón se incorporan durante 24 horas desde la última detección.')
        audit('incident.automatic',candidate,{'count':matching.count()})
    ranks={'low':0,'medium':1,'high':2,'critical':3}
    if ranks[severity]>ranks[candidate.severity]:
        candidate.severity=severity
        IncidentUpdate.objects.create(incident=candidate,text='Gravedad elevada por una nueva detección: '+severity+'. Revisar la acción permitida/bloqueada de cada evidencia.')
    if candidate.status=='resolved' and stamp>(candidate.resolved_at or candidate.updated_at):
        candidate.status='open';candidate.resolved_at=None
        IncidentUpdate.objects.create(incident=candidate,text='Caso reabierto: nueva detección posterior a la resolución. Las guías anteriores deben revisarse de nuevo.')
        candidate.runbook_steps.update(done=False,completed_at=None,completed_by=None)
    # Attach only previously unassigned evidence, never steal another historical case.
    matching.filter(incident=None).update(incident=candidate)
    evidence.incident=candidate
    totals=candidate.evidence.aggregate(count=Count('uid'),first=Min('observed_at'),last=Max('observed_at'))
    candidate.occurrence_count=totals['count'];candidate.observed_at=min(candidate.observed_at,totals['first'] or stamp)
    candidate.last_seen_at=max(candidate.last_seen_at or stamp,totals['last'] or stamp)
    candidate.episode_key=key;candidate.save()
    return candidate

"""Differences between complete observations, without attributing unknown IDs/actors."""
from collections import Counter
from django.utils.dateparse import parse_datetime

MAX_HISTORY = 20
MAX_DETAILS = 40


def rules(catalogue):
    known, anonymous = {}, []
    for pair in catalogue.get('pairs', []):
        for row in pair['policies']:
            if row['id']:
                known[row['id']] = {**row, 'source_id':pair['source_id'], 'destination_id':pair['destination_id'],
                    'source':pair['source'], 'destination':pair['destination']}
            else: anonymous.append(row['fingerprint'])
    return known, Counter(anonymous)


def changes(before, after):
    old, old_unknown = rules(before); new, new_unknown = rules(after)
    details = []
    counts = {'added':0,'removed':0,'modified':0,'zones':0,'objects':0,
        'unidentified_added':sum((new_unknown-old_unknown).values()),
        'unidentified_removed':sum((old_unknown-new_unknown).values())}
    def add(kind, label, detail):
        counts[kind] += 1
        if len(details) < MAX_DETAILS: details.append({'name':label, 'detail':detail})
    for pid in sorted(set(old)|set(new)):
        a,b = old.get(pid),new.get(pid)
        row = b or a
        where = row['source'] + ' → ' + row['destination']
        if a is None: add('added', b['name'], 'Aparece en el catálogo · ' + where)
        elif b is None: add('removed', a['name'], 'Ya no aparece en el catálogo · ' + where)
        elif a['fingerprint'] != b['fingerprint']:
            reasons = []
            if a['enabled'] != b['enabled']: reasons.append('habilitada' if b['enabled'] else 'desactivada')
            if a['action'] != b['action']: reasons.append('acción: ' + b['action'])
            if a['index'] != b['index']: reasons.append(f"índice: {a['index']} → {b['index']}")
            if (a['source_id'],a['destination_id']) != (b['source_id'],b['destination_id']): reasons.append('par: ' + where)
            if a['name'] != b['name']: reasons.append('nombre actualizado')
            if a['logging'] != b['logging']: reasons.append('registro syslog ' + ('habilitado' if b['logging'] else 'desactivado'))
            if not reasons: reasons.append('criterios u otros campos consultados modificados')
            add('modified', b['name'], '; '.join(reasons) + '. Contrastar el detalle en UniFi.')
    old_zones={z['id']:z for z in before.get('zones',[])}
    new_zones={z['id']:z for z in after.get('zones',[])}
    for zid in sorted(set(old_zones)|set(new_zones)):
        a,b=old_zones.get(zid),new_zones.get(zid)
        if a is None: add('zones',b['name'],'Zona nueva en el catálogo.')
        elif b is None: add('zones',a['name'],'Zona ausente del catálogo actual.')
        elif (a['name'],sorted(a['network_ids'])) != (b['name'],sorted(b['network_ids'])):
            add('zones',b['name'],'Nombre o miembros de la zona modificados. Revisar segmentación.')
    old_objects=dict(before.get('list_fingerprints',[]));new_objects=dict(after.get('list_fingerprints',[]))
    names={r['id']:r['name'] for r in [*before.get('objects',[]),*after.get('objects',[])]}
    for oid in sorted(set(old_objects)|set(new_objects)):
        if old_objects.get(oid)!=new_objects.get(oid):
            add('objects',names.get(oid,'Objeto de coincidencia'),
                'Objeto añadido, retirado o contenido/tipo modificado. Revisar las políticas que lo utilizan.')
    changed = sum(counts.values()) > 0
    total_details=sum(counts[k] for k in ('added','removed','modified','zones','objects'))
    return counts, details, max(0,total_details-len(details)), changed


def track(previous, current):
    """First read is a baseline; failed reads never produce a change event."""
    history=list(previous.get('history',[]))[-MAX_HISTORY:] if isinstance(previous,dict) else []
    current['history']=history
    if current.get('status')!='checked':return current
    before=previous.get('catalogue',{}) if isinstance(previous,dict) else {}
    stamp=current['last_success_at']
    # Discard malformed/out-of-order observations rather than advancing history.
    old_stamp=previous.get('last_success_at') if isinstance(previous,dict) else None
    if old_stamp:
        try:
            if parse_datetime(old_stamp)>=parse_datetime(stamp):return current
        except (TypeError,ValueError):return current
    if not before:
        history.append({'at':stamp,'since':None,'baseline':True,'details':[], 'counts':{},'omitted':0})
    else:
        counts,details,omitted,changed=changes(before,current['catalogue'])
        if changed:history.append({'at':stamp,'since':old_stamp,'baseline':False,'details':details,
            'counts':counts,'omitted':omitted,'after_gap':previous.get('status')!='checked'})
    current['history']=history[-MAX_HISTORY:]
    return current


def presentation(scope):
    rows=[]
    for record in reversed(scope.get('history',[])):
        value={**record}
        try:
            value['at']=parse_datetime(record.get('at',''))
            value['since']=parse_datetime(record.get('since') or '')
        except (TypeError,ValueError):value['at']=value['since']=None
        rows.append(value)
    return rows

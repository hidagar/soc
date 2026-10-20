"""Configuration review via bounded GET queries; never asserts reachability from rule presence."""
import hashlib
import json
import re
from datetime import timedelta
from django.db import transaction
from django.utils import timezone
from .models import Device,ExposureCheck,ExposureFinding

def text(value,limit=240):
    return str(value or '')[:limit] if not isinstance(value,(dict,list)) else ''

def boolean(value):
    if value in (True,1,'1','true','yes'): return True
    if value in (False,0,'0','false','no'): return False
    return None

def active(row):
    if boolean(row.get('disabled')) is True: return False
    if 'enabled' in row: return boolean(row['enabled']) is True
    if 'disabled' in row: return boolean(row['disabled']) is False
    return False

def any_network(value):
    if text(value).lower() in ('any','*','0.0.0.0/0','::/0'): return True
    return False

def wan(interface):
    return bool(re.fullmatch(r'wan[0-9]*',interface.lower()))

def port_risk(value):
    """Resolve literal ports/ranges only; port aliases stay explicitly unknown."""
    v=text(value,8192).lower()
    if v in ('','any','*'): return 'all'
    if any(part.strip() in ('any','*') for part in v.split(',')):return 'all'
    ranges=[]
    for part in v.split(','):
        match=re.fullmatch(r'(\d+)(?:[:-](\d+))?',part.strip())
        if not match: return 'alias'
        low=int(match[1]);high=int(match[2] or match[1])
        if not 1<=low<=high<=65535: return 'alias'
        ranges.append((low,high))
    if any(low<=p<=high for low,high in ranges for p in (21,22,23,135,139,445,3389,5900,5985,5986)): return 'sensitive'
    return 'ordinary'

def normalized(row,vendor,section):
    if vendor=='unifi':
        nat=section=='nat'
        return {'id':text(row.get('_id'),180),'enabled':active(row),'name':text(row.get('name')),
            'interface':text(row.get('pfwd_interface') if nat else row.get('ruleset')),
            'source':text(row.get('src') if nat else row.get('src_address')) or 'any',
            'source_not':False,'destination':text(row.get('fwd') if nat else row.get('dst_address')) or 'any',
            'destination_not':False,'port':text(row.get('dst_port')),'target_port':text(row.get('fwd_port')),
            'protocol':text(row.get('proto') or row.get('protocol')),'direction':'in',
            'action':'pass' if nat else text(row.get('action')),'logging':boolean(row.get('log') if nat else row.get('logging')),
            'interface_not':False,'no_redirect':False}
    nat=section=='nat'
    return {'id':text(row.get('uuid'),180),'enabled':active(row),'name':text(row.get('descr') if nat else row.get('description')),
        'interface':text(row.get('interface')),'source':text((row.get('source.address') or row.get('source.network')) if nat else row.get('source_net')),
        'source_not':boolean(row.get('source.not') if nat else row.get('source_not')) is True,
        'destination':text(row.get('target') if nat else row.get('destination_net')),
        'destination_not':boolean(row.get('destination.not') if nat else row.get('destination_not')) is True,
        'port':text(row.get('destination.port') if nat else row.get('destination_port')),
        'target_port':text(row.get('local-port')) if nat else '',
        'protocol':text(row.get('protocol')),'direction':text(row.get('direction')) or 'in',
        'action':'pass' if nat else text(row.get('action')),'logging':boolean(row.get('log')),
        'interface_not':boolean(row.get('interfacenot')) is True,'no_redirect':boolean(row.get('nordr')) is True}

def assess(row,vendor,section,aliases=None,external_interfaces=()):
    r=normalized(row,vendor,section)
    if not r['id'] or not r['enabled'] or r['source_not'] or r['destination_not'] or r['interface_not'] or r['no_redirect']: return []
    from .exposure_context import enrich
    r,resolutions,unresolved=enrich(r,aliases or {})
    interfaces=[i.strip().lower() for i in r['interface'].split(',')]
    external=any(wan(i) or i in external_interfaces for i in interfaces) or (vendor=='unifi' and r['interface'].upper() in ('WAN_IN','WAN_LOCAL'))
    risk=port_risk(r['port']);unrestricted=any_network(r['source'])
    findings=[]
    def add(kind,title,severity,recommendation):
        evidence={k:v for k,v in r.items() if k not in ('id','enabled','interface_not','no_redirect')}
        evidence['scope']='WAN' if external else 'Interfaz interna o grupo'
        if resolutions:evidence['alias_resolution']=resolutions
        evidence['port_interpretation']='Alias sin resolver' if risk=='alias' else 'Puertos literales' if r['port'] else 'Sin restricción de puerto declarada'
        findings.append({'section':section,'remote_id':r['id'],'kind':kind,'title':title,'severity':severity,'evidence':evidence,'recommendation':recommendation})
    if section=='nat' and external and r['destination']:
        sensitive=risk=='sensitive' or port_risk(r['target_port'])=='sensitive'
        add('publication','Servicio publicado en WAN','high' if unrestricted and (sensitive or risk=='all') else 'medium',
            'Confirmar que el servicio y el equipo destino siguen siendo necesarios. Documentar su propietario; restringir orígenes y usar VPN para administración. Revisar la regla de filtro asociada y las actualizaciones del servicio antes de cambiarlo.')
    elif section=='filter' and r['action'].lower() in ('pass','accept') and r['direction']=='in' and unrestricted:
        self_target=r['destination'].lower() in ('(self)','this firewall','wanip','wan address') or (vendor=='unifi' and r['interface'].upper()=='WAN_LOCAL')
        if external and self_target and (risk in ('sensitive','all') or r['port'] in ('80','443','8443')):
            add('management','Permiso WAN hacia el propio firewall','high','Revisar si el puerto corresponde a administración. Limitar el acceso a VPN o direcciones autorizadas; comprobar el acceso de recuperación y el orden de reglas antes de aplicar cambios.')
        elif external and risk in ('all','sensitive'):
            add('wan_permission','Permiso WAN que requiere revisión','high','Validar destino, servicio y origen permitido. Sustituir permisos amplios por los flujos necesarios; revisar reglas anteriores, NAT y excepciones antes de modificar.')
        elif not external and r['interface'] and any_network(r['destination']) and risk=='all' and r['protocol'].lower() in ('','any','tcp','tcp/udp'):
            add('broad_rule','Regla de acceso amplia','medium','Documentar si esta regla es necesaria. Revisar segmentación entre usuarios, servidores, IoT y administración; diseñar excepciones de negocio antes de reducir el permiso.')
    return findings

def opnsense_rows(connection,path):
    from .provisioning import _api_request
    rows=[];total=None;seen=set()
    for page in range(1,6):
        data=_api_request(connection,f'{path}?rowCount=100&current={page}')
        if not isinstance(data.get('rows'),list): raise ValueError('Respuesta sin reglas.')
        count=int(data.get('total',-1))
        if count<0 or (total is not None and total!=count): raise ValueError('Listado incompleto o cambiante.')
        total=count
        for row in data['rows']:
            if not isinstance(row,dict) or not row.get('uuid') or row['uuid'] in seen: raise ValueError('Reglas incompletas o página repetida.')
            seen.add(row['uuid']);rows.append(row)
        if len(rows)==total: return rows
        # Some OPNsense releases prepend LAN anti-lockout entries without counting
        # them in total. Only this known internal shape can account for surplus rows.
        lockout=[r for r in rows if re.fullmatch(r'lockout_\d+',str(r.get('uuid',''))) and r.get('interface')=='lan' and not r.get('target')]
        if len(rows)>total and len(rows)-len(lockout)==total: return rows
        if len(rows)>total or not data['rows']: break
    raise ValueError('Límite de paginación o listado incompleto.')

def collect(device):
    sections={};coverage={};notes=[]
    if device.management_method=='ssh' and device.vendor=='opnsense':
        from .exposure_ssh import read_legacy
        check=ExposureCheck.objects.filter(device=device).first()
        external=check.external_interfaces if check else []
        try:
            data,aliases=read_legacy(device.ssh_connection)
            for section in ('filter','nat'):
                sections[section]=[f for row in data[section] for f in assess(row,'opnsense',section,aliases,external)]
                coverage[section]={'status':'partial','rules':len(data[section]),'findings':len(sections[section]),'preserve_unseen':True}
            coverage['context']={'aliases':{'status':'checked','count':len(aliases)},'interfaces':data['interfaces'],'external_interfaces':external}
            return sections,coverage,'Lectura SSH de reglas heredadas, aliases estáticos e interfaces. Las reglas de modelos modernos, automáticas/UPnP y orden efectivo no se evalúan; se conservan hallazgos anteriores no encontrados. No acredita accesibilidad. No se cambia el firewall.'
        except Exception:
            return {},{'filter':{'status':'unavailable'},'nat':{'status':'unavailable'}},'No se pudo leer la configuración por SSH. Revisar shell, confianza, credenciales y permisos root o sudo sin interacción. Se conservan las evidencias anteriores.'
    if device.management_method!='api' or device.vendor not in ('opnsense','unifi'):
        return {},{},'Configura API OPNsense/UniFi o SSH OPNsense para esta revisión. Hillstone y alta manual requieren un adaptador compatible.'
    paths={'filter':'/api/firewall/filter/search_rule','nat':'/api/firewall/d_nat/search_rule'} if device.vendor=='opnsense' else {'filter':'/network/api/s/default/rest/firewallrule','nat':'/network/api/s/default/rest/portforward'}
    aliases={};context={};external=[]
    check=ExposureCheck.objects.filter(device=device).first()
    if check:external=[str(i).lower() for i in check.external_interfaces]
    if device.vendor=='opnsense':
        from .provisioning import _api_request
        from .exposure_context import alias_catalog,interface_catalog
        try:
            aliases=alias_catalog(_api_request(device.opnsense_api,'/api/firewall/alias/get'))
            context['aliases']={'status':'checked','count':len(aliases)}
        except Exception:
            context['aliases']={'status':'unavailable'}
            notes.append('Aliases: no se pudo consultar el catálogo; se conservan los hallazgos anteriores que no reaparezcan.')
        try:context['interfaces']=interface_catalog(_api_request(device.opnsense_api,'/api/firewall/filter/get_interface_list'))
        except Exception:context['interfaces']=[]
    context['external_interfaces']=external
    for section,path in paths.items():
        try:
            if device.vendor=='opnsense': rows=opnsense_rows(device.opnsense_api,path)
            else:
                from .unifi_cloud import connector_json,decrypt_api_key
                c=device.unifi_cloud;data=connector_json(decrypt_api_key(c.encrypted_api_key),c.remote_host_id,path)
                if data.get('meta',{}).get('rc','ok')!='ok' or not isinstance(data.get('data'),list) or len(data['data'])>500: raise ValueError('Lista no válida.')
                rows=data['data']
                if any(not isinstance(r,dict) or not r.get('_id') for r in rows): raise ValueError('Regla sin identificador.')
            sections[section]=[f for row in rows for f in assess(row,device.vendor,section,aliases,external)]
            coverage[section]={'status':'checked','rules':len(rows),'findings':len(sections[section])}
            from .exposure_context import enrich
            coverage[section]['unresolved_rules']=[r['id'] for row in rows for r in [normalized(row,device.vendor,section)] if r['enabled'] and enrich(r,aliases)[2]]
            if context.get('aliases',{}).get('status')=='unavailable':coverage[section]['preserve_unseen']=True
        except Exception:
            coverage[section]={'status':'unavailable'}
            notes.append(('Reglas de filtro' if section=='filter' else 'Publicaciones NAT')+': no se pudo obtener el listado completo. Revisar permisos, conexión y compatibilidad.')
    coverage['context']=context
    notes.append('Revisión de configuración visible por API. Solo se expanden aliases estáticos completos de puertos, hosts e IP/redes, incluidos anidados. DNS, URL, GeoIP, aliases dinámicos, ciclos o expansiones excesivas quedan sin resolver. WAN identifica wan/wan2… y los identificadores externos declarados por el SOC. No se prueba accesibilidad ni se calcula el orden efectivo, UPnP o reglas automáticas.')
    if device.vendor=='unifi':
        from .unifi_zone_scope import collect as collect_zones
        previous_zones=check.coverage.get('zones') if check else None
        try:
            coverage['zones']=collect_zones(device.unifi_cloud,
                previous=previous_zones)
        except Exception:
            # Removing/losing the connector must not discard the last catalogue
            # and change history. None fails before any network read.
            coverage['zones']=collect_zones(None,previous=previous_zones)
        notes.append('UniFi: las zonas y políticas se consultan por la API oficial en su catálogo separado. Incluye índice observado y origen, con identidad/criterios incompletos señalados; no calcula la decisión efectiva por flujo ni acredita cobertura de UPnP/ACL. Cero reglas clásicas no acredita ausencia de permisos.')
        from .advanced_coverage import collect_unifi
        try:coverage['advanced']=collect_unifi(device.unifi_cloud,check.coverage.get('advanced') if check else None)
        except Exception:coverage['advanced']={'schema':1,'status':'unavailable'}
    else: notes.append('La cobertura de reglas heredadas depende de la versión OPNsense. Un listado vacío no acredita ausencia de exposición.')
    return sections,coverage,' '.join(notes)

def save_result(device,sections,coverage,notes,now=None):
    now=now or timezone.now()
    with transaction.atomic():
        check,_=ExposureCheck.objects.get_or_create(device=device)
        check.checked_at=now;check.requested_at=None;check.coverage=coverage;check.notes=notes
        complete=all(coverage.get(s,{}).get('status')=='checked' for s in ('filter','nat')) and coverage.get('context',{}).get('aliases',{}).get('status')!='unavailable'
        if device.vendor=='unifi':
            complete=complete and coverage.get('zones',{}).get('status')=='checked'
        check.status='checked' if complete else 'partial' if sections else 'unavailable'
        if complete: check.last_success_at=now
        check.save()
        for section,findings in sections.items():
            seen=[]
            for values in findings:
                fingerprint=hashlib.sha256(json.dumps(values,sort_keys=True).encode()).hexdigest()
                obj,created=ExposureFinding.objects.get_or_create(device=device,section=section,remote_id=values['remote_id'],kind=values['kind'],defaults={**values,'fingerprint':fingerprint,'first_seen_at':now,'last_seen_at':now})
                changed=not created and (obj.fingerprint!=fingerprint or not obj.present)
                for key,value in values.items(): setattr(obj,key,value)
                obj.fingerprint=fingerprint;obj.present=True;obj.last_seen_at=now;obj.removed_at=None
                if changed:
                    obj.history=(obj.history+[{'at':now.isoformat(),'decision':'changed','note':'La configuración cambió o el hallazgo reapareció. Se requiere nueva revisión.','fingerprint':fingerprint}])[-100:]
                    obj.review='pending';obj.review_note='';obj.review_until=None;obj.reviewed_by=None;obj.reviewed_at=None
                obj.save();seen.append(obj.pk)
            if not coverage.get(section,{}).get('preserve_unseen'):
                ExposureFinding.objects.filter(device=device,section=section,present=True).exclude(pk__in=seen).exclude(remote_id__in=coverage.get(section,{}).get('unresolved_rules',[])).update(present=False,removed_at=now)
        return check

def refresh_due(limit=1):
    now=timezone.now()
    checks=list(ExposureCheck.objects.filter(device__active=True,device__site__active=True,device__site__client__active=True).select_related('device').order_by('checked_at','pk'))
    # Initial rows are cheap and do not read/decrypt credentials in the web process.
    for d in Device.objects.filter(active=True,site__active=True,site__client__active=True,exposure_check__isnull=True):
        checks.append(ExposureCheck.objects.create(device=d))
    checks.sort(key=lambda c:(c.requested_at is None,c.checked_at or now-timedelta(days=365)))
    count=0
    for c in checks:
        if c.device.integration=='paused': continue
        due=not c.checked_at or now-c.checked_at>timedelta(hours=6)
        requested=c.requested_at and (not c.checked_at or now-c.checked_at>timedelta(minutes=10))
        if not due and not requested: continue
        sections,coverage,notes=collect(c.device);save_result(c.device,sections,coverage,notes,now);count+=1
        if count>=limit: break
    return count

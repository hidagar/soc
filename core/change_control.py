"""Versioned review plans. Remote changes are disabled drafts until explicit approval."""
import hashlib
import ipaddress
import json
import re
from django.utils import timezone
from .models import ChangePlan,Device
from .security import encrypt,decrypt,audit

PROFILES={'pyme':'PYME básica','servers':'Servidores','voice':'Telefonía','industrial':'Industrial'}
VERSION='1.0'

def preview(profile,networks,interface):
    if profile not in PROFILES: raise ValueError('Plantilla no válida.')
    networks=[str(ipaddress.ip_network(n.strip(),strict=True)) for n in networks.split(',') if n.strip()]
    if not networks or len(networks)>10: raise ValueError('Indica entre una y diez redes CIDR.')
    if not re.fullmatch(r'(?:lan|opt[0-9]+)(?:,(?:lan|opt[0-9]+))*',interface):
        raise ValueError('Usa interfaces internas de OPNsense: lan,opt1…')
    ports={'pyme':'25,135,139,445,3389','servers':'135,139,445,3389','voice':'135,139,445,3389','industrial':'25,135,139,445,3389'}[profile]
    rules=[]
    for net in networks:
        if ipaddress.ip_network(net).version!=4: raise ValueError('Esta versión prepara reglas IPv4; revisa IPv6 aparte.')
        rules.append({'enabled':'0','sequence':'50000','action':'block','quick':'1',
            'interface':interface,'direction':'in','ipprotocol':'inet','protocol':'TCP',
            'source_net':net,'destination_net':'any','destination_port':ports,'log':'1'})
    checks=['Confirmar interfaces, inventario y excepciones antes de activar.',
        'Coordinar una ventana de cambio y disponer de acceso de recuperación.',
        'Revisar orden de reglas y reglas previas: un permiso anterior puede impedir el bloqueo.',
        'Estos bloqueos alcanzan destinos internos y externos. Completar excepciones de AD, SMTP y administración.']
    specifics={'pyme':['DNS/NTP corporativos, actualizaciones y aplicaciones del negocio.'],
        'servers':['AD, DNS, copias, correo y administración deben tener excepciones explícitas.'],
        'voice':['Documentar PBX/SBC, proveedor, SIP/RTP y teléfonos. No inferir rangos RTP.'],
        'industrial':['Inventariar PLC/HMI, fabricantes y mantenimiento remoto. Probar cada flujo operativo.']}
    checks+=specifics[profile]
    return {'profile':PROFILES[profile],'version':VERSION,'networks':networks,'interface':interface,
        'rules':rules,'checks':checks,'zenarmor':['Crear una política inactiva en Zenarmor para las redes elegidas. Activar categorías de malware, phishing y botnet según licencia.',
        'Verificar exclusiones, bypass y un evento real exportado.'],'suricata':['Empezar con IDS y firmas de malware/C2, exploits y escaneos. Validar compatibilidad de interfaces antes de IPS.']}

def api(connection,path,payload=None,method=None):
    from .opnsense_api import _request_json,decrypt_credential
    return _request_json(connection.api_url,decrypt_credential(connection.encrypted_api_key),
        decrypt_credential(connection.encrypted_api_secret),connection.ca_certificate,path,
        method or ('POST' if payload is not None else 'GET'),payload)

def snapshot(connection):
    return api(connection,'/api/firewall/filter/search_rule?rowCount=-1')

def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def completed(response):
    return str(response.get('status') or response.get('result') or '').strip().lower() in ('ok','success','saved','deleted','done')

def stage_ids(plan,c):
    try:
        available=api(c,'/api/ids/settings/get_policy').get('policy',{}).get('content',{})
        if not isinstance(available,dict): raise ValueError('Metadatos IDS no disponibles.')
    except Exception:
        plan.preview['suricata'].append('Preparación automática pendiente: faltan API o permisos para las políticas IDS.')
        plan.save(update_fields=['preview']); return
    classes=['classtype.command-and-control','classtype.trojan-activity','classtype.attempted-admin','classtype.attempted-user']
    filters=[v for v in classes if v in available]
    if not filters:
        plan.preview['suricata'].append('Faltan los metadatos de las firmas. Actualizar y revisar antes de preparar la política.')
        plan.save(update_fields=['preview']); return
    name=f'SOC PLAN {plan.pk} IDS v{plan.template_version}'
    desired={'enabled':'0','prio':'-90','action':'','rulesets':'','content':','.join(filters),'new_action':'alert','description':name}
    current=api(c,'/api/ids/settings/search_policy?rowCount=-1').get('rows',[])
    match=next((r for r in current if r.get('description')==name),None)
    if match: uid=match['uuid']
    else:
        response=api(c,'/api/ids/settings/add_policy',{'policy':desired})
        if response.get('result')!='saved' or not response.get('uuid'): raise ValueError('No se pudo preparar la política IDS.')
        uid=response['uuid']
    if not any(o['uuid']==uid and o.get('kind')=='suricata' for o in plan.remote_objects):
        plan.remote_objects.append({'kind':'suricata','uuid':uid,'rule':desired}); plan.save(update_fields=['remote_objects'])
    actual=api(c,'/api/ids/settings/get_policy/'+uid).get('policy',{})
    if str(actual.get('enabled'))!='0' or actual.get('description')!=name: raise ValueError('La política IDS no está desactivada.')

def stage_zenarmor(plan,c):
    try:
        info=api(c,'/api/zenarmor/configuration/info')
        categories=info['SecurityCategories']['essential']
        default=api(c,'/api/zenarmor/policy/detail?id=0')
        existing=api(c,'/api/zenarmor/policy/index').get('policies',[])
    except Exception:
        plan.preview['zenarmor'].append('Preparación automática pendiente: API de Zenarmor o permisos no disponibles.')
        plan.save(update_fields=['preview']); return
    name=f'SOC PLAN {plan.pk} Zenarmor v{plan.template_version}'
    found=next((r for r in existing if r.get('name')==name),None)
    if found: uid=str(found['id'])
    else:
        response=api(c,'/api/zenarmor/policy/index',{'name':name})
        if not response.get('success') or 'id' not in response.get('policy',{}): raise ValueError('No se pudo crear la política Zenarmor; revisar licencia y permisos.')
        uid=str(response['policy']['id'])
    if not any(o['uuid']==uid and o.get('kind')=='zenarmor' for o in plan.remote_objects):
        plan.remote_objects.append({'kind':'zenarmor','uuid':uid,'rule':{'description':name}}); plan.save(update_fields=['remote_objects'])
    detail=api(c,'/api/zenarmor/policy/detail?id='+uid)
    if detail.get('isActive') is not False: raise ValueError('La política Zenarmor está activa. Intervención manual requerida.')
    cfg=detail['configs']
    cfg.update({'directions':{'inbound':True,'outbound':True},'sort_number':1000+plan.pk,
        'webcategory_type':'permissive','decision_is_block':False,'groups':[],'usernames':[],'vlans':[]})
    requests=[('config',{'operation':'set-configs','configs':cfg}),
        ('networks',{'networks':[{'value':n,'desc':PROFILES[plan.template],'is_disabled':False} for n in plan.preview['networks']]}),
        ('essentialSecurity',{'essentialSecurity':[{'id':cat['id'],'value':int(cat['id']) in {101,102,103,104,107}} for cat in categories]})]
    for endpoint,payload in requests:
        response=api(c,'/api/zenarmor/policy/'+endpoint+'?id='+uid,payload,method='PUT')
        if not response.get('success'): raise ValueError('Configuración de política Zenarmor rechazada.')
    detail=api(c,'/api/zenarmor/policy/detail?id='+uid)
    if detail.get('isActive') is not False or {n['value'] for n in detail.get('networks',[])}!=set(plan.preview['networks']):
        raise ValueError('No se confirmó la política Zenarmor desactivada y su alcance.')
    after=api(c,'/api/zenarmor/policy/detail?id=0')
    for v in (default,after):
        v.pop('checksum',None)
        if isinstance(v.get('configs'),dict): v['configs'].pop('sort_number',None)
    if digest(default)!=digest(after): raise ValueError('La política existente cambió. Revisar manualmente.')

def stage_blocklist_alias(plan,c):
    """Tabla de IPs que el firewall descarga de la lista del SOC. Sin regla activa no bloquea nada."""
    from .blocklist import alias_name,feed_url,plan_kind
    from .models import BlocklistFeed
    kind=plan_kind(plan)
    feed=BlocklistFeed.objects.filter(client_id=plan.parameters.get('client'),enabled=True).first()
    if not feed or feed.client_id!=plan.device.site.client_id: raise ValueError('La lista del cliente no está activada.')
    if kind=='out' and not feed.outbound_enabled: raise ValueError('La lista de salida del cliente no está activada.')
    if kind=='preventive' and not feed.qfeeds_preventive: raise ValueError('La lista preventiva de Q-Feeds del cliente no está activada.')
    name=alias_name(plan);description=f'SOC PLAN {plan.pk} alias'
    desired={'enabled':'1','name':name,'type':'urltable','content':feed_url(feed,kind=kind),
        'updatefreq':plan.preview['alias']['updatefreq'],'description':description}
    rows=api(c,'/api/firewall/alias/search_item?rowCount=-1').get('rows',[])
    found=next((r for r in rows if r.get('name')==name),None)
    if found:
        if found.get('description')!=description: raise ValueError('Ya existe un alias con ese nombre que no pertenece a esta propuesta.')
        uid=found['uuid']
    else:
        response=api(c,'/api/firewall/alias/add_item',{'alias':desired})
        if response.get('result')!='saved' or not response.get('uuid'): raise ValueError('Creación del alias rechazada.')
        uid=response['uuid']
    if not any(o['uuid']==uid for o in plan.remote_objects):
        # El token va solo en el firewall; el plan guarda la identidad del objeto, no la URL.
        plan.remote_objects.append({'kind':'alias','uuid':uid,'rule':{'description':description,'name':name}})
        plan.save(update_fields=['remote_objects'])
    if not completed(api(c,'/api/firewall/alias/reconfigure',{})): raise ValueError('No se confirmó la carga del alias.')

class DnsblUnsupported(Exception):
    """El firewall no tiene la API de listas de bloqueo DNS por elementos (OPNsense anterior a 25.7)."""


def dnsbl_description(plan):
    return f'SOC PLAN {plan.pk} dnsbl'


def stage_dnsbl(plan,c):
    """Lista de bloqueo propia en Unbound, desactivada. Nunca toca las listas del operador ni la configuración común.

    OPNsense 25.7 guarda cada lista de bloqueo DNS como un elemento con su descripción; en versiones
    anteriores era un bloque común y el SOC no lo modifica (configuración guiada).
    """
    from .blocklist import feed_url
    from .models import BlocklistFeed
    from .opnsense_api import OpnsenseApiError
    feed=BlocklistFeed.objects.filter(client_id=plan.parameters.get('client'),enabled=True).first()
    if not feed or feed.client_id!=plan.device.site.client_id: raise ValueError('La lista del cliente no está activada.')
    if not feed.qfeeds_dns: raise ValueError('Los dominios de Q-Feeds del cliente no están activados.')
    try:
        rows=api(c,'/api/unbound/settings/search_dnsbl?rowCount=-1').get('rows',[])
    except OpnsenseApiError as exc:
        if 'HTTP 404' in str(exc): raise DnsblUnsupported() from None
        raise
    general=(api(c,'/api/unbound/settings/get').get('unbound') or {}).get('general') or {}
    if str(general.get('enabled'))!='1': raise ValueError('Unbound no está activo en el firewall.')
    description=dnsbl_description(plan)
    found=next((r for r in rows if r.get('description')==description),None)
    if found:
        uid=found['uuid']
    else:
        settings=plan.preview.get('dnsbl') or {}
        item={'enabled':'0','lists':feed_url(feed,kind='dns'),'nxdomain':settings.get('nxdomain','1'),
              'cache_ttl':settings.get('cache_ttl','3600'),'description':description}
        response=api(c,'/api/unbound/settings/add_dnsbl',{'blocklist':item})
        if response.get('result')!='saved' or not response.get('uuid'): raise ValueError('Creación de la lista DNS rechazada.')
        uid=response['uuid']
    if not any(o['uuid']==uid for o in plan.remote_objects):
        # El token va solo en el firewall; el plan guarda la identidad del objeto, no la URL.
        plan.remote_objects.append({'kind':'dnsbl','uuid':uid,'rule':{'description':description}})
        plan.save(update_fields=['remote_objects'])
    current=api(c,'/api/unbound/settings/get_dnsbl/'+uid).get('blocklist',{})
    if str(current.get('enabled'))!='0' or current.get('description')!=description:
        raise ValueError('La lista DNS no está desactivada o su identidad difiere.')


def _owned_dnsbl(plan,c,obj):
    current=api(c,'/api/unbound/settings/get_dnsbl/'+obj['uuid']).get('blocklist',{})
    if current.get('description')!=obj['rule']['description']: raise ValueError('La lista DNS cambió de propietario; intervención manual requerida.')
    return current


def enable_dnsbl(plan):
    """Activa la lista DNS propia y aplica Unbound. Sin punto de restauración nativo: si no se confirma a tiempo,
    el trabajo la desactiva (el DNS no corta el acceso de gestión del firewall)."""
    from datetime import timedelta
    from .qfeeds_distribution import DNS_CONFIRM_MINUTES
    c=plan.device.opnsense_api
    plan.status='applying'; plan.save(update_fields=['status'])
    try:
        for obj in plan.remote_objects:
            if obj.get('kind')!='dnsbl': continue
            if str(_owned_dnsbl(plan,c,obj).get('enabled'))!='0': raise ValueError('El borrador remoto cambió. Preparar una revisión nueva.')
            if api(c,'/api/unbound/settings/set_dnsbl/'+obj['uuid'],{'blocklist':{'enabled':'1'}}).get('result')!='saved':
                raise ValueError('Activación rechazada.')
        plan.confirmation_deadline=timezone.now()+timedelta(minutes=DNS_CONFIRM_MINUTES)
        plan.save(update_fields=['confirmation_deadline'])
        if not completed(api(c,'/api/unbound/service/dnsbl',{})): raise ValueError('Unbound no confirmó la carga de las listas.')
        api(c,'/api/core/system/status')
        for obj in plan.remote_objects:
            if obj.get('kind')=='dnsbl' and str(_owned_dnsbl(plan,c,obj).get('enabled'))!='1': raise ValueError('Verificación de activación fallida.')
        plan.status='awaiting_confirmation'
        plan.result=f'Lista DNS activa en Unbound. Comprueba que los equipos resuelven con normalidad y confirma en {DNS_CONFIRM_MINUTES} minutos o se desactivará.'
        plan.save(); audit('change.awaiting_confirmation',plan)
    except Exception:
        try: rollback(plan)
        except Exception:
            plan.status='needs_review'; plan.result='No se pudo confirmar la retirada de la lista DNS. Revisar «Unbound DNS › Listas de bloqueo» en la consola.'; plan.save()


UPDATE_PATHS={'alias':('/api/firewall/alias/get_item/','/api/firewall/alias/set_item/','alias','/api/firewall/alias/reconfigure'),
    'dnsbl':('/api/unbound/settings/get_dnsbl/','/api/unbound/settings/set_dnsbl/','blocklist','/api/unbound/service/dnsbl')}


def _plain(value):
    """Valor simple de un campo de OPNsense (los de opciones vienen como {clave: {value, selected}})."""
    if isinstance(value,dict):
        return next((k for k,v in value.items() if isinstance(v,dict) and str(v.get('selected'))=='1'),'')
    return '' if value is None else str(value)


def stage_update(plan,c):
    """Actualización de plantilla: anota el valor actual de cada ajuste en los objetos propios de la regla original."""
    target=ChangePlan.objects.filter(pk=plan.parameters.get('plan'),device=plan.device,status='active').first()
    if not target: raise ValueError('La propuesta original ya no está activa en este equipo.')
    info=plan.preview.get('update') or {}
    kind=info.get('kind')
    if kind not in UPDATE_PATHS or not info.get('changes'): raise ValueError('Actualización no válida.')
    get,_,root,_=UPDATE_PATHS[kind]
    objects=[o for o in target.remote_objects if o.get('kind')==kind]
    if not objects: raise ValueError('La propuesta original no tiene el objeto que actualizar.')
    plan.remote_objects=[]
    for obj in objects:
        current=api(c,get+obj['uuid']).get(root,{})
        if current.get('description')!=obj['rule']['description']: raise ValueError('El objeto cambió de propietario; intervención manual requerida.')
        for field,value in info['changes'].items():
            plan.remote_objects.append({'kind':'update','target':kind,'uuid':obj['uuid'],'field':field,'value':str(value),
                'previous':_plain(current.get(field)),'rule':{'description':obj['rule']['description']}})
    plan.save(update_fields=['remote_objects'])


def _set_update(plan,c,use_previous):
    """Escribe los valores nuevos (o los anteriores, al revertir), aplica y comprueba. Solo objetos propios."""
    applied=set()
    for obj in [o for o in plan.remote_objects if o.get('kind')=='update']:
        get,put,root,apply_path=UPDATE_PATHS[obj['target']]
        current=api(c,get+obj['uuid']).get(root,{})
        if current.get('description')!=obj['rule']['description']: raise ValueError('El objeto cambió de propietario; intervención manual requerida.')
        value=obj['previous'] if use_previous else obj['value']
        if api(c,put+obj['uuid'],{root:{obj['field']:value}}).get('result')!='saved': raise ValueError('Cambio rechazado.')
        applied.add(apply_path)
    for apply_path in sorted(applied):
        if not completed(api(c,apply_path,{})): raise ValueError('El firewall no confirmó la aplicación.')
    for obj in [o for o in plan.remote_objects if o.get('kind')=='update']:
        get,_,root,_=UPDATE_PATHS[obj['target']]
        if _plain(api(c,get+obj['uuid']).get(root,{}).get(obj['field']))!=(obj['previous'] if use_previous else obj['value']):
            raise ValueError('Verificación de la actualización fallida.')


def enable_update(plan):
    from datetime import timedelta
    from .template_updates import CONFIRM_MINUTES
    c=plan.device.opnsense_api
    plan.status='applying'; plan.save(update_fields=['status'])
    try:
        plan.confirmation_deadline=timezone.now()+timedelta(minutes=CONFIRM_MINUTES)
        plan.save(update_fields=['confirmation_deadline'])
        _set_update(plan,c,use_previous=False)
        api(c,'/api/core/system/status')
        plan.status='awaiting_confirmation'
        plan.result=f'Ajustes actualizados. Comprueba que el firewall sigue descargando la lista y confirma en {CONFIRM_MINUTES} minutos o se revertirán.'
        plan.save(); audit('change.awaiting_confirmation',plan)
    except Exception:
        try: rollback(plan)
        except Exception:
            plan.status='needs_review'; plan.result='No se pudo confirmar la vuelta a los valores anteriores. Revisar el objeto en la consola.'; plan.save()


def stage(plan):
    if plan.device.vendor != Device.Vendor.OPNSENSE or plan.device.management_method!='api':
        plan.status='manual'; plan.result='Guía preparada. Este equipo requiere aplicar y verificar la plantilla desde su consola.'; plan.save(); return
    c=plan.device.opnsense_api
    baseline=snapshot(c)
    plan.encrypted_backup=encrypt(json.dumps(baseline))
    plan.baseline_hash=digest(baseline)
    plan.status='staging'; plan.save()
    try:
        from .blocklist import ALL_TEMPLATES,alias_name
        from . import policy_changes
        from .qfeeds_distribution import DNS_TEMPLATE
        from .template_updates import UPDATE_TEMPLATE
        if plan.template==UPDATE_TEMPLATE:
            stage_update(plan,c)
            plan.status='staged'; plan.result='Valores actuales anotados. La actualización solo cambia los ajustes indicados.'
            audit('change.staged',plan,{'count':len(plan.remote_objects),'template':plan.template})
            plan.save(); return
        if plan.template==DNS_TEMPLATE:
            try:
                stage_dnsbl(plan,c)
            except DnsblUnsupported:
                plan.status='manual'; plan.result=('Este OPNsense no tiene la API de listas de bloqueo DNS (requiere 25.7 o posterior). '
                    'Añade a mano la URL de dominios de la lista del cliente en «Servicios › Unbound DNS › Listas de bloqueo».')
                plan.save(); return
            plan.status='staged'; plan.result='Lista de bloqueo DNS creada desactivada y verificada. Revisa las comprobaciones antes de activarla.'
            audit('change.staged',plan,{'count':len(plan.remote_objects),'template':plan.template})
            plan.save(); return
        crowdsec=plan.template in ALL_TEMPLATES
        restrict=plan.template==policy_changes.TEMPLATE
        if crowdsec: stage_blocklist_alias(plan,c)
        origins_alias=policy_changes.stage_alias(plan,api,c,completed) if restrict else ''
        for index,desired in enumerate(plan.preview['rules']):
            rule={**desired,'description':f'SOC PLAN {plan.pk} v{plan.template_version} {index+1}'}
            if crowdsec:
                # Entrada: bloquea orígenes de la lista; salida: bloquea destinos de la lista.
                rule['destination_net' if desired.get('direction')=='out' else 'source_net']=alias_name(plan)
            if restrict:
                # Bloquea el servicio a todo origen que NO esté en el alias de autorizados.
                rule['source_net']=origins_alias;rule['source_not']='1'
            # The description is an idempotency key, including recovery after a process interruption.
            rows=snapshot(c).get('rows',[])
            found=next((r for r in rows if r.get('description')==rule['description']),None)
            if found:
                uid=found['uuid']
            else:
                response=api(c,'/api/firewall/filter/add_rule',{'rule':rule})
                if response.get('result')!='saved' or not response.get('uuid'): raise ValueError('Creación rechazada.')
                uid=response['uuid']
            if not any(o['uuid']==uid for o in plan.remote_objects):
                plan.remote_objects.append({'kind':'firewall','uuid':uid,'rule':rule}); plan.save(update_fields=['remote_objects'])
            observed=api(c,'/api/firewall/filter/get_rule/'+uid).get('rule',{})
            if str(observed.get('enabled'))!='0' or observed.get('description')!=rule['description']:
                raise ValueError('La regla no está desactivada o su identidad difiere.')
        if not crowdsec and not restrict:
            stage_ids(plan,c)
            if plan.device.zenarmor_enabled: stage_zenarmor(plan,c)
        plan.status='staged'; plan.result='Borradores desactivados verificados. La activación desde este panel corresponde a las reglas de firewall; revisa las políticas de inspección en la consola antes de activarlas.'
        audit('change.staged',plan,{'count':len(plan.remote_objects),'template':plan.template})
    except Exception:
        # Undo only resources belonging to this plan; never restore an entire unrelated config.
        rollback(plan,delete=True)
        plan.status='failed'; plan.result='No terminó la preparación. Se retiraron los objetos propios que pudieron verificarse; revisar el estado remoto.'
    plan.save()

def rollback(plan,delete=False):
    c=plan.device.opnsense_api
    from .template_updates import UPDATE_TEMPLATE,mark_applied
    if plan.template==UPDATE_TEMPLATE:
        # Una actualización no crea objetos: revertir es volver a los valores anotados al prepararla.
        if any(o.get('kind')=='update' for o in plan.remote_objects): _set_update(plan,c,use_previous=True)
        if plan.status in ('active','rollback_queued') and plan.parameters.get('from'): mark_applied(plan,plan.parameters['from'])
        plan.status='rolled_back'; plan.result='Valores anteriores restaurados.'; plan.save()
        audit('change.rollback',plan)
        return
    # Las reglas antes que el alias: OPNsense no borra un alias en uso.
    for obj in sorted(plan.remote_objects,key=lambda o:o.get('kind')=='alias'):
        kind=obj.get('kind','firewall')
        if kind=='dnsbl':
            _owned_dnsbl(plan,c,obj)
            if delete:
                response=api(c,'/api/unbound/settings/del_dnsbl/'+obj['uuid'],{})
                if response.get('result') not in ('deleted','saved','ok'): raise ValueError('No se pudo retirar la lista DNS.')
            elif api(c,'/api/unbound/settings/set_dnsbl/'+obj['uuid'],{'blocklist':{'enabled':'0'}}).get('result')!='saved':
                raise ValueError('Reversión de la lista DNS rechazada.')
            continue
        if kind=='alias':
            current=api(c,'/api/firewall/alias/get_item/'+obj['uuid']).get('alias',{})
            if current.get('description')!=obj['rule']['description']: raise ValueError('El alias cambió de propietario; intervención manual requerida.')
            if delete:
                response=api(c,'/api/firewall/alias/del_item/'+obj['uuid'],{})
                if response.get('result') not in ('deleted','saved','ok'): raise ValueError('No se pudo retirar el alias.')
            continue
        if kind=='suricata':
            current=api(c,'/api/ids/settings/get_policy/'+obj['uuid']).get('policy',{})
            if current.get('description')!=obj['rule']['description']: raise ValueError('La política IDS cambió de propietario.')
            if str(current.get('enabled'))!='0': raise ValueError('La política IDS se activó fuera del panel. Revisar manualmente.')
            response=api(c,'/api/ids/settings/del_policy/'+obj['uuid'],{})
            if response.get('result') not in ('deleted','saved','ok'): raise ValueError('No se pudo retirar la política IDS.')
            continue
        if kind=='zenarmor':
            current=api(c,'/api/zenarmor/policy/detail?id='+obj['uuid'])
            if current.get('name')!=obj['rule']['description'] or current.get('isActive'):
                raise ValueError('La política Zenarmor fue modificada o activada. Revisar manualmente.')
            response=api(c,'/api/zenarmor/policy/delete',{'cloud_id':obj['uuid']})
            if not response.get('success'): raise ValueError('No se pudo retirar la política Zenarmor.')
            continue
        current=api(c,'/api/firewall/filter/get_rule/'+obj['uuid']).get('rule',{})
        if current.get('description')!=obj['rule']['description']: raise ValueError('El objeto cambió de propietario; intervención manual requerida.')
        if delete:
            response=api(c,'/api/firewall/filter/del_rule/'+obj['uuid'],{})
        else:
            response=api(c,'/api/firewall/filter/set_rule/'+obj['uuid'],{'rule':{'enabled':'0'}})
        if response.get('result') not in ('saved','deleted','ok'): raise ValueError('Reversión rechazada.')
    if any(o.get('kind')=='dnsbl' for o in plan.remote_objects):
        # Unbound recarga sus listas sin la del SOC (retirada o desactivada).
        if not completed(api(c,'/api/unbound/service/dnsbl',{})):
            raise ValueError('Unbound no confirmó la recarga de las listas tras la reversión.')
    if not delete and any(o.get('kind','firewall')=='firewall' for o in plan.remote_objects):
        apply_response=api(c,'/api/firewall/filter/apply',{})
        if not completed(apply_response):
            raise ValueError('No se confirmó la aplicación de la reversión.')
    plan.status='rolled_back'; plan.result='Objetos propios retirados o desactivados; revisar conectividad.'; plan.save()
    audit('change.rollback',plan)

def enable(plan):
    """Native savepoint limits interruption; worker must confirm inside native rollback window."""
    from .qfeeds_distribution import DNS_TEMPLATE
    from .template_updates import UPDATE_TEMPLATE
    if plan.template==DNS_TEMPLATE:
        return enable_dnsbl(plan)
    if plan.template==UPDATE_TEMPLATE:
        return enable_update(plan)
    c=plan.device.opnsense_api
    baseline=json.loads(decrypt(plan.encrypted_backup))
    current=snapshot(c)
    owned={obj['uuid'] for obj in plan.remote_objects if obj.get('kind','firewall')=='firewall'}
    previous=sorted(baseline.get('rows',[]),key=lambda r:r['uuid'])
    others=sorted([r for r in current.get('rows',[]) if r['uuid'] not in owned],key=lambda r:r['uuid'])
    if digest(previous)!=digest(others):
        raise ValueError('La configuración de otras reglas cambió desde la preparación. Revisar una propuesta nueva.')
    savepoint=api(c,'/api/firewall/filter/savepoint',{})
    revision=str(savepoint.get('revision') or '')
    if not revision: raise ValueError('El dispositivo no confirmó un punto de recuperación. No se activó nada.')
    plan.rollback_revision=revision; plan.status='applying'; plan.save()
    try:
        for obj in plan.remote_objects:
            if obj.get('kind','firewall')!='firewall': continue
            current=api(c,'/api/firewall/filter/get_rule/'+obj['uuid']).get('rule',{})
            if str(current.get('enabled'))!='0' or current.get('description')!=obj['rule']['description']:
                raise ValueError('El borrador remoto cambió. Preparar una revisión nueva.')
            response=api(c,'/api/firewall/filter/set_rule/'+obj['uuid'],{'rule':{'enabled':'1'}})
            if response.get('result')!='saved': raise ValueError('Activación rechazada.')
        from datetime import timedelta
        plan.confirmation_deadline=timezone.now()+timedelta(seconds=45)
        plan.save(update_fields=['confirmation_deadline'])
        response=api(c,'/api/firewall/filter/apply/'+revision,{})
        if not completed(response):
            raise ValueError('Aplicación rechazada.')
        # Verify management and all owned rules before cancelling native automatic rollback.
        api(c,'/api/core/system/status')
        for obj in plan.remote_objects:
            if obj.get('kind','firewall')!='firewall': continue
            current=api(c,'/api/firewall/filter/get_rule/'+obj['uuid']).get('rule',{})
            if str(current.get('enabled'))!='1': raise ValueError('Verificación de activación fallida.')
        plan.status='awaiting_confirmation'
        plan.result='Acceso de gestión verificado. Prueba los servicios y confirma antes del plazo o se revertirá.'
        plan.save(); audit('change.awaiting_confirmation',plan)
    except Exception:
        try: rollback(plan)
        except Exception:
            plan.status='needs_review'; plan.result='El firewall debe revertir mediante su savepoint. Confirmar desde la consola antes de continuar.'; plan.save()

def process_queue():
    # Service-level flock prevents concurrent workers; claim before the first network request.
    from django.db.models import Q
    candidates=ChangePlan.objects.filter(Q(status__in=['stage_queued','apply_queued','rollback_queued','staging','applying','confirm_queued'])|Q(status='awaiting_confirmation',confirmation_deadline__lt=timezone.now()))
    from django.db.models import Case,When,IntegerField
    if ChangePlan.objects.filter(status__in=['awaiting_confirmation','confirm_queued']).exists():
        candidates=candidates.filter(status__in=['confirm_queued','awaiting_confirmation','rollback_queued'])
    priority=Case(When(status='confirm_queued',then=0),When(status='rollback_queued',then=1),default=2,output_field=IntegerField())
    for plan in candidates.select_related('device').order_by(priority,'pk')[:1]:
        if plan.status in ('apply_queued','applying') and not plan.approved_by_id:
            plan.status='needs_review'; plan.result='Falta aprobación identificada.'; plan.save(); continue
        try:
            if plan.status in ('stage_queued','staging'): stage(plan)
            elif plan.status=='rollback_queued': rollback(plan)
            elif plan.status in ('awaiting_confirmation','confirm_queued'):
                if plan.status=='awaiting_confirmation' or not plan.confirmation_deadline or timezone.now()>=plan.confirmation_deadline:
                    rollback(plan)
                else:
                    c=plan.device.opnsense_api
                    api(c,'/api/core/system/status')
                    if plan.rollback_revision:
                        # Las listas DNS no usan el punto de restauración del filtro: no hay nada que cancelar.
                        response=api(c,'/api/firewall/filter/cancel_rollback/'+plan.rollback_revision,{})
                        if not completed(response): raise ValueError('Confirmación rechazada.')
                    plan.status='active'; plan.confirmation_deadline=None; plan.result='Pruebas confirmadas por el aprobador y acceso de gestión verificado.'; plan.save(); audit('change.applied',plan)
                    from .template_updates import UPDATE_TEMPLATE,mark_applied
                    if plan.template==UPDATE_TEMPLATE: mark_applied(plan,plan.parameters.get('to'))
            elif plan.status=='applying':
                # Interrupted activation never resumes automatically.
                rollback(plan)
            else: enable(plan)
        except Exception:
            plan.status='needs_review'; plan.result='Operación incompleta. Revisar la consola y los registros protegidos antes de reintentar.'; plan.save()

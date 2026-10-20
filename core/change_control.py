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

def stage(plan):
    if plan.device.vendor != Device.Vendor.OPNSENSE or plan.device.management_method!='api':
        plan.status='manual'; plan.result='Guía preparada. Este equipo requiere aplicar y verificar la plantilla desde su consola.'; plan.save(); return
    c=plan.device.opnsense_api
    baseline=snapshot(c)
    plan.encrypted_backup=encrypt(json.dumps(baseline))
    plan.baseline_hash=digest(baseline)
    plan.status='staging'; plan.save()
    try:
        for index,desired in enumerate(plan.preview['rules']):
            rule={**desired,'description':f'SOC PLAN {plan.pk} v{plan.template_version} {index+1}'}
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
    for obj in plan.remote_objects:
        kind=obj.get('kind','firewall')
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
    if not delete:
        apply_response=api(c,'/api/firewall/filter/apply',{})
        if not completed(apply_response):
            raise ValueError('No se confirmó la aplicación de la reversión.')
    plan.status='rolled_back'; plan.result='Objetos propios retirados o desactivados; revisar conectividad.'; plan.save()
    audit('change.rollback',plan)

def enable(plan):
    """Native savepoint limits interruption; worker must confirm inside native rollback window."""
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
                    response=api(c,'/api/firewall/filter/cancel_rollback/'+plan.rollback_revision,{})
                    if not completed(response): raise ValueError('Confirmación rechazada.')
                    plan.status='active'; plan.confirmation_deadline=None; plan.result='Pruebas confirmadas por el aprobador y acceso de gestión verificado.'; plan.save(); audit('change.applied',plan)
            elif plan.status=='applying':
                # Interrupted activation never resumes automatically.
                rollback(plan)
            else: enable(plan)
        except Exception:
            plan.status='needs_review'; plan.result='Operación incompleta. Revisar la consola y los registros protegidos antes de reintentar.'; plan.save()

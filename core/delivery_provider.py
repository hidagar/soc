"""Readonly, bounded diagnosis of this service's SendGrid webhook."""
import json,hashlib
from urllib import request,error,parse
from django.utils import timezone
from .models import MailSettings,DeliverySettings,WorkerState
from .mail_delivery import decrypt_sendgrid_key,_NoRedirect
from .delivery_tracking import verification_key
from cryptography.hazmat.primitives import serialization

URL='https://soc.ibred.es/reports/delivery-events/'

def fingerprint(value):
    key=verification_key(value)
    return hashlib.sha256(key.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()

def diagnose():
    state,_=WorkerState.objects.get_or_create(name='delivery-provider')
    state.last_run_at=timezone.now()
    try:
        config=MailSettings.objects.first()
        if not config:raise ValueError('missing mail configuration')
        base={'global':'https://api.sendgrid.com','eu':'https://api.eu.sendgrid.com'}[config.region]
        key=decrypt_sendgrid_key(config.encrypted_api_key)
        def get(path):
            req=request.Request(base+'/v3/user/webhooks/event/'+path,headers={'Authorization':'Bearer '+key,'Accept':'application/json'})
            with request.build_opener(_NoRedirect()).open(req,timeout=15) as response:raw=response.read(65537)
            if len(raw)>65536:raise ValueError('oversized')
            return json.loads(raw)
        data=get('settings/all')
        hooks=data.get('webhooks')
        if not isinstance(hooks,list) or len(hooks)>100:raise ValueError('schema')
        matching=[h for h in hooks if isinstance(h,dict) and h.get('url')==URL]
        result={'status':'missing','note':'No se encontró el webhook de este SOC. Configúralo en SendGrid.'}
        if len(matching)>1:result={'status':'ambiguous','note':'Hay varios destinos de este SOC. Revisar duplicados en SendGrid.'}
        elif matching:
            hook=matching[0];identity=hook.get('id')
            if not isinstance(identity,str) or not identity or len(identity)>180:raise ValueError('id')
            signed=get('settings/signed/'+parse.quote(identity,safe=''))
            public=signed.get('public_key','')
            local=DeliverySettings.objects.filter(pk=1).first()
            good=bool(public and local and local.enabled and local.public_key and fingerprint(public)==fingerprint(local.public_key))
            enabled=hook.get('enabled') is True
            events=all(hook.get(k) is True for k in ('processed','delivered','deferred','bounce','dropped'))
            result={'status':'configured' if good and enabled and events else 'review','enabled':enabled,'events_complete':events,'key_matches':good,
                'note':'Configuración contrastada; falta recibir un evento firmado de un envío real.' if good and enabled and events else 'Revisar activación, categorías y coincidencia de la clave pública en SendGrid y el SOC.'}
        state.details=result;state.last_success_at=timezone.now();state.error=''
    except error.HTTPError as exc:
        state.details={'status':'permission' if exc.code in (401,403) else 'unavailable','note':'La clave API no permite consultar webhooks. Puedes configurarlos manualmente en SendGrid y guardar la clave pública en el SOC.' if exc.code in (401,403) else 'SendGrid no permitió comprobar el destino.'};state.error='Consulta no completada.'
    except Exception:
        state.details={'status':'unavailable','note':'No se pudo comprobar la configuración del proveedor. Revisar conexión, región y permisos.'};state.error='Consulta no completada.'
    state.save()
    return state

"""One-use welcome links; administrators never choose the user's password."""
import hashlib,hmac,secrets
from datetime import timedelta
from urllib.parse import urlsplit
from django.conf import settings
from django.contrib.auth import logout
from django.contrib.auth.forms import SetPasswordForm
from django.contrib.auth import get_user_model
from django.db import transaction
from django.shortcuts import render,redirect
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.debug import sensitive_post_parameters
from django.views.decorators.http import require_http_methods
from .models import UserInvitation
from .security import encrypt,decrypt,audit,throttled,failed_attempt

def origin():
    value=getattr(settings,'SOC_PUBLIC_ORIGIN','https://soc.ibred.es').rstrip('/')
    parsed=urlsplit(value)
    if parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:raise ValueError('Invalid public origin')
    return value

def queue(user):
    if not user.email:raise ValueError('El usuario necesita un correo para recibir la invitación.')
    if user.has_usable_password():raise ValueError('La cuenta ya ha establecido su contraseña.')
    token=secrets.token_urlsafe(32)
    invitation,_=UserInvitation.objects.update_or_create(user=user,defaults={'recipient':user.email,
        'token_hash':hashlib.sha256(token.encode()).hexdigest(),'encrypted_token':encrypt(token),'created_at':timezone.now(),
        'expires_at':timezone.now()+timedelta(hours=48),'accepted_at':None,'sent_at':None,'attempted_at':None,'status':'queued','error':'','provider_id':''})
    audit('staff.invitation_queued',user)
    return invitation

def send_pending(limit=3):
    from .mail_delivery import send_customer_email,MailConfigurationError,MailDeliveryError
    # Never retry an uncertain request automatically. A manager may rotate/resend.
    for item in UserInvitation.objects.filter(status='queued',expires_at__gt=timezone.now(),accepted_at=None,user__is_active=True).select_related('user').order_by('created_at')[:limit]:
        if item.user.has_usable_password() or item.recipient.casefold()!=item.user.email.casefold():
            UserInvitation.objects.filter(pk=item.pk).update(status='failed',encrypted_token='',error='La cuenta cambió. Revisa el correo y vuelve a invitar.');continue
        if not UserInvitation.objects.filter(pk=item.pk,status='queued').update(status='sending',attempted_at=timezone.now()):continue
        try:
            token=decrypt(item.encrypted_token)
            url=origin()+reverse('accept_invitation',args=[item.user_id,token])
            context={'email':item.recipient,'username':item.user.username,'activation_url':url,'expires_at':item.expires_at,'logo_url':origin()+'/static/brand/ibred-empresas-color.png'}
            provider=send_customer_email(item.recipient,'Bienvenido al Centro SOC · ib-red empresas',render_to_string('welcome_email.txt',context),render_to_string('welcome_email.html',context))
            UserInvitation.objects.filter(pk=item.pk,token_hash=item.token_hash,status='sending').update(status='accepted',sent_at=timezone.now(),provider_id=provider,encrypted_token='',error='')
            audit('staff.invitation_sent',item.user)
        except MailConfigurationError:
            UserInvitation.objects.filter(pk=item.pk,token_hash=item.token_hash,status='sending').update(status='failed',error='El correo del SOC no está configurado y probado.')
        except MailDeliveryError:
            UserInvitation.objects.filter(pk=item.pk,token_hash=item.token_hash,status='sending').update(status='uncertain',error='SendGrid no confirmó la aceptación. Revisa el envío antes de reenviar.')
        except Exception:
            UserInvitation.objects.filter(pk=item.pk,token_hash=item.token_hash,status='sending').update(status='failed',error='No se pudo preparar la invitación. Revisa la configuración y reenvía.')

def eligible(item):
    return bool(item and item.user.is_active and not item.user.has_usable_password() and not item.accepted_at and item.expires_at>timezone.now() and item.recipient.casefold()==item.user.email.casefold())

@never_cache
@sensitive_post_parameters('new_password1','new_password2')
@require_http_methods(['GET','POST'])
def activate(request,uid,token):
    item=UserInvitation.objects.select_related('user').filter(user_id=uid).first()
    valid=eligible(item)
    if token!='set-password':
        # Mail scanners can open the URL; a GET never consumes the invitation.
        if request.method!='GET' or len(token)>100 or not valid or not hmac.compare_digest(hashlib.sha256(token.encode()).hexdigest(),item.token_hash):
            return activation_response(request,{'invalid':True},400)
        request.session['soc_invitation']={'user':uid,'hash':item.token_hash}
        response=redirect('accept_invitation',uid=uid,token='set-password');response['Referrer-Policy']='no-referrer';return response
    session=request.session.get('soc_invitation',{})
    if not valid or session.get('user')!=uid or not hmac.compare_digest(str(session.get('hash','')),item.token_hash):
        return activation_response(request,{'invalid':True},400)
    form=SetPasswordForm(item.user,request.POST or None)
    for field in form.fields.values():field.widget.attrs['class']='input'
    if request.method=='POST':
        if throttled(request,'invitation',str(uid),limit=10):return activation_response(request,{'limited':True},429)
        if form.is_valid():
            # CAS is also the write lock on SQLite. A competing activation gets zero.
            with transaction.atomic():
                claimed=UserInvitation.objects.filter(pk=item.pk,token_hash=item.token_hash,accepted_at=None,expires_at__gt=timezone.now(),user__is_active=True,user__email=item.recipient).update(accepted_at=timezone.now(),encrypted_token='')
                if not claimed:return activation_response(request,{'invalid':True},400)
                user=get_user_model().objects.get(pk=uid)
                if user.has_usable_password():
                    transaction.set_rollback(True);return activation_response(request,{'invalid':True},400)
                user.set_password(form.cleaned_data['new_password1']);user.save(update_fields=['password'])
                audit('staff.invitation_accepted',user,user=user)
            logout(request)
            return activation_response(request,{'complete':True})
        failed_attempt(request,'invitation',str(uid))
    return activation_response(request,{'form':form,'username':item.user.username,'email':item.recipient})

def activation_response(request,context,status=200):
    response=render(request,'activate_account.html',context,status=status)
    # The form URL contains no invitation secret. Preserve its same-origin POST
    # Origin header; no-referrer makes browsers send Origin: null and fails CSRF.
    response['Referrer-Policy']='same-origin'
    response['X-Robots-Tag']='noindex, nofollow'
    return response

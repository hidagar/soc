"""Internal nginx authorization subrequest; never accepts browser identity headers."""
import hmac
import time
from django.conf import settings
from django.http import HttpResponse, HttpResponseForbidden
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect,render
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET
from .models import StaffAccess,MfaProfile,Client
from .security import audit

def allowed(user):
    if not user.is_authenticated or not user.is_active:return False
    if user.is_superuser:return True
    access=StaffAccess.objects.filter(user=user).first()
    if not access:return False
    if access.role=='customer':return not access.all_clients and access.clients.filter(active=True).count()==1 and access.clients.count()==1
    return access.role in ('manager','operator','reader') and (access.all_clients or access.clients.filter(active=True).exists())

def global_access(user):
    return user.is_superuser or StaffAccess.objects.filter(user=user,all_clients=True,role__in=['manager','operator','reader']).exists()

def selected_scope(request):
    access=StaffAccess.objects.filter(user=request.user).first()
    if not access:return None
    clients=access.clients.filter(active=True)
    wanted=request.session.get('soc_wazuh_client')
    if wanted is None and clients.count()==1:wanted=clients.first().pk
    return clients.filter(pk=wanted).first() if isinstance(wanted,int) and not isinstance(wanted,bool) else None

def verified(request):
    profile=MfaProfile.objects.filter(user=request.user,enabled=True).first()
    return bool(profile and request.session.get('soc_mfa_user')==request.user.pk
        and request.session.get('soc_mfa_version')==profile.version
        and 0 <= time.time()-request.session.get('soc_mfa_at',0) < settings.SESSION_COOKIE_AGE)

@never_cache
@require_GET
def check(request):
    expected=getattr(settings,'SOC_WAZUH_PROXY_KEY','')
    given=request.headers.get('X-SOC-Wazuh-Key','')
    if not expected or not hmac.compare_digest(given,expected):return HttpResponseForbidden()
    if not request.user.is_authenticated:return HttpResponse(status=401)
    if not allowed(request.user):return HttpResponseForbidden('Acceso Wazuh no autorizado.')
    if not verified(request):return HttpResponse(status=401)
    response=HttpResponse(status=200)
    if global_access(request.user):
        response['X-SOC-Wazuh-User']=f'soc-portal-{request.user.pk}'
        response['X-SOC-Wazuh-Roles']='soc_portal_reader'
        response['X-SOC-Wazuh-Tenant']='global'
    else:
        from .wazuh_scoped import binding_ready,names
        client=selected_scope(request)
        if not client or not binding_ready(client.pk):return HttpResponseForbidden('Ámbito no preparado o permiso revocado.')
        n=names(client.pk)
        response['X-SOC-Wazuh-User']=f'soc-c{client.pk}-u{request.user.pk}'
        response['X-SOC-Wazuh-Roles']=n['role']+',soc_portal_scoped'
        response['X-SOC-Wazuh-Tenant']=n['tenant']
    return response

@login_required
@never_cache
@require_GET
def enter(request):
    if not allowed(request.user):return HttpResponseForbidden('Acceso Wazuh no autorizado.')
    if not verified(request):return redirect('mfa_challenge')
    dashboard='soc-general'
    code=request.GET.get('client','')
    if not global_access(request.user):
        access=StaffAccess.objects.get(user=request.user)
        clients=access.clients.filter(active=True)
        if not code and clients.count()!=1:return render(request,'wazuh_scope_choice.html',{'clients':clients})
        client=clients.filter(code=code).first() if code else clients.first()
        if not client:return HttpResponse(status=404)
        from .wazuh_scoped import binding_ready,names
        if not binding_ready(client.pk):return HttpResponse('El dashboard de esta empresa aún no está preparado. Contacta con el SOC.',status=503)
        request.session['soc_wazuh_client']=client.pk
        n=names(client.pk)
        audit('wazuh.sso_access',details={'role':'reader','clients':[client.pk]},user=request.user)
        return redirect('/wazuh/app/dashboards?security_tenant='+n['tenant']+'#/view/'+n['dashboard'])
    if code:
        client=Client.objects.filter(code=code,active=True).first()
        if client is None:return HttpResponse(status=404)
        from urllib.parse import quote
        dashboard='soc-client-'+quote(client.code,safe='')
    audit('wazuh.sso_access',details={'role':'reader'},user=request.user)
    return redirect('/wazuh/app/dashboards#/view/'+dashboard)

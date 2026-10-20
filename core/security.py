"""Internal staff security: TOTP, client authorization and redacted audit."""
import base64
import hashlib
import hmac
import ipaddress
import json
import secrets
import struct
import time
from datetime import timedelta
from urllib.parse import quote
from cryptography.fernet import Fernet
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import check_password, make_password
from django.db import transaction
from django.http import HttpResponse, HttpResponseForbidden
from django.shortcuts import redirect, render
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_http_methods
from .models import AuditEvent, AuthAttempt, MfaProfile, StaffAccess, WorkerState
from .scope import actor_scope, customer_scope

def vault():
    # Separate cryptographic domain from connector credentials; survives process restarts.
    key = hmac.new(settings.SECRET_KEY.encode(), b'soc-operations-vault-v1', hashlib.sha256).digest()
    return Fernet(base64.urlsafe_b64encode(key))

def encrypt(value):
    return vault().encrypt(value.encode()).decode()

def decrypt(value):
    return vault().decrypt(value.encode()).decode()

def totp(secret, counter, digits=6):
    key = base64.b32decode(secret + '=' * (-len(secret) % 8), casefold=True)
    data = hmac.new(key, struct.pack('>Q', counter), hashlib.sha1).digest()
    offset = data[-1] & 15
    number = (struct.unpack('>I', data[offset:offset + 4])[0] & 0x7fffffff) % (10 ** digits)
    return str(number).zfill(digits)

def verify_token(profile, value, now=None, recovery=True):
    now = time.time() if now is None else now
    value = str(value).strip().replace(' ', '').replace('-', '')
    with transaction.atomic():
        locked = MfaProfile.objects.select_for_update().get(pk=profile.pk)
        secret = decrypt(locked.encrypted_secret)
        if value.isascii() and value.isdigit() and len(value) == 6:
            counter = int(now // 30)
            for candidate in (counter, counter - 1, counter + 1):
                if candidate > locked.last_counter and hmac.compare_digest(value, totp(secret, candidate)):
                    # Optimistic CAS also prevents replay on databases without row locking.
                    if MfaProfile.objects.filter(pk=locked.pk, last_counter=locked.last_counter).update(last_counter=candidate):
                        return True
                    return False
        if recovery and locked.enabled:
            for encoded in locked.recovery_hashes:
                if check_password(value.lower(), encoded):
                    hashes = list(locked.recovery_hashes)
                    hashes.remove(encoded)
                    count = MfaProfile.objects.filter(pk=locked.pk, recovery_hashes=locked.recovery_hashes).update(recovery_hashes=hashes)
                    return bool(count)
    return False

def attempt_key(request, purpose, username=None):
    identity = username if username is not None else str(getattr(request.user, 'pk', 'anonymous'))
    value = f'{purpose}|{str(identity).strip().lower()}'
    return hmac.new(settings.SECRET_KEY.encode(), value.encode(), hashlib.sha256).hexdigest()

def throttled(request, purpose, username=None, limit=8):
    key = attempt_key(request, purpose, username)
    return AuthAttempt.objects.filter(identifier=key, occurred_at__gte=timezone.now()-timedelta(minutes=15)).count() >= limit

def failed_attempt(request, purpose, username=None):
    AuthAttempt.objects.create(identifier=attempt_key(request, purpose, username))

def client_ip(request):
    """IP del navegador, o None si no se puede atribuir con seguridad.

    Detrás del Nginx local REMOTE_ADDR es el proxy: solo entonces se acepta su
    X-Real-IP (que el proxy sustituye). Sin esa cabecera devolver el proxy haría
    que un único límite bloqueara el acceso de todos los usuarios.
    """
    remote = request.META.get('REMOTE_ADDR', '')
    value = request.META.get('HTTP_X_REAL_IP', '') if remote in settings.SOC_TRUSTED_PROXIES else remote
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    return None if str(address) in settings.SOC_TRUSTED_PROXIES else str(address)

def login_throttled(request):
    ip = client_ip(request)
    return (throttled(request, 'password', request.POST.get('username', ''))
            or bool(ip and throttled(request, 'password-ip', ip, limit=settings.SOC_LOGIN_IP_LIMIT)))

def failed_login(request):
    failed_attempt(request, 'password', request.POST.get('username', ''))
    ip = client_ip(request)
    if ip:
        failed_attempt(request, 'password-ip', ip)

def audit(action, obj=None, details=None, user=None):
    user = user or actor_scope.get()
    # Fixed allowlist: never request bodies, tokens, credentials, URLs or arbitrary notes.
    safe = {k: v for k, v in (details or {}).items() if k in {'fields','status','count','template','role','clients','reason','job','sha256'}}
    with transaction.atomic():
        WorkerState.reserve('audit-lock')
        previous = AuditEvent.objects.order_by('-pk').first()
        stamp = timezone.now()
        record = {'actor_name': user.get_username() if user and user.is_authenticated else 'system',
                  'action': str(action)[:100], 'object_type': obj.__class__.__name__ if obj else '',
                  'object_id': str(obj.pk) if obj else '', 'details': safe,
                  'previous_hash': previous.digest if previous else '', 'created_at': stamp.isoformat()}
        digest = hmac.new(settings.SECRET_KEY.encode(),b'soc-audit-v1|'+json.dumps(record, sort_keys=True, separators=(',',':')).encode(),hashlib.sha256).hexdigest()
        return AuditEvent.objects.create(actor=user if user and user.is_authenticated else None,
            actor_name=record['actor_name'], action=record['action'], object_type=record['object_type'],
            object_id=record['object_id'], details=safe, previous_hash=record['previous_hash'], digest=digest, created_at=stamp)

def audit_integrity():
    previous = ''
    for row in AuditEvent.objects.order_by('pk').iterator():
        record = {k: getattr(row, k) for k in ('actor_name','action','object_type','object_id','details','previous_hash')}
        record['created_at'] = row.created_at.isoformat()
        expected = hmac.new(settings.SECRET_KEY.encode(),b'soc-audit-v1|'+json.dumps(record, sort_keys=True, separators=(',',':')).encode(),hashlib.sha256).hexdigest()
        if row.previous_hash != previous or not hmac.compare_digest(row.digest, expected):
            return False
        previous = row.digest
    return True

def mfa_fresh(request, seconds=600):
    return bool(request.session.get('soc_mfa_user') == request.user.pk and
                time.time() - request.session.get('soc_mfa_at', 0) < seconds)

def mark_mfa(request, profile):
    request.session.cycle_key()
    request.session['soc_mfa_user'] = request.user.pk
    request.session['soc_mfa_version'] = profile.version
    request.session['soc_mfa_at'] = time.time()

class SocSecurityMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def process_view(self, request, view_func, view_args, view_kwargs):
        if not request.user.is_authenticated or request.user.is_superuser:
            return None
        access = StaffAccess.objects.filter(user=request.user).first()
        if access and access.role=='customer':
            allowed=request.path.startswith(('/cliente/','/security/mfa/','/reports/','/activate/')) or request.path in ('/login/','/logout/','/security/wazuh/enter/','/security/wazuh/check/')
            if request.path in ('/','/gestion/') and request.method in ('GET','HEAD'):
                return redirect('customer_home')
            if not allowed:
                return HttpResponseForbidden('Esta cuenta solo puede acceder al portal de su empresa.')
        global_views={'mail_settings','verify_public_reports','audit_log','recovery','staff','staff_edit','mfa_reset','delivery_settings'}
        if request.resolver_match and request.resolver_match.url_name in global_views and not (access and access.all_clients):
            return HttpResponseForbidden('Esta operación requiere acceso global al SOC.')
        if request.path.startswith('/admin/') and request.path not in ('/admin/login/','/admin/logout/'):
            if not access or access.role != 'manager' or not access.all_clients:
                return HttpResponseForbidden('Administración global requerida.')
        if request.method in ('GET','HEAD','OPTIONS'):
            return None
        name = request.resolver_match.url_name if request.resolver_match else ''
        permissions = {'client_new':'add_client','client_edit':'change_client',
            'site_new':'add_site','site_edit':'change_site','site_delete':'delete_site',
            'device_new':'add_device','device_edit':'change_device','onboarding_add_device':'add_device',
            'device_onboarding':'change_device','incident_new':'add_incident','incident_edit':'change_incident',
            'mail_settings':'manage_connections','verify_public_reports':'manage_connections',
            'manage_report_link':'manage_connections','export_destination':'manage_connections'}
        required = permissions.get(name)
        if required and not request.user.has_perm('core.'+required):
            return HttpResponseForbidden('Tu perfil no permite esta operación.')

    def __call__(self, request):
        public = request.path.startswith(('/reports/','/activate/','/ingest/'))
        # A pre-existing session is not evidence that this login POST succeeded.
        request.soc_password_login_user = None
        if request.method == 'POST' and request.path in ('/login/', '/admin/login/'):
            if login_throttled(request):
                return HttpResponse('Demasiados intentos. Espera 15 minutos.', status=429)
        access = None
        ids = None
        if request.user.is_authenticated and not public:
            access = StaffAccess.objects.filter(user=request.user).first()
            if access and access.role=='customer':
                ids=list(access.clients.values_list('pk',flat=True))
                if len(ids)!=1 or access.all_clients or request.user.is_superuser:
                    return HttpResponseForbidden('Acceso de cliente no válido. Contacta con el SOC.')
            elif not request.user.is_superuser and not (access and access.all_clients):
                ids = list(access.clients.values_list('pk', flat=True)) if access else []
            exempt = request.path.startswith('/security/mfa/') or request.path in ('/logout/','/login/','/admin/logout/','/security/wazuh/check/')
            if getattr(settings, 'SOC_MFA_REQUIRED', True) and not exempt:
                profile = MfaProfile.objects.filter(user=request.user).first()
                if not profile or not profile.enabled:
                    return redirect('mfa_setup')
                if request.session.get('soc_mfa_user') != request.user.pk or request.session.get('soc_mfa_version') != profile.version:
                    return redirect('mfa_challenge')
            if request.method not in ('GET','HEAD','OPTIONS') and not exempt:
                role = 'manager' if request.user.is_superuser else access.role if access else 'reader'
                import re
                customer_reply=role=='customer' and bool(re.fullmatch(r'/cliente/tareas/[0-9]+/responder/',request.path))
                if role in ('reader','customer') and not customer_reply:
                    return HttpResponseForbidden('Tu perfil es de consulta. Solicita acceso de operador.')
        scope_token = customer_scope.set(ids if not public else None)
        actor_token = actor_scope.set(request.user if request.user.is_authenticated else None)
        try:
            response = self.get_response(request)
            if request.method == 'POST' and request.path in ('/login/','/admin/login/'):
                if request.soc_password_login_user is None:
                    failed_login(request)
                else:
                    # Solo se limpia la identidad intentada: los fallos de la IP siguen contando.
                    AuthAttempt.objects.filter(identifier=attempt_key(request,'password',request.POST.get('username',''))).delete()
                    audit('password_login', user=request.soc_password_login_user)
            elif request.user.is_authenticated and request.method not in ('GET','HEAD','OPTIONS') and response.status_code < 400:
                match = getattr(request, 'resolver_match', None)
                name = match.url_name if match else 'request'
                audit('portal.' + str(name), details={'status': response.status_code}, user=request.user)
            if not public:
                response['Cache-Control'] = 'no-store, private'
            return response
        finally:
            actor_scope.reset(actor_token)
            customer_scope.reset(scope_token)

@login_required
@never_cache
@require_http_methods(['GET','POST'])
def mfa_setup(request):
    profile, _ = MfaProfile.objects.get_or_create(user=request.user)
    if profile.enabled:
        codes = request.session.pop('soc_new_recovery_codes', [])
        return render(request, 'security_mfa.html', {'enabled': True, 'codes': codes})
    error = ''
    if request.method == 'POST':
        if throttled(request, 'enrol'):
            return HttpResponse('Demasiados intentos. Espera 15 minutos.', status=429)
        if request.POST.get('action') == 'generate':
            if request.user.check_password(request.POST.get('password','')):
                secret = base64.b32encode(secrets.token_bytes(20)).decode().rstrip('=')
                profile.encrypted_secret = encrypt(secret)
                profile.last_counter = -1
                profile.save()
                request.session['soc_enrol_at'] = time.time()
            else:
                failed_attempt(request, 'enrol')
                error = 'La contraseña no es correcta.'
        elif request.POST.get('action') == 'confirm':
            if time.time()-request.session.get('soc_enrol_at',0) > 600 or not profile.encrypted_secret:
                error = 'Vuelve a confirmar tu contraseña para preparar el autenticador.'
            elif verify_token(profile, request.POST.get('code',''), recovery=False):
                codes = [secrets.token_hex(8) for _ in range(10)]
                profile.enabled = True
                profile.recovery_hashes = [make_password(code) for code in codes]
                profile.save(update_fields=['enabled','recovery_hashes','updated_at'])
                mark_mfa(request, profile)
                request.session['soc_new_recovery_codes'] = codes
                request.session.pop('soc_enrol_at',None)
                audit('mfa.enrolled', profile)
                return redirect('mfa_setup')
            else:
                failed_attempt(request, 'enrol')
                error = 'El código no es válido o ya se ha utilizado.'
    secret = ''
    svg = ''
    if profile.encrypted_secret and time.time()-request.session.get('soc_enrol_at',0) < 600:
        secret = decrypt(profile.encrypted_secret)
        uri = 'otpauth://totp/' + quote('Centro SOC:' + request.user.username, safe='') + '?secret=' + secret + '&issuer=Centro%20SOC&digits=6&period=30'
        from reportlab.graphics.barcode.qr import QrCodeWidget
        from reportlab.graphics.shapes import Drawing
        from reportlab.graphics import renderSVG
        qr = QrCodeWidget(uri)
        bounds = qr.getBounds()
        drawing = Drawing(220,220,transform=[220/(bounds[2]-bounds[0]),0,0,220/(bounds[3]-bounds[1]),0,0])
        drawing.add(qr)
        svg = renderSVG.drawToString(drawing)
        if isinstance(svg, bytes):
            svg = svg.decode()
    return render(request,'security_mfa.html',{'secret':secret,'qr':svg,'error':error})

@login_required
@never_cache
@require_http_methods(['GET','POST'])
def mfa_challenge(request):
    profile = MfaProfile.objects.filter(user=request.user, enabled=True).first()
    if not profile:
        return redirect('mfa_setup')
    error = ''
    if request.method == 'POST':
        if throttled(request, 'mfa'):
            return HttpResponse('Demasiados intentos. Espera 15 minutos.',status=429)
        if verify_token(profile, request.POST.get('code','')):
            mark_mfa(request,profile)
            audit('mfa.verified',profile)
            access=StaffAccess.objects.filter(user=request.user).first()
            return redirect('customer_home' if access and access.role=='customer' else 'dashboard')
        failed_attempt(request,'mfa')
        error = 'Código incorrecto, caducado o ya utilizado.'
    return render(request,'security_mfa.html',{'challenge':True,'error':error})

@login_required
@require_http_methods(['POST'])
def mfa_reset(request, pk):
    from django.contrib.auth import get_user_model
    from django.shortcuts import get_object_or_404
    access = getattr(request.user,'soc_access',None)
    if not request.user.has_perm('core.manage_security') or not (request.user.is_superuser or access and access.all_clients):
        return HttpResponseForbidden('Administración global requerida.')
    if not mfa_fresh(request):
        return redirect('mfa_challenge')
    user = get_object_or_404(get_user_model(),pk=pk)
    if user.is_superuser and not request.user.is_superuser:
        return HttpResponseForbidden('No puedes restablecer este usuario.')
    if request.POST.get('username') != user.username:
        return HttpResponseForbidden('Confirma el nombre exacto del usuario.')
    profile,_ = MfaProfile.objects.get_or_create(user=user)
    profile.enabled=False
    profile.encrypted_secret=''
    profile.recovery_hashes=[]
    profile.last_counter=-1
    profile.version+=1
    profile.save()
    audit('mfa.reset',profile, user=request.user)
    messages.success(request,'Autenticador restablecido. El usuario debe volver a configurarlo.')
    return redirect('staff')

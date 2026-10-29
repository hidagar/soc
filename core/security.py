"""Internal staff security: TOTP, client authorization and redacted audit."""
import base64
import hashlib
import hmac
import ipaddress
import json
import logging
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
from .keyring import multifernet
from .scope import actor_scope, customer_scope

def vault():
    # Separate cryptographic domain from connector credentials; survives process restarts.
    # SOC_PORTAL_VAULT_KEYS (opcional, «nueva,anterior») desacopla la bóveda de SECRET_KEY;
    # la clave derivada sigue al final para leer lo cifrado antes de rotar.
    key = hmac.new(settings.SECRET_KEY.encode(), b'soc-operations-vault-v1', hashlib.sha256).digest()
    return multifernet(settings.SOC_VAULT_KEYS, legacy=[Fernet(base64.urlsafe_b64encode(key))])

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
        if recovery and locked.enabled and len(value) == 16 and all(c in '0123456789abcdefABCDEF' for c in value):
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

# Campos de auditoría permitidos: valores acotados o identificadores, nunca texto libre.
AUDIT_FIELDS = {'fields','status','count','template','role','clients','reason','job','sha256',
                'decision','until','incident_id','owner','due_at','active','all_clients'}

def audit(action, obj=None, details=None, user=None):
    user = user or actor_scope.get()
    # Fixed allowlist: never request bodies, tokens, credentials, URLs or arbitrary notes.
    safe = {k: v for k, v in (details or {}).items() if k in AUDIT_FIELDS}
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

def audit_chain(after_pk=0, previous='', deadline=None):
    """Comprueba la cadena desde el evento `after_pk` (excluido), cuyo resumen es `previous`.

    Devuelve (íntegra, último pk, último resumen, terminada). Con `deadline` (time.monotonic) para al
    agotar el tiempo y la llamada siguiente continúa desde el último punto.
    """
    last = after_pk
    for row in AuditEvent.objects.filter(pk__gt=after_pk).order_by('pk').iterator(chunk_size=2000):
        record = {k: getattr(row, k) for k in ('actor_name','action','object_type','object_id','details','previous_hash')}
        record['created_at'] = row.created_at.isoformat()
        expected = hmac.new(settings.SECRET_KEY.encode(),b'soc-audit-v1|'+json.dumps(record, sort_keys=True, separators=(',',':')).encode(),hashlib.sha256).hexdigest()
        if row.previous_hash != previous or not hmac.compare_digest(row.digest, expected):
            return False, last, previous, True
        previous, last = row.digest, row.pk
        if deadline is not None and time.monotonic() > deadline:
            return True, last, previous, False
    return True, last, previous, True

def audit_integrity():
    """Cadena completa desde el primer evento (restauraciones, traslados y pruebas)."""
    return audit_chain()[0]

AUDIT_CHECK_EVERY = timedelta(hours=24)

def check_audit_chain(now=None, budget=60):
    """Trabajo horario: una pasada completa al día, por partes de `budget` segundos.

    La página de auditoría recorría toda la cadena en cada visita, y con muchos eventos acababa
    superando el límite de tiempo. Ahora solo comprueba los eventos posteriores a esta pasada.
    """
    from django.utils.dateparse import parse_datetime
    from .operations import set_issue
    now = now or timezone.now()
    with transaction.atomic():
        WorkerState.reserve('audit-integrity')
    state = WorkerState.objects.get(name='audit-integrity')
    details = dict(state.details)
    if not details.get('in_progress'):
        last_pass = parse_datetime(details.get('pass_at') or '')
        if last_pass and now - last_pass < AUDIT_CHECK_EVERY:
            return details
        details.update(in_progress=True, cursor_pk=0, cursor_digest='')
    ok, pk, digest, done = audit_chain(details['cursor_pk'], details['cursor_digest'], time.monotonic() + budget)
    if not ok:
        details.update(in_progress=False, ok=False, pass_at=now.isoformat(), broken_after_pk=pk)
        set_issue('platform:audit-integrity', 'La cadena de auditoría no es íntegra', severity='critical', now=now,
                  details=f'Un evento posterior al número {pk} no coincide con su firma o con el anterior. Revisar '
                          'si se ha modificado la base o cambiado SOC_PORTAL_SECRET_KEY antes de seguir.')
    elif done:
        details.update(in_progress=False, ok=True, pass_at=now.isoformat(), full_at=now.isoformat(),
                       verified_pk=pk, verified_digest=digest)
        details.pop('broken_after_pk', None)
        from .models import OperationalIssue
        OperationalIssue.objects.filter(key='platform:audit-integrity', active=True).update(active=False, resolved_at=now)
    else:
        details.update(cursor_pk=pk, cursor_digest=digest)
    WorkerState.objects.filter(name='audit-integrity').update(details=details, last_run_at=now)
    return details

def audit_status():
    """Para la página de auditoría: la última pasada completa más los eventos posteriores, comprobados ahora.

    Detecta también el borrado del último evento ya comprobado (truncar la cola de la cadena no
    rompe la firma de los anteriores).
    """
    from django.utils.dateparse import parse_datetime
    state = WorkerState.objects.filter(name='audit-integrity').first()
    details = state.details if state else {}
    if details.get('ok') is False:
        return {'ok': False, 'full_at': None}
    full_at = parse_datetime(details.get('full_at') or '')
    if not full_at:
        return {'ok': audit_integrity(), 'full_at': None}  # aún sin pasada completa: como antes, toda la cadena
    pk, digest = details['verified_pk'], details['verified_digest']
    if pk and not AuditEvent.objects.filter(pk=pk, digest=digest).exists():
        return {'ok': False, 'full_at': full_at, 'truncated': True}
    return {'ok': audit_chain(pk, digest)[0], 'full_at': full_at,
            'recent': AuditEvent.objects.filter(pk__gt=pk).count()}

def mfa_fresh(request, seconds=600):
    return bool(request.session.get('soc_mfa_user') == request.user.pk and
                time.time() - request.session.get('soc_mfa_at', 0) < seconds)

def mark_mfa(request, profile):
    request.session.cycle_key()
    request.session['soc_mfa_user'] = request.user.pk
    request.session['soc_mfa_version'] = profile.version
    request.session['soc_mfa_at'] = time.time()

# Guardan credenciales, destinos de envío o borran datos: un MFA de hace más de 10 minutos no basta.
FRESH_MFA_VIEWS = {'mail_settings','verify_public_reports','unifi_cloud','opnsense_api','ssh_connection',
                   'export_destination','site_delete','hillstone_api','gdms_cloud'}
# Desactivar el envío es una parada segura: no se retrasa con el MFA.
FRESH_MFA_EXEMPT = {('mail_settings','disable')}
# Tiempo máximo de una sesión verificada con MFA, aunque se siga usando.
MFA_SESSION_MAX = 12 * 3600

class SocSecurityMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def process_view(self, request, view_func, view_args, view_kwargs):
        if not request.user.is_authenticated:
            return None
        name = request.resolver_match.url_name if request.resolver_match else ''
        if (request.method not in ('GET','HEAD','OPTIONS') and name in FRESH_MFA_VIEWS
                and (name, request.POST.get('action', '')) not in FRESH_MFA_EXEMPT and not mfa_fresh(request)):
            messages.info(request, 'Confirma tu código MFA y repite la operación.')
            return redirect('mfa_challenge')
        if request.user.is_superuser:
            return None
        access = StaffAccess.objects.filter(user=request.user).first()
        if access and access.role=='customer':
            allowed=request.path.startswith(('/cliente/','/security/mfa/','/reports/','/activate/')) or request.path in ('/login/','/logout/','/security/wazuh/enter/','/security/wazuh/check/')
            if request.path in ('/','/gestion/') and request.method in ('GET','HEAD'):
                return redirect('customer_home')
            if not allowed:
                return HttpResponseForbidden('Esta cuenta solo puede acceder al portal de su empresa.')
        global_views={'mail_settings','verify_public_reports','audit_log','recovery','staff','staff_edit','mfa_reset','delivery_settings',
            'crowdsec_list_action',  # cambia las suscripciones de toda la organización de CrowdSec
            'client_new'}  # un gestor limitado no vería el cliente que acaba de crear
        if request.resolver_match and request.resolver_match.url_name in global_views and not (access and access.all_clients):
            return HttpResponseForbidden('Esta operación requiere acceso global al SOC.')
        if request.path.startswith('/admin/') and request.path not in ('/admin/login/','/admin/logout/'):
            if not access or access.role != 'manager' or not access.all_clients:
                return HttpResponseForbidden('Administración global requerida.')
        if request.method in ('GET','HEAD','OPTIONS'):
            return None
        permissions = {'client_new':'add_client','client_edit':'change_client',
            'site_new':'add_site','site_edit':'change_site','site_delete':'delete_site',
            'device_new':'add_device','device_edit':'change_device','onboarding_add_device':'add_device',
            'device_onboarding':'change_device','incident_new':'add_incident','incident_edit':'change_incident',
            'mail_settings':'manage_connections','verify_public_reports':'manage_connections',
            'manage_report_link':'manage_connections','rectify_report':'manage_connections','export_destination':'manage_connections'}
        required = permissions.get(name)
        if required and not request.user.has_perm('core.'+required):
            return HttpResponseForbidden('Tu perfil no permite esta operación.')

    def __call__(self, request):
        public = request.path.startswith(('/reports/','/activate/','/ingest/','/feeds/'))
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
                if time.time() - request.session.get('soc_mfa_at', 0) > MFA_SESSION_MAX:
                    request.session.pop('soc_mfa_user', None)
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
                # Después de contar el intento y sin poder romper el acceso: solo alimenta un aviso de «Salud del SOC».
                try:
                    from .continuity import note_login_origin
                    note_login_origin(client_ip(request))
                except Exception:
                    logging.getLogger(__name__).exception('No se pudo anotar el origen del acceso')
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
            from .models import OperationalIssue
            # Aviso de plataforma (sin equipo): fuera del ámbito de cliente de quien inicia sesión.
            OperationalIssue._base_manager.filter(key=f'security:mfa-failures:{request.user.pk}',active=True).update(
                active=False,resolved_at=timezone.now())
            access=StaffAccess.objects.filter(user=request.user).first()
            return redirect('customer_home' if access and access.role=='customer' else 'dashboard')
        failed_attempt(request,'mfa')
        if throttled(request,'mfa'):
            mfa_locked(request.user,profile)
        error = 'Código incorrecto, caducado o ya utilizado.'
    return render(request,'security_mfa.html',{'challenge':True,'error':error})

def mfa_locked(user,profile):
    """Quien llega al código MFA ya ha acertado la contraseña: agotar los intentos es una señal fuerte.

    Aviso crítico al SOC (también por correo de operaciones); se resuelve cuando el usuario verifica bien
    su código. Antes solo se bloqueaba 15 minutos, sin avisar a nadie.
    """
    from .operations import set_issue
    # set_issue busca por clave con el gestor con ámbito: dentro de la petición del usuario no vería el aviso
    # anterior (sin equipo) y el segundo bloqueo chocaría con la clave única.
    token = customer_scope.set(None)
    try:
        set_issue(f'security:mfa-failures:{user.pk}','Intentos de MFA fallidos repetidos',severity='critical',
                  details=f'La cuenta {user.get_username()} ha fallado el código MFA varias veces seguidas y queda bloqueada '
                          '15 minutos. Si no ha sido el usuario, alguien conoce su contraseña: cámbiala y revisa la auditoría.')
    finally:
        customer_scope.reset(token)
    audit('mfa.locked',profile,user=user)

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

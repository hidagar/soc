"""Avisos urgentes por Microsoft Teams y Telegram, además del correo.

Garantías, las mismas que el correo urgente (AGENTS.md, invariante 6):

- Un aviso y un canal forman un único `ChatNotice` (restricción única): repetir el trabajo no lo
  publica dos veces. Se reserva con un cambio de estado condicional antes de llamar a la API.
- Si la respuesta no llega (corte de red, tiempo agotado, error 5xx), el estado queda «Entrega por
  comprobar» y no se reintenta solo: podría haberse publicado.
- Teams (Workflows) responde 202: el flujo aceptó la petición, no se confirma la publicación en el
  canal. Telegram devuelve el identificador del mensaje publicado en el grupo.
- Solo salen avisos creados después de activar el canal y dentro del plazo de envío inmediato.

La URL de Teams lleva su firma: se guarda cifrada (clave del correo) y nunca se muestra ni registra.
El token del bot de Telegram vive en el entorno (SOC_PORTAL_TELEGRAM_BOT_TOKEN), nunca en la base,
y va en la ruta de la API: los errores se describen con texto propio, sin la URL ni la respuesta.
"""
import json
import os
import re
import time
from datetime import timedelta
from urllib import error as url_error, request as url_request
from urllib.parse import urlsplit

from django import forms
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import F, Q
from django.http import HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.cache import never_cache

from .models import ChatChannel, ChatNotice, Client, UrgentAlert
from .security import audit

TEAMS_HOST_SUFFIXES = ('.logic.azure.com', '.powerplatform.com', '.webhook.office.com')
TELEGRAM_API = 'https://api.telegram.org'
CHAT_ID = re.compile(r'^(-?\d{1,20}|@[A-Za-z][A-Za-z0-9_]{4,31})$')
BOT_TOKEN = re.compile(r'^\d{5,16}:[A-Za-z0-9_-]{30,64}$')
MAX_TEXT = 3500
STALE_SENDING = timedelta(minutes=5)
BUDGET_SECONDS = 120


class ChatConfigurationError(Exception):
    pass


class ChatDeliveryError(Exception):
    def __init__(self, message, *, uncertain=False, retry_after=None):
        super().__init__(message)
        self.uncertain = uncertain
        self.retry_after = retry_after


class _NoRedirect(url_request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# --- Configuración ---------------------------------------------------------------------------

def validate_teams_url(value):
    """Solo flujos de Microsoft por HTTPS: evita usar el portal para llamar a cualquier dirección."""
    value = (value or '').strip()
    if not value or len(value) > 2048 or any(c.isspace() for c in value):
        raise ChatConfigurationError('Pega la URL completa del flujo de Teams, sin espacios.')
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError as exc:
        raise ChatConfigurationError('La URL del flujo de Teams no es válida.') from exc
    host = (parts.hostname or '').lower()
    if parts.scheme != 'https' or parts.username or parts.password or port not in (None, 443) \
            or not host.endswith(TEAMS_HOST_SUFFIXES):
        raise ChatConfigurationError('La URL debe ser la de un flujo de Microsoft (https://…logic.azure.com o '
                                     '…powerplatform.com). Créala en Teams con «Workflows».')
    return value


def validate_chat_id(value):
    value = (value or '').strip()
    if not CHAT_ID.match(value):
        raise ChatConfigurationError('El identificador del grupo de Telegram es un número (los grupos empiezan por -100) '
                                     'o @nombre_del_canal.')
    return value


def _fernet():
    from .mail_delivery import MailConfigurationError, _fernet as mail_fernet
    try:
        return mail_fernet()
    except MailConfigurationError as exc:
        raise ChatConfigurationError('Falta la clave de cifrado del correo (SOC_PORTAL_MAIL_KEY).') from exc


def encrypt_target(value):
    return _fernet().encrypt(value.encode('utf-8')).decode('ascii')


def decrypt_target(value):
    from cryptography.fernet import InvalidToken
    if not value:
        raise ChatConfigurationError('Falta la URL del flujo de Teams.')
    try:
        return _fernet().decrypt(value.encode('ascii')).decode('utf-8')
    except (InvalidToken, UnicodeError, ValueError) as exc:
        raise ChatConfigurationError('No se puede leer la URL de Teams guardada; vuelve a pegarla.') from exc


def bot_token():
    return os.environ.get('SOC_PORTAL_TELEGRAM_BOT_TOKEN', '').strip()


def telegram_ready():
    return bool(BOT_TOKEN.match(bot_token()))


# --- Contenido -------------------------------------------------------------------------------

def _defang(text):
    """Las URL de un registro no deben quedar como enlaces pulsables en el chat del cliente."""
    text = re.sub(r'(?i)\bhttp(s?)://', r'hxxp\1://', str(text or ''))
    return text.replace('[', '(').replace(']', ')').replace('<', '‹').replace('>', '›')


def facts(alert, info):
    when = timezone.localtime(alert.observed_at)
    asset = alert.asset_name or 'Equipo sin identificar'
    if alert.destination_ip:
        asset += f' ({alert.destination_ip}' + (f':{alert.destination_port}' if alert.destination_port else '') + ')'
    rows = [('Cliente', alert.client.name + (f' · {alert.site_name}' if alert.site_name else '')),
            ('Detectado', f'{when:%d/%m/%Y} a las {when:%H:%M} (hora de Madrid)'),
            ('Equipo', asset)]
    if alert.external_ip:
        rows.append(('Origen observado', alert.external_ip))
    if alert.signature:
        rows.append(('Registro', alert.signature))
    if alert.action:
        rows.append(('Acción del firewall', info['action_label']))
    return [(k, _defang(v)) for k, v in rows]


FOOTER = ('Aviso del Centro SOC de ib-red con eventos de una fuente verificada. Una detección no demuestra por sí sola '
          'que el equipo haya sido comprometido. El detalle completo llega también por correo.')


def telegram_text(alert):
    from .urgent_alerts import content
    info = content(alert)
    lines = [f'⚠️ AVISO URGENTE · {info["headline"]}', '']
    lines += [f'{k}: {v}' for k, v in facts(alert, info)]
    lines += ['', 'Qué ha pasado: ' + info['meaning'], '', 'Qué hacer ahora:']
    lines += [f'{n}. {_defang(a)}' for n, a in enumerate(info['actions'], 1)]
    lines += ['', FOOTER]
    text = '\n'.join(lines)
    return text if len(text) <= MAX_TEXT else text[:MAX_TEXT - 1] + '…'


def teams_payload(alert):
    from .urgent_alerts import content
    info = content(alert)
    body = [
        {'type': 'TextBlock', 'text': 'AVISO URGENTE · CENTRO SOC', 'size': 'Small', 'weight': 'Bolder', 'color': 'Attention'},
        {'type': 'TextBlock', 'text': info['headline'], 'size': 'Large', 'weight': 'Bolder', 'wrap': True},
        {'type': 'FactSet', 'facts': [{'title': k, 'value': v[:300]} for k, v in facts(alert, info)]},
        {'type': 'TextBlock', 'text': 'Qué ha pasado', 'weight': 'Bolder', 'spacing': 'Medium'},
        {'type': 'TextBlock', 'text': info['meaning'], 'wrap': True},
        {'type': 'TextBlock', 'text': 'Qué hacer ahora', 'weight': 'Bolder', 'spacing': 'Medium'},
        {'type': 'TextBlock', 'wrap': True,
         'text': '\r'.join(f'{n}. {_defang(a)}' for n, a in enumerate(info['actions'], 1))},
        {'type': 'TextBlock', 'text': FOOTER, 'wrap': True, 'isSubtle': True, 'size': 'Small', 'spacing': 'Medium'},
    ]
    return _card(body)


def _card(body):
    return {'type': 'message', 'attachments': [{
        'contentType': 'application/vnd.microsoft.card.adaptive', 'contentUrl': None,
        'content': {'$schema': 'http://adaptivecards.io/schemas/adaptive-card.json', 'type': 'AdaptiveCard',
                    'version': '1.4', 'body': body, 'msteams': {'width': 'Full'}}}]}


def test_text(client):
    return (f'Prueba del Centro SOC de ib-red: si ves este mensaje, los avisos urgentes de {client.name} '
            'llegarán a este chat. No hace falta responder.')


# --- Envío -----------------------------------------------------------------------------------

def _post(url, payload, timeout=15):
    req = url_request.Request(url, data=json.dumps(payload, ensure_ascii=False).encode('utf-8'),
                              headers={'Content-Type': 'application/json', 'User-Agent': 'ib-red-centro-soc/1'},
                              method='POST')
    return url_request.build_opener(_NoRedirect()).open(req, timeout=timeout)


def send_teams(channel, payload):
    url = validate_teams_url(decrypt_target(channel.encrypted_target))
    try:
        with _post(url, payload) as response:
            if response.status not in (200, 201, 202):
                raise ChatDeliveryError(f'Teams respondió HTTP {response.status}.', uncertain=True)
            return ''
    except url_error.HTTPError as exc:
        if exc.code >= 500:
            raise ChatDeliveryError(f'Teams respondió HTTP {exc.code}; puede haberse publicado.', uncertain=True) from None
        if exc.code == 429:
            raise ChatDeliveryError('Teams pidió esperar (HTTP 429).', retry_after=60) from None
        if exc.code in (401, 403, 404):
            raise ChatDeliveryError(f'Teams rechazó el aviso (HTTP {exc.code}): el flujo se borró, se desactivó o '
                                    'cambió su URL.') from None
        raise ChatDeliveryError(f'Teams rechazó el aviso: HTTP {exc.code}.') from None
    except (url_error.URLError, TimeoutError, OSError):
        raise ChatDeliveryError('No se pudo completar la conexión con Teams; puede haberse publicado.', uncertain=True) from None


def send_telegram(channel, text):
    token = bot_token()
    if not BOT_TOKEN.match(token):
        raise ChatConfigurationError('Falta el bot de Telegram del SOC (SOC_PORTAL_TELEGRAM_BOT_TOKEN).')
    chat = validate_chat_id(channel.chat_id)
    payload = {'chat_id': int(chat) if chat.lstrip('-').isdigit() else chat, 'text': text,
               'link_preview_options': {'is_disabled': True}}
    try:
        with _post(f'{TELEGRAM_API}/bot{token}/sendMessage', payload) as response:
            data = json.loads(response.read(65536) or b'{}')
    except url_error.HTTPError as exc:
        detail = _telegram_error(exc)
        if exc.code >= 500:
            raise ChatDeliveryError(f'Telegram respondió HTTP {exc.code}; puede haberse publicado.', uncertain=True) from None
        if exc.code == 429:
            raise ChatDeliveryError('Telegram pidió esperar antes de enviar más mensajes.',
                                    retry_after=detail.get('retry_after') or 60) from None
        if detail.get('migrate_to'):
            raise ChatDeliveryError(f'El grupo pasó a supergrupo: su identificador nuevo es {detail["migrate_to"]}.') from None
        if exc.code == 403:
            raise ChatDeliveryError('El bot no puede escribir en ese chat: lo expulsaron o no es miembro.') from None
        if exc.code == 400 and detail.get('not_found'):
            raise ChatDeliveryError('Telegram no encuentra el chat: revisa el identificador y que el bot esté en el grupo.') from None
        raise ChatDeliveryError(f'Telegram rechazó el mensaje: HTTP {exc.code}.') from None
    except (url_error.URLError, TimeoutError, OSError, ValueError):
        raise ChatDeliveryError('No se pudo completar la conexión con Telegram; puede haberse publicado.', uncertain=True) from None
    message_id = (data.get('result') or {}).get('message_id') if isinstance(data, dict) and data.get('ok') else None
    if not message_id:
        raise ChatDeliveryError('Telegram no devolvió el mensaje publicado.', uncertain=True)
    return str(message_id)[:64]


def _telegram_error(exc):
    """Solo los datos que necesitamos de la respuesta de error; nunca se muestra en crudo."""
    try:
        data = json.loads(exc.read(8192) or b'{}')
    except (ValueError, OSError):
        return {}
    params = data.get('parameters') or {} if isinstance(data, dict) else {}
    description = str(data.get('description') or '').lower() if isinstance(data, dict) else ''
    result = {'not_found': 'not found' in description}
    if isinstance(params.get('retry_after'), int):
        result['retry_after'] = max(1, min(params['retry_after'], 3600))
    if isinstance(params.get('migrate_to_chat_id'), int):
        result['migrate_to'] = params['migrate_to_chat_id']
    return result


def send(channel, alert):
    if channel.kind == ChatChannel.Kind.TEAMS:
        return send_teams(channel, teams_payload(alert))
    return send_telegram(channel, telegram_text(alert))


def send_test(channel):
    if channel.kind == ChatChannel.Kind.TEAMS:
        return send_teams(channel, _card([
            {'type': 'TextBlock', 'text': 'Centro SOC · ib-red', 'weight': 'Bolder', 'size': 'Medium'},
            {'type': 'TextBlock', 'text': test_text(channel.client), 'wrap': True}]))
    return send_telegram(channel, test_text(channel.client))


def recent_telegram_chats():
    """Grupos donde se añadió el bot en las últimas 24 h (getUpdates, sin confirmar: no consume nada)."""
    token = bot_token()
    if not BOT_TOKEN.match(token):
        raise ChatConfigurationError('Falta el bot de Telegram del SOC (SOC_PORTAL_TELEGRAM_BOT_TOKEN).')
    try:
        with _post(f'{TELEGRAM_API}/bot{token}/getUpdates',
                   {'limit': 100, 'timeout': 0, 'allowed_updates': ['message', 'my_chat_member', 'channel_post']}) as response:
            data = json.loads(response.read(1_000_000) or b'{}')
    except url_error.HTTPError as exc:
        if exc.code == 409:
            raise ChatDeliveryError('El bot usa un webhook: no se pueden listar los grupos desde aquí.') from None
        raise ChatDeliveryError(f'Telegram respondió HTTP {exc.code}.') from None
    except (url_error.URLError, TimeoutError, OSError, ValueError):
        raise ChatDeliveryError('No se pudo conectar con Telegram.') from None
    chats = {}
    for update in (data.get('result') or []) if isinstance(data, dict) else []:
        for key in ('my_chat_member', 'message', 'channel_post'):
            chat = (update.get(key) or {}).get('chat') if isinstance(update, dict) else None
            if isinstance(chat, dict) and isinstance(chat.get('id'), int) and chat.get('type') != 'private':
                chats[chat['id']] = {'id': chat['id'], 'title': str(chat.get('title') or '')[:120],
                                     'type': {'group': 'Grupo', 'supergroup': 'Grupo', 'channel': 'Canal'}.get(chat.get('type'), '')}
    return list(chats.values())


# --- Cola (trabajo de avisos urgentes, cada minuto) ------------------------------------------

def _wanted(channel, alert, now):
    """Motivo para no publicar el aviso en el canal, o '' si debe salir."""
    from .urgent_alerts import MAX_AGE
    client = alert.client
    if not channel.enabled or not channel.configured:
        return 'Canal desactivado.'
    if not client.active or not client.urgent_alerts_enabled:
        return 'El cliente desactivó los avisos urgentes.'
    if alert.kind == UrgentAlert.Kind.AVAILABILITY and not client.urgent_availability_enabled:
        return 'El cliente no recibe avisos de caídas de Internet.'
    if alert.acknowledged_at:
        return 'El SOC ya había revisado el aviso.'
    if alert.observed_at < now - MAX_AGE:
        return 'expired'
    return ''


def queue_new(now):
    """Un ChatNotice por aviso nuevo y canal activo. Los avisos de antes de activar el canal no salen."""
    from .urgent_alerts import MAX_AGE
    created = 0
    channels = ChatChannel._base_manager.filter(enabled=True, enabled_at__isnull=False, client__active=True,
                                                client__urgent_alerts_enabled=True).select_related('client')
    for channel in channels:
        if not channel.configured:
            continue
        alerts = (UrgentAlert._base_manager.filter(client_id=channel.client_id, created_at__gte=channel.enabled_at,
                                                   observed_at__gte=now - MAX_AGE)
                  .exclude(status=UrgentAlert.Status.EXPIRED).exclude(chat_notices__channel=channel))
        if not channel.client.urgent_availability_enabled:
            alerts = alerts.exclude(kind=UrgentAlert.Kind.AVAILABILITY)
        for alert in alerts.order_by('observed_at', 'pk')[:100]:
            created += int(ChatNotice._base_manager.get_or_create(alert=alert, channel=channel)[1])
    return created


def deliver_pending(now=None):
    """Publica los avisos pendientes. Devuelve cuántos aceptó Teams o publicó Telegram."""
    from .urgent_alerts import COOLDOWN
    now = now or timezone.now()
    ChatNotice._base_manager.filter(status=ChatNotice.Status.SENDING, last_attempt_at__lt=now - STALE_SENDING).update(
        status=ChatNotice.Status.UNCERTAIN, last_error='El proceso terminó durante el envío; comprobar en el chat antes de reenviar.')
    queue_new(now)
    sent, started = 0, time.monotonic()
    queue = (ChatNotice._base_manager.filter(status__in=[ChatNotice.Status.PENDING, ChatNotice.Status.FAILED], attempts__lt=3)
             .filter(Q(next_retry_at__isnull=True) | Q(next_retry_at__lte=now))
             .select_related('alert__client', 'channel__client').order_by('alert__observed_at', 'pk')[:100])
    for notice in queue:
        if time.monotonic() - started > BUDGET_SECONDS:
            break  # el resto sale en la siguiente pasada; el servicio corta a los 300 s
        alert, channel = notice.alert, notice.channel
        reason = _wanted(channel, alert, now)
        if not reason and ChatNotice._base_manager.filter(
                channel=channel, alert__fingerprint=alert.fingerprint, last_attempt_at__gte=now - COOLDOWN,
                status__in=[ChatNotice.Status.ACCEPTED, ChatNotice.Status.DELIVERED, ChatNotice.Status.SENDING,
                            ChatNotice.Status.UNCERTAIN]).exclude(pk=notice.pk).exists():
            reason = 'Agrupado con un aviso de la última hora para no repetir mensajes.'
        if reason:
            expired = reason == 'expired'
            ChatNotice._base_manager.filter(pk=notice.pk, status__in=[ChatNotice.Status.PENDING, ChatNotice.Status.FAILED]).update(
                status=ChatNotice.Status.EXPIRED if expired else ChatNotice.Status.SUPPRESSED,
                last_error='Fuera del plazo de envío inmediato.' if expired else reason, next_retry_at=None)
            continue
        if not ChatNotice._base_manager.filter(pk=notice.pk, status__in=[ChatNotice.Status.PENDING, ChatNotice.Status.FAILED]).update(
                status=ChatNotice.Status.SENDING, attempts=F('attempts') + 1, last_attempt_at=now):
            continue  # otro proceso lo reservó
        notice.refresh_from_db()
        fields = {'last_error': '', 'next_retry_at': None}
        try:
            provider_id = send(channel, alert)
        except ChatConfigurationError as exc:
            fields.update(status=ChatNotice.Status.FAILED, last_error=str(exc)[:250], next_retry_at=now + timedelta(minutes=15))
        except ChatDeliveryError as exc:
            if exc.uncertain:
                fields.update(status=ChatNotice.Status.UNCERTAIN, last_error=str(exc)[:250])
            else:
                wait = timedelta(seconds=exc.retry_after) if exc.retry_after else timedelta(minutes=5 * notice.attempts)
                fields.update(status=ChatNotice.Status.FAILED, last_error=str(exc)[:250], next_retry_at=now + wait)
        else:
            fields.update(status=ChatNotice.Status.ACCEPTED if channel.kind == ChatChannel.Kind.TEAMS else ChatNotice.Status.DELIVERED,
                          sent_at=now, provider_id=provider_id)
            sent += 1
        ChatNotice._base_manager.filter(pk=notice.pk, status=ChatNotice.Status.SENDING).update(**fields)
    return sent


def status(client):
    """Resumen para «Servicios del cliente»."""
    active = [c.get_kind_display() for c in ChatChannel.objects.filter(client=client, enabled=True) if c.configured]
    if not active:
        return ('paused', 'Sin configurar')
    if not client.urgent_alerts_enabled:
        return ('pending', ' y '.join(active) + ' · activa antes los avisos urgentes')
    return ('ok', ' y '.join(active))


# --- Página de configuración -----------------------------------------------------------------

class TeamsForm(forms.Form):
    url = forms.CharField(label='URL del flujo de Teams', required=False, max_length=2048,
                          widget=forms.PasswordInput(attrs={'class': 'input', 'autocomplete': 'off',
                                                            'placeholder': 'https://…logic.azure.com/workflows/…'}))
    label = forms.CharField(label='Canal de Teams', required=False, max_length=120,
                            widget=forms.TextInput(attrs={'class': 'input', 'placeholder': 'Equipo › Canal'}))

    def clean_url(self):
        value = self.cleaned_data['url'].strip()
        if value:
            try:
                validate_teams_url(value)
            except ChatConfigurationError as exc:
                raise forms.ValidationError(str(exc)) from None
        return value


class TelegramForm(forms.Form):
    chat_id = forms.CharField(label='Identificador del grupo', max_length=64,
                              widget=forms.TextInput(attrs={'class': 'input', 'placeholder': '-1001234567890'}))
    label = forms.CharField(label='Nombre del grupo', required=False, max_length=120,
                            widget=forms.TextInput(attrs={'class': 'input'}))

    def clean_chat_id(self):
        try:
            return validate_chat_id(self.cleaned_data['chat_id'])
        except ChatConfigurationError as exc:
            raise forms.ValidationError(str(exc)) from None


def _channel(client, kind):
    return ChatChannel.objects.get_or_create(client=client, kind=kind)[0]


@login_required
@never_cache
def configure(request, pk):
    """Teams y Telegram de un cliente. Cambiar o probar exige permiso sobre clientes y MFA reciente."""
    client = get_object_or_404(Client, pk=pk)
    teams = ChatChannel.objects.filter(client=client, kind=ChatChannel.Kind.TEAMS).first()
    telegram = ChatChannel.objects.filter(client=client, kind=ChatChannel.Kind.TELEGRAM).first()
    teams_form = TeamsForm(initial={'label': teams.label if teams else ''})
    telegram_form = TelegramForm(initial={'chat_id': telegram.chat_id if telegram else '', 'label': telegram.label if telegram else ''})
    chats = None
    if request.method == 'POST':
        if not request.user.has_perm('core.change_client'):
            return HttpResponseForbidden('Tu cuenta no tiene permiso para cambiar los avisos del cliente.')
        action, kind = request.POST.get('action', ''), request.POST.get('kind', '')
        if kind not in ChatChannel.Kind.values:
            return HttpResponseForbidden('Canal no válido.')
        target = redirect('client_chat_channels', pk=client.pk)
        if action == 'disable':
            changed = ChatChannel.objects.filter(client=client, kind=kind, enabled=True).update(enabled=False)
            if changed:
                audit('client.chat', client, {'fields': [kind], 'status': 'disabled'})
            messages.success(request, 'Canal desactivado: no se enviarán más avisos por él.')
            return target
        if action == 'save':
            form = TeamsForm(request.POST) if kind == ChatChannel.Kind.TEAMS else TelegramForm(request.POST)
            if not form.is_valid():
                teams_form, telegram_form = (form, telegram_form) if kind == ChatChannel.Kind.TEAMS else (teams_form, form)
            else:
                channel = _channel(client, kind)
                fields = ['label']
                channel.label = form.cleaned_data['label'].strip()
                if kind == ChatChannel.Kind.TEAMS:
                    if form.cleaned_data['url']:
                        try:
                            channel.encrypted_target = encrypt_target(form.cleaned_data['url'])
                        except ChatConfigurationError as exc:
                            messages.error(request, str(exc))
                            return target
                        fields.append('encrypted_target')
                        channel.last_test_ok = None
                    elif not channel.encrypted_target:
                        messages.error(request, 'Pega la URL del flujo de Teams.')
                        return target
                elif channel.chat_id != form.cleaned_data['chat_id']:
                    channel.chat_id = form.cleaned_data['chat_id']
                    channel.last_test_ok = None
                    fields.append('chat_id')
                retarget = 'encrypted_target' in fields or 'chat_id' in fields
                was_enabled = channel.enabled
                if retarget:
                    channel.enabled = False  # un destino nuevo se prueba y se activa de nuevo
                channel.save()
                audit('client.chat', client, {'fields': [f'{kind}.{f}' for f in fields], 'status': 'saved'})
                messages.success(request, 'Canal guardado. ' + ('El destino cambió y el canal queda desactivado: ' if retarget and was_enabled else '')
                                 + 'Envía un mensaje de prueba y actívalo.')
                return target
        elif action in ('test', 'enable'):
            channel = ChatChannel.objects.filter(client=client, kind=kind).first()
            if not channel or not channel.configured:
                messages.error(request, 'Guarda primero el canal.')
                return target
            if action == 'enable':
                if not channel.last_test_ok:
                    messages.error(request, 'Envía primero un mensaje de prueba y comprueba que ha llegado.')
                    return target
                if not client.urgent_alerts_enabled:
                    messages.error(request, 'Activa antes los avisos urgentes del cliente en «Servicios del cliente».')
                    return target
                channel.enabled, channel.enabled_at = True, timezone.now()
                channel.save(update_fields=['enabled', 'enabled_at', 'updated_at'])
                audit('client.chat', client, {'fields': [kind], 'status': 'enabled'})
                messages.success(request, f'Avisos urgentes activados también por {channel.get_kind_display()}. '
                                          'Solo saldrán los avisos nuevos.')
                return target
            channel.last_test_at = timezone.now()
            try:
                send_test(channel)
            except (ChatConfigurationError, ChatDeliveryError) as exc:
                channel.last_test_ok, channel.last_test_error = False, str(exc)[:250]
                messages.error(request, f'La prueba no ha salido: {exc}')
            else:
                channel.last_test_ok, channel.last_test_error = True, ''
                messages.success(request, 'Mensaje de prueba enviado. Comprueba que ha llegado al chat y activa el canal.')
            channel.save(update_fields=['last_test_at', 'last_test_ok', 'last_test_error', 'updated_at'])
            audit('client.chat', client, {'fields': [kind], 'status': 'test_ok' if channel.last_test_ok else 'test_failed'})
            return target
        elif action == 'find' and kind == ChatChannel.Kind.TELEGRAM:
            from .blocklist import global_access
            if not global_access(request.user):
                return HttpResponseForbidden('Ver los grupos del bot requiere acceso global: muestra los de todos los clientes.')
            try:
                chats = recent_telegram_chats()
            except (ChatConfigurationError, ChatDeliveryError) as exc:
                messages.error(request, str(exc))
                return target
    from .blocklist import global_access
    notices = ChatNotice.objects.filter(channel__client=client).select_related('alert', 'channel')[:20]
    return render(request, 'chat_channels.html', {
        'client': client, 'teams': teams, 'telegram': telegram, 'teams_form': teams_form, 'telegram_form': telegram_form,
        'telegram_ready': telegram_ready(), 'chats': chats, 'notices': notices,
        'can_change': request.user.has_perm('core.change_client'), 'can_find': global_access(request.user),
    })

"""Avisos urgentes por Microsoft Teams y Telegram."""
import io
import json
import time
from datetime import timedelta
from unittest import mock
from urllib import error as url_error

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from . import chat_alerts
from .models import AuditEvent, ChatChannel, ChatNotice, Client, StaffAccess, UrgentAlert

KEY = Fernet.generate_key().decode()
BOT = '123456789:AAbbCCddEEffGGhhIIjjKKllMMnnOOppQQr'
TEAMS_URL = 'https://prod-01.westeurope.logic.azure.com:443/workflows/abc/triggers/manual/paths/invoke?api-version=2016-06-01&sig=SECRETO'


class _Response:
    def __init__(self, status=200, body=b''):
        self.status, self.body = status, body

    def read(self, limit=None):
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def _http_error(code, body=None):
    return url_error.HTTPError('https://api.telegram.org/bot-oculto/sendMessage', code, 'error', {},
                               io.BytesIO(json.dumps(body or {}).encode()))


class _Env:
    """Claves de prueba también durante setUp (el decorador de clase solo cubre los métodos de prueba)."""
    def setUp(self):
        patcher = mock.patch.dict('os.environ', {'SOC_PORTAL_MAIL_KEY': KEY, 'SOC_PORTAL_TELEGRAM_BOT_TOKEN': BOT})
        patcher.start()
        self.addCleanup(patcher.stop)
        super().setUp()


def telegram_ok(message_id=77):
    return _Response(200, json.dumps({'ok': True, 'result': {'message_id': message_id}}).encode())


class ChatDeliveryTests(_Env, TestCase):
    def setUp(self):
        super().setUp()
        self.company = Client.objects.create(name='Empresa A', code='a', urgent_alerts_enabled=True, urgent_email='it@a.test')
        self.now = timezone.now()
        self.telegram = ChatChannel.objects.create(client=self.company, kind='telegram', chat_id='-1001234567890',
                                                   enabled=True, enabled_at=self.now - timedelta(minutes=10))
        self.teams = ChatChannel.objects.create(client=self.company, kind='teams', enabled=True,
                                                enabled_at=self.now - timedelta(minutes=10),
                                                encrypted_target=chat_alerts.encrypt_target(TEAMS_URL))

    def alert(self, uid='u1', fingerprint='f1', **extra):
        values = dict(client=self.company, event_uid=uid, fingerprint=fingerprint, kind='security_allowed',
                      observed_at=self.now - timedelta(minutes=2), source_ip='192.0.2.10', asset_name='SRV-<b>NAS</b>',
                      destination_ip='10.0.0.5', destination_port='443', external_ip='203.0.113.9',
                      signature='ET WEB http://malo.test/[x](http://phish.test)', action='allowed', recipient='it@a.test')
        values.update(extra)
        return UrgentAlert.objects.create(**values)

    def test_each_alert_goes_once_to_each_channel_even_if_the_job_repeats(self):
        self.alert()
        with mock.patch.object(chat_alerts, '_post', side_effect=lambda url, payload, timeout=15:
                               telegram_ok() if 'telegram' in url else _Response(202)) as post:
            self.assertEqual(chat_alerts.deliver_pending(self.now), 2)
            self.assertEqual(chat_alerts.deliver_pending(self.now), 0)
        self.assertEqual(post.call_count, 2)
        statuses = dict(ChatNotice.objects.values_list('channel__kind', 'status'))
        self.assertEqual(statuses, {'teams': 'accepted', 'telegram': 'delivered'})
        self.assertEqual(ChatNotice.objects.get(channel=self.telegram).provider_id, '77')

    def test_content_is_the_alert_with_links_defanged(self):
        alert = self.alert()
        text = chat_alerts.telegram_text(alert)
        self.assertIn('Detección de seguridad no bloqueada', text)
        self.assertIn('Empresa A', text)
        self.assertIn('hxxp://malo.test', text)
        self.assertNotIn('http://', text)
        self.assertNotIn('[x]', text)
        self.assertNotIn('<b>', text)
        card = json.dumps(chat_alerts.teams_payload(alert), ensure_ascii=False)
        self.assertIn('application/vnd.microsoft.card.adaptive', card)
        self.assertNotIn('http://phish', card)

    def test_alerts_before_enabling_expired_or_acknowledged_do_not_go_out(self):
        old = self.alert('old', 'f-old')
        UrgentAlert.objects.filter(pk=old.pk).update(created_at=self.now - timedelta(hours=1))
        self.alert('late', 'f-late', observed_at=self.now - timedelta(hours=3))
        self.alert('seen', 'f-seen', acknowledged_at=self.now)
        with mock.patch.object(chat_alerts, '_post', return_value=telegram_ok()) as post:
            self.assertEqual(chat_alerts.deliver_pending(self.now), 0)
        post.assert_not_called()
        self.assertFalse(ChatNotice.objects.filter(alert=old).exists())
        self.assertFalse(ChatNotice.objects.filter(alert__event_uid='late').exists())
        self.assertEqual(set(ChatNotice.objects.filter(alert__event_uid='seen').values_list('status', flat=True)), {'suppressed'})

    def test_repeated_alerts_are_grouped_for_an_hour(self):
        self.teams.delete()
        self.alert('a', 'same')
        self.alert('b', 'same', observed_at=self.now - timedelta(minutes=1))
        with mock.patch.object(chat_alerts, '_post', return_value=telegram_ok()) as post:
            chat_alerts.deliver_pending(self.now)
        self.assertEqual(post.call_count, 1)
        self.assertEqual(sorted(ChatNotice.objects.values_list('status', flat=True)), ['delivered', 'suppressed'])

    def test_lost_connection_is_uncertain_and_not_retried(self):
        self.teams.delete()
        self.alert()
        with mock.patch.object(chat_alerts, '_post', side_effect=TimeoutError()) as post:
            chat_alerts.deliver_pending(self.now)
            chat_alerts.deliver_pending(self.now + timedelta(minutes=30))
        self.assertEqual(post.call_count, 1)
        notice = ChatNotice.objects.get()
        self.assertEqual(notice.status, 'uncertain')
        self.assertNotIn(BOT, notice.last_error)

    def test_rejection_is_retried_with_its_own_text_and_without_the_token(self):
        self.teams.delete()
        self.alert()
        error = _http_error(400, {'ok': False, 'description': 'Bad Request: chat not found <script>'})
        with mock.patch.object(chat_alerts, '_post', side_effect=error):
            chat_alerts.deliver_pending(self.now)
        notice = ChatNotice.objects.get()
        self.assertEqual(notice.status, 'failed')
        self.assertIn('no encuentra el chat', notice.last_error)
        self.assertNotIn('script', notice.last_error)
        self.assertNotIn(BOT, notice.last_error)
        self.assertIsNotNone(notice.next_retry_at)
        with mock.patch.object(chat_alerts, '_post', return_value=telegram_ok()):
            chat_alerts.deliver_pending(notice.next_retry_at)
        notice.refresh_from_db()
        self.assertEqual((notice.status, notice.attempts), ('delivered', 2))

    def test_telegram_rate_limit_waits_what_it_asks(self):
        self.teams.delete()
        self.alert()
        with mock.patch.object(chat_alerts, '_post', side_effect=_http_error(429, {'parameters': {'retry_after': 30}})):
            chat_alerts.deliver_pending(self.now)
        notice = ChatNotice.objects.get()
        self.assertEqual(notice.next_retry_at, self.now + timedelta(seconds=30))

    def test_teams_server_error_is_uncertain(self):
        self.telegram.delete()
        self.alert()
        with mock.patch.object(chat_alerts, '_post', side_effect=_http_error(502)):
            chat_alerts.deliver_pending(self.now)
        self.assertEqual(ChatNotice.objects.get().status, 'uncertain')

    def test_availability_only_when_the_client_wants_it_and_disabled_channels_stop(self):
        self.alert('down', 'f-down', kind='availability')
        with mock.patch.object(chat_alerts, '_post', return_value=_Response(202)) as post:
            chat_alerts.deliver_pending(self.now)
        post.assert_not_called()
        self.company.urgent_availability_enabled = True
        self.company.save()
        ChatChannel.objects.update(enabled=False)
        with mock.patch.object(chat_alerts, '_post', return_value=_Response(202)) as post:
            chat_alerts.deliver_pending(self.now)
        post.assert_not_called()

    def test_stale_sending_becomes_uncertain(self):
        alert = self.alert()
        notice = ChatNotice.objects.create(alert=alert, channel=self.telegram, status='sending', attempts=1,
                                           last_attempt_at=self.now - timedelta(minutes=10))
        with mock.patch.object(chat_alerts, '_post') as post:
            chat_alerts.deliver_pending(self.now)
        notice.refresh_from_db()
        self.assertEqual(notice.status, 'uncertain')
        self.assertEqual(post.call_count, 1)  # solo Teams, que aún no tenía su envío

    def test_missing_bot_token_fails_without_sending(self):
        self.teams.delete()
        self.alert()
        with mock.patch.dict('os.environ', {'SOC_PORTAL_TELEGRAM_BOT_TOKEN': ''}), \
                mock.patch.object(chat_alerts, '_post') as post:
            chat_alerts.deliver_pending(self.now)
        post.assert_not_called()
        self.assertIn('Falta el bot', ChatNotice.objects.get().last_error)

    def test_recent_chats_lists_groups_only(self):
        body = json.dumps({'ok': True, 'result': [
            {'my_chat_member': {'chat': {'id': -1009, 'title': 'IT Empresa A', 'type': 'supergroup'}}},
            {'message': {'chat': {'id': 55, 'type': 'private', 'first_name': 'Ana'}}}]}).encode()
        with mock.patch.object(chat_alerts, '_post', return_value=_Response(200, body)):
            self.assertEqual(chat_alerts.recent_telegram_chats(), [{'id': -1009, 'title': 'IT Empresa A', 'type': 'Grupo'}])


class ValidationTests(TestCase):
    def test_only_microsoft_flow_urls_over_https(self):
        for good in (TEAMS_URL, 'https://abc.12.environment.api.powerplatform.com/powerautomate/automations/direct/workflows/x',
                     'https://empresa.webhook.office.com/webhookb2/x'):
            self.assertEqual(chat_alerts.validate_teams_url(good), good)
        for bad in ('http://prod-01.westeurope.logic.azure.com/x', 'https://logic.azure.com.evil.test/x',
                    'https://evil.test/?h=.logic.azure.com', 'https://u:p@prod.logic.azure.com/x',
                    'https://prod.logic.azure.com:8443/x', 'https://127.0.0.1/x', TEAMS_URL + ' x', ''):
            with self.assertRaises(chat_alerts.ChatConfigurationError, msg=bad):
                chat_alerts.validate_teams_url(bad)

    def test_chat_ids(self):
        for good in ('-1001234567890', '123456', '@canal_soc'):
            self.assertEqual(chat_alerts.validate_chat_id(good), good)
        for bad in ('abc', '-100 123', '@a', 'https://t.me/x', ''):
            with self.assertRaises(chat_alerts.ChatConfigurationError):
                chat_alerts.validate_chat_id(bad)


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class ChatPageTests(_Env, TestCase):
    def setUp(self):
        super().setUp()
        self.company = Client.objects.create(name='Empresa A', code='a', urgent_alerts_enabled=True, urgent_email='it@a.test')
        self.other = Client.objects.create(name='Empresa B', code='b')
        self.manager = get_user_model().objects.create_user('gestor')
        access = StaffAccess.objects.create(user=self.manager, role='manager')
        access.clients.add(self.company)
        self.manager.user_permissions.add(Permission.objects.get(codename='change_client'))
        self.client.force_login(self.manager)
        self.fresh()
        self.url = reverse('client_chat_channels', args=[self.company.pk])

    def fresh(self):
        session = self.client.session
        session.update({'soc_mfa_user': self.manager.pk, 'soc_mfa_at': time.time()})
        session.save()

    def test_full_flow_save_test_enable_and_url_never_shown(self):
        page = self.client.get(self.url)
        self.assertContains(page, 'Avisos por Teams y Telegram')
        self.client.post(self.url, {'kind': 'teams', 'action': 'save', 'url': TEAMS_URL, 'label': 'IT › Alertas'})
        channel = ChatChannel.objects.get(kind='teams')
        self.assertNotIn('SECRETO', channel.encrypted_target)
        self.assertEqual(chat_alerts.decrypt_target(channel.encrypted_target), TEAMS_URL)
        response = self.client.post(self.url, {'kind': 'teams', 'action': 'enable'}, follow=True)
        self.assertContains(response, 'Envía primero un mensaje de prueba')
        with mock.patch.object(chat_alerts, '_post', return_value=_Response(202)) as post:
            self.client.post(self.url, {'kind': 'teams', 'action': 'test'})
        self.assertIn('Empresa A', json.dumps(post.call_args.args[1], ensure_ascii=False))
        self.client.post(self.url, {'kind': 'teams', 'action': 'enable'})
        channel.refresh_from_db()
        self.assertTrue(channel.enabled and channel.enabled_at)
        page = self.client.get(self.url)
        self.assertNotContains(page, 'SECRETO')
        self.assertNotContains(page, 'workflows/abc')
        events = AuditEvent.objects.filter(action='client.chat')
        self.assertEqual(events.count(), 3)
        self.assertNotIn('SECRETO', json.dumps(list(events.values_list('details', flat=True))))
        services = self.client.get(reverse('client_detail', args=[self.company.pk]))
        self.assertContains(services, 'Avisos urgentes por Teams o Telegram')
        self.assertContains(services, 'Microsoft Teams')

    def test_new_destination_disables_the_channel_until_tested_again(self):
        ChatChannel.objects.create(client=self.company, kind='telegram', chat_id='-1001', enabled=True,
                                   enabled_at=timezone.now(), last_test_ok=True)
        self.client.post(self.url, {'kind': 'telegram', 'action': 'save', 'chat_id': '-1002'})
        channel = ChatChannel.objects.get()
        self.assertEqual((channel.chat_id, channel.enabled, channel.last_test_ok), ('-1002', False, None))

    def test_bad_url_is_rejected(self):
        response = self.client.post(self.url, {'kind': 'teams', 'action': 'save', 'url': 'https://evil.test/x'})
        self.assertContains(response, 'flujo de Microsoft')
        self.assertFalse(ChatChannel.objects.exists())

    def test_changes_need_fresh_mfa_except_disabling(self):
        ChatChannel.objects.create(client=self.company, kind='telegram', chat_id='-1001', enabled=True, enabled_at=timezone.now())
        session = self.client.session
        session['soc_mfa_at'] = 0
        session.save()
        response = self.client.post(self.url, {'kind': 'telegram', 'action': 'save', 'chat_id': '-1002'})
        self.assertRedirects(response, reverse('mfa_challenge'), fetch_redirect_response=False)
        self.client.post(self.url, {'kind': 'telegram', 'action': 'disable'})
        self.assertFalse(ChatChannel.objects.get().enabled)

    def test_scope_permission_and_global_group_search(self):
        self.assertEqual(self.client.get(reverse('client_chat_channels', args=[self.other.pk])).status_code, 404)
        with mock.patch.object(chat_alerts, '_post') as post:
            response = self.client.post(self.url, {'kind': 'telegram', 'action': 'find'})
        self.assertEqual(response.status_code, 403)  # muestra grupos de todos los clientes
        post.assert_not_called()
        self.manager.user_permissions.clear()
        self.manager = get_user_model().objects.get(pk=self.manager.pk)
        response = self.client.post(self.url, {'kind': 'telegram', 'action': 'save', 'chat_id': '-1002'})
        self.assertEqual(response.status_code, 403)

    def test_enable_requires_urgent_alerts(self):
        self.company.urgent_alerts_enabled = False
        self.company.save()
        ChatChannel.objects.create(client=self.company, kind='telegram', chat_id='-1001', last_test_ok=True)
        response = self.client.post(self.url, {'kind': 'telegram', 'action': 'enable'}, follow=True)
        self.assertContains(response, 'Activa antes los avisos urgentes')
        self.assertFalse(ChatChannel.objects.get().enabled)

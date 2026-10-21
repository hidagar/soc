"""CrowdSec CTI (fase 1): privacidad, cupo, errores, análisis y presentación. API simulada."""
import io
import json
from datetime import timedelta
from unittest import mock
from urllib import error as urlerror

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from . import reputation
from .models import (Client, Device, ExportConfiguration, Incident, IpReputation, SecurityEvidence, Site,
                     StaffAccess, WorkerState)
from .reputation import eligible, parse

# IPs públicas (los rangos de documentación no son globales y nunca se consultarían).
ATTACKER, OTHER_ATTACKER, CUSTOMER_PUBLIC = '45.155.205.233', '185.220.101.4', '81.47.12.10'
SAMPLE = {
    'ip': ATTACKER, 'reputation': 'malicious', 'confidence': 'high', 'background_noise': 'high',
    'background_noise_score': 9, 'as_name': 'Ejemplo Hosting', 'location': {'country': 'NL', 'city': 'X'},
    'history': {'first_seen': '2026-01-02T00:00:00', 'last_seen': '2026-10-19T00:00:00'},
    'behaviors': [{'name': 'ssh:bruteforce', 'label': 'SSH Bruteforce', 'description': 'x'}],
    'classifications': {'classifications': [{'name': 'scanner', 'label': 'Escáner'}], 'false_positives': []},
    'scores': {'overall': {'aggressiveness': 4, 'threat': 5, 'trust': 3, 'anomaly': 1, 'total': 4, 'otro': 9}},
    'cves': ['CVE-0000-0000'], 'references': [{'name': 'lista'}],
}


class EligibilityTests(SimpleTestCase):
    def test_only_public_sources_entering_internal_networks_or_customer_ips(self):
        protected = {CUSTOMER_PUBLIC}
        self.assertTrue(eligible(ATTACKER, '10.0.0.5', protected))
        self.assertTrue(eligible(ATTACKER, CUSTOMER_PUBLIC, protected))
        self.assertFalse(eligible('10.0.0.5', ATTACKER, protected), 'conexión saliente: el destino revelaría navegación')
        self.assertFalse(eligible('192.168.1.4', '10.0.0.5', protected), 'IP interna')
        self.assertFalse(eligible(CUSTOMER_PUBLIC, '10.0.0.5', protected), 'IP del propio cliente')
        self.assertFalse(eligible(ATTACKER, OTHER_ATTACKER, protected), 'tráfico entre terceros')
        self.assertFalse(eligible('no-es-ip', '10.0.0.5', protected))
        self.assertFalse(eligible('203.0.113.9', '10.0.0.5', protected), 'rango de documentación: no es público')


class ParseTests(SimpleTestCase):
    def test_keeps_only_displayed_fields_with_bounds(self):
        values = parse(SAMPLE)
        self.assertEqual(values['reputation'], 'malicious')
        self.assertEqual(values['behaviors'], ['SSH Bruteforce'])
        self.assertEqual(values['classifications'], ['Escáner'])
        self.assertEqual(values['scores'], {'aggressiveness': 4, 'threat': 5, 'trust': 3, 'anomaly': 1, 'total': 4})
        self.assertEqual(values['country'], 'NL')
        self.assertNotIn('cves', values)

    def test_unexpected_or_hostile_values_do_not_break_or_overflow(self):
        values = parse({'reputation': 'evil<script>', 'behaviors': 'x', 'as_name': 'A' * 5000,
                        'classifications': [], 'scores': {'overall': {'total': True, 'threat': 10 ** 9}},
                        'background_noise_score': -1, 'history': 'x', 'location': None})
        self.assertEqual(values['reputation'], 'unknown')
        self.assertEqual(values['behaviors'], [])
        self.assertEqual(len(values['as_name']), 200)
        self.assertEqual(values['scores'], {})
        self.assertIsNone(values['background_noise_score'])


class FetchTests(SimpleTestCase):
    def opener(self, response=None, error=None):
        opener = mock.Mock()
        if error:
            opener.open.side_effect = error
        else:
            opener.open.return_value.__enter__ = lambda s: io.BytesIO(response)
            opener.open.return_value.__exit__ = lambda *a: False
        return opener

    def http_error(self, code):
        return urlerror.HTTPError(reputation.API + ATTACKER, code, 'x', {}, io.BytesIO(b''))

    def test_request_uses_the_key_header_and_maps_provider_answers(self):
        opener = self.opener(json.dumps(SAMPLE).encode())
        with mock.patch.object(reputation.urlrequest, 'build_opener', return_value=opener):
            self.assertEqual(reputation.fetch(ATTACKER, 'clave')['reputation'], 'malicious')
        sent = opener.open.call_args.args[0]
        self.assertEqual(sent.full_url, 'https://cti.api.crowdsec.net/v2/smoke/' + ATTACKER)
        self.assertEqual(sent.get_header('X-api-key'), 'clave')
        for code, outcome in ((404, None), (429, reputation.QuotaExceeded), (403, reputation.KeyRejected)):
            with self.subTest(code), mock.patch.object(reputation.urlrequest, 'build_opener',
                                                       return_value=self.opener(error=self.http_error(code))):
                if outcome is None:
                    self.assertIsNone(reputation.fetch(ATTACKER, 'clave'))
                else:
                    with self.assertRaises(outcome):
                        reputation.fetch(ATTACKER, 'clave')

    def test_oversized_answer_is_rejected(self):
        with mock.patch.object(reputation.urlrequest, 'build_opener',
                               return_value=self.opener(b'{' + b' ' * reputation.MAX_RESPONSE + b'}')):
            with self.assertRaises(ValueError):
                reputation.fetch(ATTACKER, 'clave')


class RefreshTests(TestCase):
    def setUp(self):
        self.now = timezone.now()
        company = Client.objects.create(name='Empresa', code='e')
        self.device = Device.objects.create(site=Site.objects.create(client=company, name='S', code='s'),
                                            name='FW', vendor='opnsense')
        ExportConfiguration.objects.create(device=self.device, source_ip=CUSTOMER_PUBLIC)
        for index, (src, dst, action) in enumerate((
                (ATTACKER, '10.0.0.5', 'blocked'), (OTHER_ATTACKER, '10.0.0.6', 'allowed'),
                ('10.0.0.7', '151.101.1.69', 'allowed'), (CUSTOMER_PUBLIC, '10.0.0.8', 'allowed'))):
            SecurityEvidence.objects.create(uid=f'{index:064x}', device=self.device, observed_at=self.now - timedelta(hours=1),
                                            engine='suricata', signature='Firma', source_ip=src, destination_ip=dst,
                                            action=action, level=8, client_scope_id=company.pk)

    def run_refresh(self, fetch=None, env=None, now=None):
        calls = []

        def fake(ip, key):
            calls.append((ip, key))
            return fetch(ip) if fetch else dict(SAMPLE, ip=ip)
        variables = {'SOC_PORTAL_CROWDSEC_KEY': 'clave-secreta', **(env or {})}
        with mock.patch.dict('os.environ', variables), mock.patch.object(reputation, 'fetch', side_effect=fake):
            updated = reputation.refresh(now or self.now)
        return updated, calls

    def test_without_key_nothing_is_sent(self):
        with mock.patch.object(reputation, 'fetch') as fetch, mock.patch.dict('os.environ', {'SOC_PORTAL_CROWDSEC_KEY': ''}):
            self.assertEqual(reputation.refresh(self.now), 0)
        fetch.assert_not_called()
        self.assertFalse(WorkerState.objects.get(name='crowdsec-quota').details['enabled'])

    def test_only_eligible_sources_are_sent_allowed_first_and_cached(self):
        updated, calls = self.run_refresh()
        self.assertEqual([ip for ip, _ in calls], [OTHER_ATTACKER, ATTACKER])
        self.assertEqual(updated, 2)
        row = IpReputation.objects.get(ip=ATTACKER)
        self.assertEqual((row.reputation, row.behaviors), ('malicious', ['SSH Bruteforce']))
        _, again = self.run_refresh()
        self.assertEqual(again, [], 'datos en caché vigentes: no se repite la consulta')
        _, expired = self.run_refresh(now=self.now + reputation.TTL + timedelta(minutes=1))
        self.assertEqual(len(expired), 2, 'dato caducado y evidencia aún reciente: se actualiza')
        _, old = self.run_refresh(now=self.now + timedelta(days=8))
        self.assertEqual(old, [], 'evidencias fuera de la ventana de 7 días: no se consulta')

    def test_daily_limit_is_respected_across_runs_and_resets_next_day(self):
        _, first = self.run_refresh(env={'SOC_PORTAL_CROWDSEC_DAILY_LIMIT': '1'})
        _, second = self.run_refresh(env={'SOC_PORTAL_CROWDSEC_DAILY_LIMIT': '1'})
        self.assertEqual((len(first), len(second)), (1, 0))
        _, next_day = self.run_refresh(env={'SOC_PORTAL_CROWDSEC_DAILY_LIMIT': '1'}, now=self.now + timedelta(days=1))
        self.assertEqual(len(next_day), 1)

    def test_unknown_ip_is_cached_as_without_data(self):
        self.run_refresh(fetch=lambda ip: None)
        self.assertFalse(IpReputation.objects.get(ip=ATTACKER).found)

    def test_quota_or_rejected_key_pauses_and_never_stores_the_key(self):
        for error, text in ((reputation.QuotaExceeded(), 'cupo'), (reputation.KeyRejected(), 'clave')):
            with self.subTest(text):
                WorkerState.objects.filter(name='crowdsec-quota').delete()

                def fail(ip, error=error):
                    raise error
                _, calls = self.run_refresh(fetch=fail)
                self.assertEqual(len(calls), 1)
                state = WorkerState.objects.get(name='crowdsec-quota')
                self.assertIn(text, state.error)
                self.assertNotIn('clave-secreta', json.dumps(state.details) + state.error)
                _, paused = self.run_refresh()
                self.assertEqual(paused, [])

    def test_one_failing_ip_does_not_stop_the_rest_and_reputation_never_creates_incidents(self):
        def flaky(ip):
            if ip == OTHER_ATTACKER:
                raise ValueError('fallo de red')
            return dict(SAMPLE, ip=ip)
        updated, calls = self.run_refresh(fetch=flaky)
        self.assertEqual((updated, len(calls)), (1, 2))
        self.assertFalse(Incident.objects.exists())


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class ReputationPagesTests(TestCase):
    def setUp(self):
        company = Client.objects.create(name='Empresa', code='e')
        device = Device.objects.create(site=Site.objects.create(client=company, name='S', code='s'), name='FW', vendor='opnsense')
        SecurityEvidence.objects.create(uid='a' * 64, device=device, observed_at=timezone.now() - timedelta(hours=1),
                                        engine='suricata', signature='Firma de prueba', source_ip=ATTACKER,
                                        destination_ip='10.0.0.5', action='blocked', level=12, client_scope_id=company.pk)
        IpReputation.objects.create(ip=ATTACKER, expires_at=timezone.now() + timedelta(days=1),
                                    **{k: v for k, v in parse(SAMPLE).items()})
        self.staff = get_user_model().objects.create_superuser('admin', 'a@example.test', 'x')
        self.customer = get_user_model().objects.create_user('cliente')
        StaffAccess.objects.create(user=self.customer, role='customer').clients.add(company)

    def test_soc_sees_reputation_as_context_in_investigation_and_priority_list(self):
        self.client.force_login(self.staff)
        page = self.client.get(reverse('ip_investigation'), {'ip': ATTACKER})
        self.assertContains(page, 'Reputación (CrowdSec)')
        self.assertContains(page, 'Maliciosa')
        self.assertContains(page, 'SSH Bruteforce')
        self.assertContains(page, 'confianza alta')
        self.assertContains(page, 'no confirma que esta IP atacara')
        self.assertContains(self.client.get(reverse('intelligence')), 'CrowdSec: Maliciosa')

    def test_customers_never_reach_reputation_screens(self):
        self.client.force_login(self.customer)
        self.assertEqual(self.client.get(reverse('ip_investigation'), {'ip': ATTACKER}).status_code, 403)
        self.assertNotContains(self.client.get(reverse('customer_home')), 'CrowdSec')

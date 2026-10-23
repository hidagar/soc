"""CrowdSec (fase 1), modos LAPI local y CTI: privacidad, cupo, errores, análisis y presentación. Respuestas simuladas."""
import io
import json
from datetime import timedelta
from unittest import mock
from urllib import error as urlerror

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase, TransactionTestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from . import reputation
from .models import (Client, Device, ExportConfiguration, Incident, IpReputation, SecurityEvidence, Site,
                     StaffAccess, WorkerState)
from .reputation import eligible, parse, parse_lapi

LAPI_ONLY = {**reputation.CTI_EMPTY, 'cti_found': None}


def setUpModule():
    # Sin esperas reales entre consultas CTI en las pruebas; el ritmo se comprueba aparte.
    global _pace
    _pace = mock.patch.object(reputation, 'CTI_PACE', 0)
    _pace.start()


def tearDownModule():
    _pace.stop()

# IPs públicas (los rangos de documentación no son globales y nunca se consultarían).
ATTACKER, OTHER_ATTACKER, CUSTOMER_PUBLIC = '45.155.205.233', '185.220.101.4', '81.47.12.10'
THIRD = '193.32.162.31'
SAMPLE = {
    'ip': ATTACKER, 'reputation': 'malicious', 'confidence': 'high', 'background_noise': 'high',
    'background_noise_score': 9, 'as_name': 'Ejemplo Hosting', 'location': {'country': 'NL', 'city': 'X'},
    'history': {'first_seen': '2026-01-02T00:00:00', 'last_seen': '2026-10-19T00:00:00'},
    'behaviors': [{'name': 'ssh:bruteforce', 'label': 'SSH Bruteforce', 'description': 'x'}],
    'classifications': {'classifications': [{'name': 'scanner', 'label': 'Escáner'}], 'false_positives': []},
    'scores': {'overall': {'aggressiveness': 4, 'threat': 5, 'trust': 3, 'anomaly': 1, 'total': 4, 'otro': 9}},
    'cves': ['CVE-0000-0000'], 'references': [{'name': 'lista'}],
}
# Forma real de GET /v1/decisions?ip= del motor (comprobada con crowdsec 1.6).
DECISIONS = [{'duration': '147h12m3s', 'id': 415, 'origin': 'CAPI', 'scenario': 'crowdsecurity/ssh-bf', 'scope': 'Ip',
              'type': 'ban', 'value': ATTACKER},
             {'duration': '20h', 'id': 9, 'origin': 'lists', 'scenario': 'lista:firehol', 'scope': 'Range',
              'type': 'ban', 'value': '45.155.205.0/24'}]


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
        variables = {'SOC_PORTAL_CROWDSEC_KEY': 'clave-secreta', 'SOC_PORTAL_CROWDSEC_LAPI_KEY': '', **(env or {})}
        with mock.patch.dict('os.environ', variables), mock.patch.object(reputation, 'fetch', side_effect=fake):
            updated = reputation.refresh(now or self.now)
        return updated, calls

    def test_without_key_nothing_is_sent(self):
        with mock.patch.object(reputation, 'fetch') as fetch, mock.patch.dict('os.environ', {'SOC_PORTAL_CROWDSEC_KEY': '', 'SOC_PORTAL_CROWDSEC_LAPI_KEY': ''}):
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
        self.assertIs(IpReputation.objects.get(ip=ATTACKER).cti_found, False)

    def test_quota_or_rejected_key_pauses_and_never_stores_the_key(self):
        for error, text in ((reputation.QuotaExceeded(), '429'), (reputation.KeyRejected(), 'clave')):
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


class ProtectedNetworkTests(TestCase):
    def test_client_exceptions_and_management_addresses_are_never_sent(self):
        from .models import BlocklistFeed
        company = Client.objects.create(name='Empresa', code='e')
        site = Site.objects.create(client=company, name='S', code='s')
        Device.objects.create(site=site, name='FW', vendor='opnsense', management_address='81.47.12.10')
        BlocklistFeed.objects.create(client=company, allowlist='193.32.162.0/24  # oficina remota')
        protected = reputation.protected_addresses()
        self.assertIn('81.47.12.10', protected)
        self.assertIn('193.32.162.31', protected)
        self.assertFalse(eligible('193.32.162.31', '10.0.0.5', protected))
        self.assertTrue(eligible(ATTACKER, '10.0.0.5', protected))


class LapiTests(TestCase):
    """Modo gratuito: decisiones del motor local (lista comunitaria y listas de la consola)."""
    def setUp(self):
        RefreshTests.setUp(self)

    def opener(self, response=None, error=None):
        opener = mock.Mock()
        if error:
            opener.open.side_effect = error
        else:
            opener.open.return_value.__enter__ = lambda s: io.BytesIO(response)
            opener.open.return_value.__exit__ = lambda *a: False
        return opener

    def test_request_goes_to_the_local_engine_with_the_bouncer_key(self):
        opener = self.opener(json.dumps(DECISIONS).encode())
        with mock.patch.object(reputation.urlrequest, 'build_opener', return_value=opener):
            self.assertEqual(reputation.fetch_lapi(ATTACKER, 'clave-bouncer', 'http://127.0.0.1:8080'), DECISIONS)
        request = opener.open.call_args[0][0]
        self.assertEqual(request.full_url, f'http://127.0.0.1:8080/v1/decisions?ip={ATTACKER}')
        self.assertEqual(request.get_header('X-api-key'), 'clave-bouncer')

    def test_engine_answers_are_mapped(self):
        for body, expected in ((b'null', []), (b'[]', [])):
            with mock.patch.object(reputation.urlrequest, 'build_opener', return_value=self.opener(body)):
                self.assertEqual(reputation.fetch_lapi(ATTACKER, 'k', 'http://127.0.0.1:8080'), expected)
        forbidden = urlerror.HTTPError('u', 403, 'access forbidden', {}, io.BytesIO(b'{"message":"access forbidden"}'))
        for error, exception in ((forbidden, reputation.KeyRejected),
                                 (urlerror.URLError(ConnectionRefusedError()), reputation.EngineUnavailable)):
            with self.subTest(exception), self.assertRaises(exception), \
                    mock.patch.object(reputation.urlrequest, 'build_opener', return_value=self.opener(error=error)):
                reputation.fetch_lapi(ATTACKER, 'k', 'http://127.0.0.1:8080')
        with self.assertRaises(ValueError), \
                mock.patch.object(reputation.urlrequest, 'build_opener', return_value=self.opener(b'{"a": 1}')):
            reputation.fetch_lapi(ATTACKER, 'k', 'http://127.0.0.1:8080')

    def test_key_never_travels_in_clear_outside_the_host(self):
        for url, ok in (('', True), ('http://127.0.0.1:8080', True), ('http://localhost:8080/', True),
                        ('https://crowdsec.interno:8080', True), ('http://10.0.0.9:8080', False),
                        ('http://crowdsec.interno:8080', False), ('ftp://127.0.0.1', False),
                        ('http://u:p@127.0.0.1:8080', False), ('http://127.0.0.1:8080/?x=1', False)):
            with self.subTest(url), mock.patch.dict('os.environ', {'SOC_PORTAL_CROWDSEC_LAPI_URL': url}):
                if ok:
                    self.assertTrue(reputation.lapi_url().startswith('http'))
                else:
                    with self.assertRaises(ValueError):
                        reputation.lapi_url()

    def test_decisions_are_summarised_without_extra_fields(self):
        values = parse_lapi(DECISIONS)
        self.assertEqual(values, {'listed': True,
                                  'list_scenarios': ['crowdsecurity/ssh-bf', 'lista:firehol'],
                                  'list_origins': ['Lista comunitaria', 'Lista de la consola'],
                                  'listed_range': '45.155.205.0/24'})
        self.assertEqual(parse_lapi([]), {'listed': False, 'list_origins': [], 'list_scenarios': [], 'listed_range': ''})
        hostile = parse_lapi([{'origin': ['x'], 'scenario': 'x' * 999, 'scope': 'Range', 'value': 'no-es-red'}, 'basura'])
        self.assertEqual((hostile['list_origins'], len(hostile['list_scenarios'][0]), hostile['listed_range']),
                         (['Otra fuente'], 120, ''))

    def run_lapi(self, fetch=None, env=None, now=None):
        calls = []

        def fake(ip, key, base):
            calls.append((ip, key, base))
            return fetch(ip) if fetch else (DECISIONS if ip == ATTACKER else [])
        variables = {'SOC_PORTAL_CROWDSEC_LAPI_KEY': 'clave-bouncer', 'SOC_PORTAL_CROWDSEC_KEY': '',
                     'SOC_PORTAL_CROWDSEC_LAPI_URL': '', **(env or {})}
        with mock.patch.dict('os.environ', variables), mock.patch.object(reputation, 'fetch_lapi', side_effect=fake), \
                mock.patch.object(reputation, 'fetch') as cti, \
                mock.patch.object(reputation, 'summarize_lists', side_effect=lambda key, base, now: {'at': now.isoformat()}):
            updated = reputation.refresh(now or self.now)
        cti.assert_not_called()
        return updated, calls

    def test_local_engine_is_preferred_without_daily_quota_and_with_short_cache(self):
        updated, calls = self.run_lapi(env={'SOC_PORTAL_CROWDSEC_DAILY_LIMIT': '0'})
        self.assertEqual([ip for ip, *_ in calls], [OTHER_ATTACKER, ATTACKER], 'mismo filtro de privacidad y orden')
        self.assertEqual({(key, base) for _, key, base in calls}, {('clave-bouncer', 'http://127.0.0.1:8080')})
        self.assertEqual(updated, 2)
        listed, absent = IpReputation.objects.get(ip=ATTACKER), IpReputation.objects.get(ip=OTHER_ATTACKER)
        self.assertEqual((listed.listed, listed.cti_found, listed.list_origins[0]), (True, None, 'Lista comunitaria'))
        self.assertEqual((absent.listed, absent.cti_found), (False, None))
        self.assertEqual(listed.lists_expires_at, self.now + reputation.LAPI_TTL)
        self.assertEqual(self.run_lapi()[1], [])
        self.assertEqual(len(self.run_lapi(now=self.now + reputation.LAPI_TTL + timedelta(minutes=1))[1]), 2)
        self.assertEqual(WorkerState.objects.get(name='crowdsec-quota').details['mode'], 'lapi')

    def test_lists_are_counted_in_bounded_chunks_including_split_entries(self):
        decisions = [dict(DECISIONS[0], id=n, scenario='crowdsecurity/ssh-bf' if n % 3 else 'http:scan')
                     for n in range(3000)]
        body = json.dumps(decisions).encode()
        response = io.BytesIO(body)
        opener = self.opener()
        opener.open.return_value.__enter__ = lambda s: response
        reads = []
        original = response.read
        response.read = lambda size: reads.append(size) or original(min(size, 7777))  # cortes arbitrarios
        with mock.patch.object(reputation.urlrequest, 'build_opener', return_value=opener):
            summary = reputation.count_decisions('k', 'http://127.0.0.1:8080', 'CAPI')
        self.assertEqual(summary, {'count': 3000, 'top': [('crowdsecurity/ssh-bf', 2000), ('http:scan', 1000)]})
        self.assertIn('origins=CAPI', opener.open.call_args[0][0].full_url)
        self.assertTrue(all(size <= 256 * 1024 for size in reads))
        with mock.patch.object(reputation.urlrequest, 'build_opener', return_value=self.opener(b'null')):
            self.assertEqual(reputation.count_decisions('k', 'http://127.0.0.1:8080', 'lists'), {'count': 0, 'top': []})
        with mock.patch.object(reputation, 'LISTS_MAX_BYTES', 100), self.assertRaises(ValueError), \
                mock.patch.object(reputation.urlrequest, 'build_opener', return_value=self.opener(body)):
            reputation.count_decisions('k', 'http://127.0.0.1:8080', 'CAPI')

    def test_list_summary_runs_hourly_and_one_failing_origin_does_not_stop_it(self):
        def count(key, base, origin):
            if origin == 'lists':
                raise ValueError('demasiado grande')
            return {'count': 5, 'top': [('x', 5)]}
        variables = {'SOC_PORTAL_CROWDSEC_LAPI_KEY': 'clave-bouncer', 'SOC_PORTAL_CROWDSEC_LAPI_URL': ''}
        with mock.patch.dict('os.environ', variables), mock.patch.object(reputation, 'fetch_lapi', return_value=[]), \
                mock.patch.object(reputation, 'count_decisions', side_effect=count) as counted:
            reputation.refresh(self.now)
            reputation.refresh(self.now + timedelta(minutes=30))
            self.assertEqual(counted.call_count, len(reputation.ORIGINS), 'una vez por hora')
            reputation.refresh(self.now + timedelta(minutes=61))
            self.assertEqual(counted.call_count, 2 * len(reputation.ORIGINS))
        lists = WorkerState.objects.get(name='crowdsec-quota').details['lists']['origins']
        self.assertEqual((lists['CAPI']['count'], lists['lists']), (5, {'error': True}))

    def test_engine_down_is_reported_and_retried_next_run(self):
        def down(ip):
            raise reputation.EngineUnavailable()
        _, calls = self.run_lapi(fetch=down)
        self.assertEqual(len(calls), 1)
        state = WorkerState.objects.get(name='crowdsec-quota')
        self.assertIn('motor CrowdSec local', state.error)
        self.assertNotIn('paused_until', state.details)
        self.assertEqual(len(self.run_lapi()[1]), 2)
        self.assertEqual(WorkerState.objects.get(name='crowdsec-quota').error, '')

    def test_rejected_key_or_bad_url_never_exposes_the_key(self):
        def rejected(ip):
            raise reputation.KeyRejected()
        self.run_lapi(fetch=rejected)
        state = WorkerState.objects.get(name='crowdsec-quota')
        self.assertIn('SOC_PORTAL_CROWDSEC_LAPI_KEY', state.error)
        self.assertEqual(self.run_lapi()[1], [], 'en pausa')
        WorkerState.objects.filter(name='crowdsec-quota').delete()
        _, calls = self.run_lapi(env={'SOC_PORTAL_CROWDSEC_LAPI_URL': 'http://10.0.0.9:8080'})
        self.assertEqual(calls, [])
        state = WorkerState.objects.get(name='crowdsec-quota')
        self.assertIn('HTTPS', state.error)
        self.assertNotIn('clave-bouncer', json.dumps(state.details) + state.error)


class CombinedModeTests(TestCase):
    """Con las dos claves: listas para todo y API CTI de pago para lo prioritario, dentro del cupo."""
    def setUp(self):
        RefreshTests.setUp(self)
        evidence = SecurityEvidence.objects.get(source_ip=ATTACKER)
        SecurityEvidence.objects.create(uid='9' * 64, device=evidence.device, observed_at=evidence.observed_at,
                                        engine='suricata', signature='Firma', source_ip=THIRD, destination_ip='10.0.0.9',
                                        action='blocked', level=12, client_scope_id=evidence.client_scope_id)

    def refresh(self, env=None, now=None, lists=None, cti=None):
        calls = {'lists': [], 'cti': []}

        def fake_lists(ip, key, base):
            calls['lists'].append(ip)
            return lists(ip) if lists else (DECISIONS[:1] if ip == ATTACKER else [])

        def fake_cti(ip, key):
            calls['cti'].append((ip, key))
            return cti(ip) if cti else dict(SAMPLE, ip=ip)
        variables = {'SOC_PORTAL_CROWDSEC_LAPI_KEY': 'clave-bouncer', 'SOC_PORTAL_CROWDSEC_KEY': 'clave-cti',
                     'SOC_PORTAL_CROWDSEC_LAPI_URL': '', 'SOC_PORTAL_CROWDSEC_DAILY_LIMIT': '2',
                     'SOC_PORTAL_CROWDSEC_MONTHLY_LIMIT': '', **(env or {})}
        with mock.patch.dict('os.environ', variables), mock.patch.object(reputation, 'fetch_lapi', side_effect=fake_lists), \
                mock.patch.object(reputation, 'fetch', side_effect=fake_cti), \
                mock.patch.object(reputation, 'summarize_lists', side_effect=lambda key, base, now: {'at': now.isoformat()}):
            reputation.refresh(now or self.now)
        return calls

    def test_lists_cover_everything_and_cti_goes_to_allowed_then_listed_first(self):
        calls = self.refresh()
        self.assertEqual(sorted(calls['lists']), sorted([ATTACKER, OTHER_ATTACKER, THIRD]))
        # Cupo de 2: primero el permitido, después el que ya figura en una lista, aunque el otro tenga más nivel.
        self.assertEqual([ip for ip, _ in calls['cti']], [OTHER_ATTACKER, ATTACKER])
        self.assertEqual({key for _, key in calls['cti']}, {'clave-cti'})
        row = IpReputation.objects.get(ip=ATTACKER)
        self.assertEqual((row.listed, row.cti_found, row.reputation, row.list_origins), (True, True, 'malicious', ['Lista comunitaria']))
        self.assertIs(IpReputation.objects.get(ip=THIRD).cti_found, None)
        state = WorkerState.objects.get(name='crowdsec-quota')
        self.assertEqual((state.details['mode'], state.details['used'], state.error), ('lapi+cti', 2, ''))

    def test_each_source_keeps_its_own_data_and_expiry(self):
        self.refresh()
        later = self.now + reputation.LAPI_TTL + timedelta(minutes=1)
        calls = self.refresh(now=later, lists=lambda ip: [], env={'SOC_PORTAL_CROWDSEC_DAILY_LIMIT': '10'})
        self.assertEqual([ip for ip, _ in calls['cti']], [THIRD], 'la CTI sigue vigente 3 días; solo queda la pendiente')
        row = IpReputation.objects.get(ip=ATTACKER)
        self.assertEqual((row.listed, row.cti_found, row.reputation), (False, True, 'malicious'))
        self.assertEqual(row.lists_checked_at, later)
        self.assertEqual(row.cti_checked_at, self.now)

    def test_monthly_quota_is_respected_across_days(self):
        env = {'SOC_PORTAL_CROWDSEC_DAILY_LIMIT': '10', 'SOC_PORTAL_CROWDSEC_MONTHLY_LIMIT': '2'}
        self.assertEqual(len(self.refresh(env=env)['cti']), 2)
        tomorrow = self.now + timedelta(days=1)
        same_month = tomorrow.strftime('%Y-%m') == self.now.strftime('%Y-%m')
        self.assertEqual(len(self.refresh(env=env, now=tomorrow)['cti']), 0 if same_month else 1)

    def test_cti_calls_are_paced_and_429_backs_off_progressively(self):
        with mock.patch.object(reputation.time, 'sleep') as sleep:
            calls = self.refresh()
        self.assertEqual(len(calls['cti']), 2)
        self.assertEqual(sleep.call_count, 1, 'una pausa entre dos consultas, ninguna antes de la primera')

        def limited(ip):
            raise reputation.QuotaExceeded()
        waits = []
        moment = self.now
        IpReputation.objects.update(cti_expires_at=None)
        for _ in range(4):
            WorkerState.objects.filter(name='crowdsec-quota').update(details={})  # día nuevo: cupo libre
            state = WorkerState.objects.get_or_create(name='crowdsec-quota')[0]
            state.details = {'cti_limited': len(waits)}
            state.save()
            self.refresh(now=moment, cti=limited, env={'SOC_PORTAL_CROWDSEC_DAILY_LIMIT': '10'})
            paused = WorkerState.objects.get(name='crowdsec-quota').details['paused_until']
            waits.append(round((timezone.datetime.fromisoformat(paused) - moment).total_seconds() / 60))
        self.assertEqual(waits, [15, 60, 360, 360])

        def told(ip):
            raise reputation.QuotaExceeded(retry_after=120)
        WorkerState.objects.all().delete()
        self.refresh(cti=told)
        paused = WorkerState.objects.get(name='crowdsec-quota').details['paused_until']
        self.assertEqual(timezone.datetime.fromisoformat(paused) - self.now, timedelta(seconds=120))

    def test_each_run_sends_a_small_batch_so_the_daily_quota_spreads_over_the_day(self):
        env = {'SOC_PORTAL_CROWDSEC_DAILY_LIMIT': '48', 'SOC_PORTAL_CROWDSEC_CTI_PER_RUN': '1'}
        first = self.refresh(env=env)['cti']
        second = self.refresh(env=env, now=self.now + timedelta(minutes=15))['cti']
        self.assertEqual(([ip for ip, _ in first], [ip for ip, _ in second]), ([OTHER_ATTACKER], [ATTACKER]))
        self.assertEqual(len(self.refresh(env={'SOC_PORTAL_CROWDSEC_DAILY_LIMIT': '48'},
                                          now=self.now + timedelta(minutes=30))['cti']), 1, 'solo queda THIRD')
        with mock.patch.dict('os.environ', {'SOC_PORTAL_CROWDSEC_CTI_PER_RUN': 'x'}):
            self.assertEqual(reputation.cti_per_run(), 2)

    def test_counters_survive_a_job_killed_mid_batch_and_failing_ips_do_not_burn_quota(self):
        def killed(ip):
            raise KeyboardInterrupt  # corte del proceso: no lo atrapa ningún «except Exception»
        with self.assertRaises(KeyboardInterrupt):
            self.refresh(cti=killed)
        state = WorkerState.objects.get(name='crowdsec-quota')
        self.assertEqual((state.details['used'], state.details['month_used']), (1, 1), 'guardado antes de llamar')

        def broken(ip):
            raise ValueError('respuesta no válida')
        WorkerState.objects.all().delete()
        first = self.refresh(cti=broken, env={'SOC_PORTAL_CROWDSEC_DAILY_LIMIT': '48'})['cti']
        again = self.refresh(cti=broken, env={'SOC_PORTAL_CROWDSEC_DAILY_LIMIT': '48'},
                             now=self.now + timedelta(minutes=15))['cti']
        self.assertEqual(len(first), 2)
        self.assertEqual([ip for ip, _ in again], [THIRD], 'las que fallaron esperan un día')

    def test_paused_sources_are_reported_not_shown_as_working(self):
        self.refresh(lists=lambda ip: (_ for _ in ()).throw(reputation.KeyRejected()))
        later = self.refresh(now=self.now + timedelta(minutes=15))
        self.assertEqual(later['lists'], [])
        self.assertIn('en pausa', WorkerState.objects.get(name='crowdsec-quota').error)

    def test_batch_fits_the_job_time_limit(self):
        with mock.patch.object(reputation, 'CTI_PACE', 15), \
                mock.patch.dict('os.environ', {'SOC_PORTAL_CROWDSEC_CTI_PER_RUN': '20'}):
            self.assertEqual(reputation.cti_per_run(), 8)

    def test_retry_after_header_is_read(self):
        error = urlerror.HTTPError('u', 429, 'Too Many Requests', {'Retry-After': '30'}, io.BytesIO(b'{}'))
        opener = mock.Mock()
        opener.open.side_effect = error
        with mock.patch.object(reputation.urlrequest, 'build_opener', return_value=opener), \
                self.assertRaises(reputation.QuotaExceeded) as caught:
            reputation.fetch(ATTACKER, 'k')
        self.assertEqual(caught.exception.retry_after, 30)

    def test_cti_quota_or_key_problem_does_not_stop_lists_and_vice_versa(self):
        def no_quota(ip):
            raise reputation.QuotaExceeded()
        calls = self.refresh(cti=no_quota)
        self.assertEqual(len(calls['lists']), 3)
        state = WorkerState.objects.get(name='crowdsec-quota')
        self.assertIn('limitó las consultas CTI', state.error)
        self.assertIn('paused_until', state.details)
        self.assertNotIn('clave-cti', state.error + json.dumps(state.details))
        WorkerState.objects.all().delete()
        IpReputation.objects.all().delete()

        def engine_down(ip):
            raise reputation.EngineUnavailable()
        calls = self.refresh(lists=engine_down)
        self.assertEqual(len(calls['cti']), 2)
        self.assertIn('motor CrowdSec local', WorkerState.objects.get(name='crowdsec-quota').error)


class ReputationMigrationTests(TransactionTestCase):
    """0052 reparte las filas existentes (modo lapi o cti) en los campos de cada fuente, y vuelve atrás."""
    def test_existing_rows_are_split_by_source(self):
        from django.db import connection
        from django.db.migrations.executor import MigrationExecutor
        executor = MigrationExecutor(connection)
        executor.migrate([('core', '0051_customer_portal_detail')])
        old = executor.loader.project_state([('core', '0051_customer_portal_detail')]).apps.get_model('core', 'IpReputation')
        now = timezone.now()
        old.objects.create(ip=ATTACKER, source='lapi', found=True, reputation='listed', behaviors=['http:scan'],
                           classifications=['Lista comunitaria'], fetched_at=now, expires_at=now + timedelta(hours=6))
        old.objects.create(ip=OTHER_ATTACKER, source='cti', found=True, reputation='malicious', behaviors=['SSH'],
                           fetched_at=now, expires_at=now + timedelta(days=3))
        executor = MigrationExecutor(connection)
        executor.migrate([('core', '0052_ip_reputation_sources')])
        split = executor.loader.project_state([('core', '0052_ip_reputation_sources')]).apps.get_model('core', 'IpReputation')
        listed, cti = split.objects.get(ip=ATTACKER), split.objects.get(ip=OTHER_ATTACKER)
        self.assertEqual((listed.listed, listed.list_scenarios, listed.list_origins, listed.cti_found, listed.reputation),
                         (True, ['http:scan'], ['Lista comunitaria'], None, ''))
        self.assertEqual(listed.lists_expires_at, now + timedelta(hours=6))
        self.assertEqual((cti.cti_found, cti.reputation, cti.behaviors, cti.listed), (True, 'malicious', ['SSH'], None))
        executor = MigrationExecutor(connection)
        executor.migrate([('core', '0051_customer_portal_detail')])
        back = executor.loader.project_state([('core', '0051_customer_portal_detail')]).apps.get_model('core', 'IpReputation')
        self.assertEqual(back.objects.get(ip=ATTACKER).source, 'lapi')
        self.assertEqual(back.objects.get(ip=OTHER_ATTACKER).reputation, 'malicious')
        executor = MigrationExecutor(connection)
        executor.migrate(executor.loader.graph.leaf_nodes())


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class ReputationPagesTests(TestCase):
    def setUp(self):
        company = Client.objects.create(name='Empresa', code='e')
        device = Device.objects.create(site=Site.objects.create(client=company, name='S', code='s'), name='FW', vendor='opnsense')
        SecurityEvidence.objects.create(uid='a' * 64, device=device, observed_at=timezone.now() - timedelta(hours=1),
                                        engine='suricata', signature='Firma de prueba', source_ip=ATTACKER,
                                        destination_ip='10.0.0.5', action='blocked', level=12, client_scope_id=company.pk)
        IpReputation.objects.create(ip=ATTACKER, cti_expires_at=timezone.now() + timedelta(days=1),
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

    def test_local_engine_lists_are_explained_without_claiming_benign(self):
        IpReputation.objects.filter(ip=ATTACKER).update(**parse_lapi(DECISIONS), **LAPI_ONLY)
        IpReputation.objects.create(ip=OTHER_ATTACKER, lists_expires_at=timezone.now() + timedelta(hours=1),
                                    **parse_lapi([]))
        evidence = SecurityEvidence.objects.get()
        evidence.pk, evidence.uid, evidence.source_ip = None, 'b' * 64, OTHER_ATTACKER
        evidence.save()
        self.client.force_login(self.staff)
        page = self.client.get(reverse('ip_investigation'), {'ip': ATTACKER})
        self.assertContains(page, 'En lista de bloqueo')
        self.assertContains(page, 'Lista comunitaria, Lista de la consola')
        self.assertContains(page, 'por el rango 45.155.205.0/24')
        absent = self.client.get(reverse('ip_investigation'), {'ip': OTHER_ATTACKER})
        self.assertContains(absent, 'No figurar no significa que sea benigna')
        self.assertContains(self.client.get(reverse('intelligence')), 'CrowdSec: En lista de bloqueo')

    def test_crowdsec_page_shows_engine_state_and_only_listed_sources_in_scope(self):
        other = Client.objects.create(name='Otra empresa', code='o')
        other_device = Device.objects.create(site=Site.objects.create(client=other, name='S2', code='s2'),
                                             name='FW2', vendor='opnsense')
        SecurityEvidence.objects.create(uid='e' * 64, device=other_device, observed_at=timezone.now() - timedelta(hours=2),
                                        engine='suricata', signature='Otra', source_ip=OTHER_ATTACKER,
                                        destination_ip='10.1.0.5', action='allowed', level=3, client_scope_id=other.pk)
        evidence = SecurityEvidence.objects.get(uid='a' * 64)
        SecurityEvidence.objects.create(uid='f' * 64, device=evidence.device, observed_at=evidence.observed_at,
                                        engine='suricata', signature='Permitida', source_ip=ATTACKER,
                                        destination_ip='10.0.0.5', action='allowed', level=3,
                                        client_scope_id=evidence.client_scope_id)
        IpReputation.objects.filter(ip=ATTACKER).update(**parse_lapi(DECISIONS), **LAPI_ONLY)
        IpReputation.objects.create(ip=OTHER_ATTACKER, lists_expires_at=timezone.now() + timedelta(hours=1),
                                    **parse_lapi(DECISIONS[:1]))
        WorkerState.objects.create(name='crowdsec-quota', details={
            'enabled': True, 'mode': 'lapi', 'lists': {'at': timezone.now().isoformat(), 'origins': {
                'CAPI': {'count': 15000, 'top': [['crowdsecurity/ssh-bf', 9000]]}, 'lists': {'error': True}}}})
        url = reverse('crowdsec_overview')
        self.client.force_login(self.staff)
        page = self.client.get(url)
        self.assertContains(page, 'Motor local (gratuito)')
        self.assertContains(page, '15000')
        self.assertContains(page, 'No se pudo contar')
        self.assertContains(page, ATTACKER)
        self.assertContains(page, OTHER_ATTACKER)
        self.assertContains(page, '1 permitida')
        self.assertContains(page, 'Rango 45.155.205.0/24')
        # Operador limitado a la primera empresa: no ve IPs ni nombres de otros clientes.
        operator = get_user_model().objects.create_user('operador')
        StaffAccess.objects.create(user=operator, role='operator').clients.add(evidence.client_scope_id)
        self.client.force_login(operator)
        scoped = self.client.get(url)
        self.assertContains(scoped, ATTACKER)
        self.assertNotContains(scoped, OTHER_ATTACKER)
        self.assertNotContains(scoped, 'Otra empresa')
        self.assertEqual(self.client.get(url, {'client': 'x'}).status_code, 404)
        self.client.force_login(self.customer)
        self.assertNotEqual(self.client.get(url).status_code, 200)

    def test_both_sources_are_shown_and_noise_can_be_hidden(self):
        IpReputation.objects.filter(ip=ATTACKER).update(**parse_lapi(DECISIONS[:1]))
        evidence = SecurityEvidence.objects.get()
        SecurityEvidence.objects.create(uid='c' * 64, device=evidence.device, observed_at=evidence.observed_at,
                                        engine='suricata', signature='Firma sin ruido', source_ip=OTHER_ATTACKER,
                                        destination_ip='10.0.0.5', action='blocked', level=3,
                                        client_scope_id=evidence.client_scope_id)
        IpReputation.objects.create(ip=OTHER_ATTACKER, cti_expires_at=timezone.now() + timedelta(days=1),
                                    **parse(dict(SAMPLE, background_noise='low')))
        WorkerState.objects.create(name='crowdsec-quota', details={'enabled': True, 'mode': 'lapi+cti', 'used': 7,
                                                                    'month_used': 120})
        self.client.force_login(self.staff)
        page = self.client.get(reverse('ip_investigation'), {'ip': ATTACKER})
        self.assertContains(page, 'En lista de bloqueo (Lista comunitaria)')
        self.assertContains(page, 'Reputación detallada (API CTI):</strong> Maliciosa')
        url = reverse('intelligence')
        self.assertContains(self.client.get(url), 'CrowdSec: Maliciosa · en lista · ruido')
        quiet = self.client.get(url, {'reputacion': 'sin_ruido'})
        self.assertContains(quiet, 'Firma sin ruido')
        self.assertNotContains(quiet, 'Firma de prueba')
        with mock.patch.dict('os.environ', {'SOC_PORTAL_CROWDSEC_DAILY_LIMIT': '160', 'SOC_PORTAL_CROWDSEC_MONTHLY_LIMIT': '5000'}):
            overview = self.client.get(reverse('crowdsec_overview'))
        self.assertContains(overview, 'Motor local + API CTI')
        self.assertContains(overview, '7 de 160 consultas hoy · 120 de 5000 este mes')

    def test_crowdsec_page_without_configuration_explains_how_to_enable(self):
        self.client.force_login(self.staff)
        page = self.client.get(reverse('crowdsec_overview'))
        self.assertContains(page, 'CrowdSec no está configurado')
        self.assertContains(page, 'Sin configurar')

    def test_priority_list_highlights_and_filters_allowed_traffic_from_listed_sources(self):
        evidence = SecurityEvidence.objects.get()
        IpReputation.objects.filter(ip=ATTACKER).update(**parse_lapi(DECISIONS), **LAPI_ONLY)
        for uid, source, action, signature in (('b', ATTACKER, 'allowed', 'Firma permitida'),
                                               ('c', OTHER_ATTACKER, 'allowed', 'Firma sin lista'),
                                               ('d', '203.0.113.50', 'allowed', 'Firma sin consultar')):
            SecurityEvidence.objects.create(uid=uid * 64, device=evidence.device, observed_at=evidence.observed_at,
                                            engine='suricata', signature=signature, source_ip=source,
                                            destination_ip='10.0.0.5', action=action, level=3,
                                            client_scope_id=evidence.client_scope_id)
        IpReputation.objects.create(ip=OTHER_ATTACKER, lists_expires_at=timezone.now() + timedelta(hours=1),
                                    **parse_lapi([]))
        self.client.force_login(self.staff)
        url = reverse('intelligence')
        everything = self.client.get(url)
        self.assertContains(everything, '1 grupo de tráfico permitido desde IPs en listas')
        self.assertContains(everything, 'Permitida desde IP en lista', count=1)
        for signature in ('Firma de prueba', 'Firma permitida', 'Firma sin lista', 'Firma sin consultar'):
            self.assertContains(everything, signature)
        listed = self.client.get(url, {'reputacion': 'lista'})
        self.assertContains(listed, 'Firma de prueba')
        self.assertContains(listed, 'Firma permitida')
        self.assertNotContains(listed, 'Firma sin lista')
        self.assertNotContains(listed, 'Firma sin consultar')
        allowed = self.client.get(url, {'reputacion': 'permitida'})
        self.assertContains(allowed, 'Firma permitida')
        self.assertNotContains(allowed, 'Firma de prueba')
        self.assertEqual(self.client.get(url, {'reputacion': 'otra'}).status_code, 404)
        # Solo contexto: la prioridad y los motivos no dependen de la reputación.
        from .service_development import intelligence_rows
        before = [(r['signature'], r['priority'], r['reasons']) for r in intelligence_rows()[0]]
        IpReputation.objects.all().delete()
        self.assertEqual(before, [(r['signature'], r['priority'], r['reasons']) for r in intelligence_rows()[0]])
        self.assertFalse(Incident.objects.exists())

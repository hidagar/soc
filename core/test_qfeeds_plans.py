"""Q-Feeds, planes B y C y consulta de contexto: licencias por firewall, lista de bloqueo y IOC Lookup."""
import io
import json
import os
import time
from datetime import date, timedelta
from unittest import mock
from urllib import error as urlerror

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from . import qfeeds_devices, threat_intel
from .blocklist import refresh_feeds, servable
from .models import (BlocklistFeed, ChangePlan, OperationalIssue, OpnsenseConnection, QFeedsLicense, StaffAccess,
                     ThreatIntelLookup, ThreatIntelReview)
from .security import decrypt
from . import test_threat_intel as base
from .test_threat_intel import ATTACKER, C2, KEY, OTHER_C2, FakeApi

CUSTOMER_KEY = 'qf-customer-key-0123456789'
OEM = {'SOC_PORTAL_QFEEDS_OEM': 'OEM-2026-01'}


def login(test, *perms, all_clients=True):
    user = get_user_model().objects.create_user('analista')
    access = StaffAccess.objects.create(user=user, role='operator', all_clients=all_clients)
    if not all_clients:
        access.clients.add(test.company)
    for codename in perms:
        user.user_permissions.add(Permission.objects.get(codename=codename))
    test.client.force_login(user)
    session = test.client.session
    session.update({'soc_mfa_user': user.pk, 'soc_mfa_at': time.time()})
    session.save()
    return user


class Base(TestCase):
    setUp = base.ThreatIntelTests.setUp
    sync = base.ThreatIntelTests.sync

    def ready(self):
        self.sync()
        threat_intel.refresh_matches(self.now)


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class BlocklistQFeedsTests(Base):
    """Plan C: solo con acuerdo de redistribución y solo IPs vistas en las detecciones."""

    def feed(self, **extra):
        values = {'client': self.company, 'enabled': True, 'include_lists': False, 'include_cti': False, 'include_qfeeds': True,
                  'outbound_enabled': True, 'include_c2_detections': False, 'include_qfeeds_c2': True, **extra}
        return BlocklistFeed.objects.create(**values)

    def test_without_agreement_nothing_from_qfeeds_enters_the_list(self):
        self.ready()
        feed = self.feed()
        refresh_feeds(self.now)
        feed.refresh_from_db()
        self.assertEqual((feed.entries, feed.outbound_entries), ([], []))

    def test_with_agreement_only_observed_ips_enter_and_dismissed_destinations_do_not(self):
        self.ready()
        ThreatIntelReview.objects.create(client=self.other, ip=OTHER_C2, decision='dismissed')
        feed = self.feed()
        with mock.patch.dict(os.environ, OEM):
            refresh_feeds(self.now)
            feed.refresh_from_db()
            inbound = {e['ip']: e for e in feed.entries}
            self.assertIn(ATTACKER, inbound)
            self.assertTrue(inbound[ATTACKER]['qfeeds_only'])
            self.assertIn('Q-Feeds: Botnet', inbound[ATTACKER]['reasons'])
            self.assertEqual([e['ip'] for e in feed.outbound_entries], [C2])  # OTHER_C2 descartado en la revisión
            self.assertIn(ATTACKER, servable(feed, self.now))
            self.assertEqual(servable(feed, self.now, outbound=True), [C2])
        # Se retira el acuerdo: lo que solo venía de Q-Feeds deja de servirse sin esperar al recálculo.
        self.assertNotIn(ATTACKER, servable(feed, self.now))
        self.assertEqual(servable(feed, self.now, outbound=True), [])

    def test_crowdsec_reason_keeps_an_entry_when_the_agreement_ends(self):
        from .models import IpReputation
        self.ready()
        IpReputation.objects.create(ip=ATTACKER, listed=True, lists_checked_at=self.now)
        feed = self.feed(include_lists=True)
        with mock.patch.dict(os.environ, OEM):
            refresh_feeds(self.now)
        feed.refresh_from_db()
        entry = next(e for e in feed.entries if e['ip'] == ATTACKER)
        self.assertNotIn('qfeeds_only', entry)
        self.assertIn(ATTACKER, servable(feed, self.now))

    def test_settings_only_accept_the_options_with_an_agreement(self):
        self.ready()
        feed = BlocklistFeed.objects.create(client=self.company)
        login(self, 'manage_operations')
        data = {'action': 'settings', 'enabled': 'on', 'include_qfeeds': 'on', 'include_qfeeds_c2': 'on', 'max_entries': '100'}
        page = self.client.get(reverse('blocklist_detail', args=[self.company.pk]))
        self.assertContains(page, 'prohíbe redistribuir sus datos sin acuerdo escrito')
        self.client.post(reverse('blocklist_detail', args=[self.company.pk]), data)
        feed.refresh_from_db()
        self.assertFalse(feed.include_qfeeds or feed.include_qfeeds_c2)
        with mock.patch.dict(os.environ, OEM):
            self.client.post(reverse('blocklist_detail', args=[self.company.pk]), data)
        feed.refresh_from_db()
        self.assertTrue(feed.include_qfeeds and feed.include_qfeeds_c2)


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class PilotReviewTests(Base):
    """Revisión del piloto del plan C en la página de la lista del cliente."""

    def setUp(self):
        Base.setUp(self)
        self.ready()
        self.feed = BlocklistFeed.objects.create(client=self.company, enabled=True, include_lists=False, include_cti=False,
                                                 include_qfeeds=True, outbound_enabled=True, include_c2_detections=False,
                                                 include_qfeeds_c2=True)
        with mock.patch.dict(os.environ, OEM):
            refresh_feeds(self.now)
        self.feed.refresh_from_db()
        login(self, 'manage_operations')

    def test_outbound_entries_say_whether_this_client_contacted_them(self):
        entry = next(e for e in self.feed.outbound_entries if e['ip'] == C2)
        self.assertEqual((entry['here'], entry['here_allowed']), (1, 1))

    def test_page_summarises_the_pilot_and_filters_qfeeds_entries(self):
        url = reverse('blocklist_detail', args=[self.company.pk])
        with mock.patch.dict(os.environ, OEM):
            page = self.client.get(url)
            self.assertContains(page, 'Q-Feeds en esta lista')
            self.assertContains(page, 'Contactados por este cliente')
            self.assertContains(page, 'Solo Q-Feeds')
            filtered = self.client.get(url, {'solo': 'qfeeds'})
        self.assertContains(filtered, 'mostrando solo Q-Feeds')
        self.assertContains(filtered, C2)

    def test_exclude_adds_the_ip_to_the_exceptions_and_removes_it(self):
        url = reverse('blocklist_detail', args=[self.company.pk])
        with mock.patch.dict(os.environ, OEM):
            self.client.post(url, {'action': 'exclude', 'ip': C2})
            self.client.post(url, {'action': 'exclude', 'ip': C2})  # repetir no la duplica
            self.feed.refresh_from_db()
            self.assertEqual(self.feed.allowlist.count(C2), 1)
            self.assertIn('excluida en la revisión (Q-Feeds)', self.feed.allowlist)
            self.assertNotIn(C2, [e['ip'] for e in self.feed.outbound_entries])
            response = self.client.post(url, {'action': 'exclude', 'ip': '8.8.8.8'})
        self.assertContains(response, 'ya no está en la lista')


class FakeFirewall:
    """API del plugin de Q-Feeds en OPNsense, en memoria."""

    def __init__(self, key='', installed=True, licensed=True):
        self.key, self.installed, self.licensed, self.calls = key, installed, licensed, []

    def __call__(self, connection, path, payload=None, method=None):
        self.calls.append(path)
        if not self.installed:
            raise RuntimeError('HTTP 404')
        if path.endswith('/get'):
            return {'connect': {'general': {'apikey': self.key, 'enable_unbound_bl': '0'}}}
        if path.endswith('/set'):
            self.key = payload['connect']['general']['apikey']
            return {'result': 'saved'}
        if path.endswith('/reconfigure'):
            return {'status': 'ok'}
        if path.endswith('/search_feeds'):
            return {'rows': [{'feed_type': 'malware_ip', 'licensed': '1' if self.licensed else '0'}]}
        if path.endswith('/stats'):
            return {'feeds': [{'name': 'malware_ip'}], 'totals': {'entries': 1200, 'packets_blocked': 40, 'addresses_blocked': 3},
                    'license': {'expiry_date': '2027-11-01'}}
        raise AssertionError(path)


def completed(response):
    return response.get('status') == 'ok'


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class FirewallLicenseTests(Base):
    """Plan B: licencia del cliente en su firewall."""

    def license(self, **extra):
        from .security import encrypt
        values = {'device': self.device, 'plan': 'plus', 'users_band': 'lt50', 'encrypted_key': encrypt(CUSTOMER_KEY),
                  'key_hint': CUSTOMER_KEY[-4:], 'starts_on': date(2026, 11, 1), 'expires_on': date(2027, 11, 1),
                  'purchase_price': 100, 'sale_price': 180}
        values.update(extra)
        return QFeedsLicense.objects.create(**values)

    def plan(self, item):
        return ChangePlan.objects.create(device=self.device, template=qfeeds_devices.TEMPLATE, title='t',
                                         preview=qfeeds_devices.plan_preview(item))

    def test_license_is_saved_encrypted_and_never_shown(self):
        login(self, 'manage_operations', 'manage_connections')
        response = self.client.post(reverse('qfeeds_licenses'), {
            'action': 'save', 'device': self.device.pk, 'plan': 'premium', 'users_band': 'lt50', 'key': CUSTOMER_KEY,
            'starts_on': '2026-11-01', 'expires_on': '2027-11-01', 'purchase_price': '249', 'sale_price': '399', 'reference': 'P-1'})
        self.assertRedirects(response, reverse('qfeeds_licenses'), fetch_redirect_response=False)
        item = QFeedsLicense.objects.get()
        self.assertEqual((decrypt(item.encrypted_key), item.key_hint), (CUSTOMER_KEY, '6789'))
        page = self.client.get(reverse('qfeeds_licenses'))
        self.assertNotContains(page, CUSTOMER_KEY)
        self.assertContains(page, '150,00 €')  # margen
        # Editar sin clave la conserva.
        self.client.post(reverse('qfeeds_licenses'), {
            'action': 'save', 'license': item.pk, 'plan': 'premium', 'users_band': '50_250', 'key': '',
            'starts_on': '2026-11-01', 'expires_on': '2027-11-01'})
        item.refresh_from_db()
        self.assertEqual((item.users_band, decrypt(item.encrypted_key)), ('50_250', CUSTOMER_KEY))

    def test_managing_licenses_needs_connections_permission(self):
        login(self, 'manage_operations')
        self.assertEqual(self.client.get(reverse('qfeeds_licenses')).status_code, 200)
        self.assertEqual(self.client.get(reverse('qfeeds_licenses'), {'new': 1}).status_code, 403)

    def test_operators_only_see_licenses_of_their_clients(self):
        self.license()
        login(self, 'manage_operations', all_clients=False)
        self.assertContains(self.client.get(reverse('qfeeds_licenses')), 'FW-A')
        QFeedsLicense.objects.all().delete()
        self.license(device=self.other_device)
        self.assertNotContains(self.client.get(reverse('qfeeds_licenses')), 'FW-B')

    def test_staging_sets_the_key_checks_the_license_and_rollback_removes_only_ours(self):
        item = self.license()
        plan = self.plan(item)
        firewall = FakeFirewall()
        qfeeds_devices.stage_plugin(plan, firewall, None, completed)
        self.assertEqual(firewall.key, CUSTOMER_KEY)
        self.assertNotIn(CUSTOMER_KEY, json.dumps(plan.remote_objects))
        [obj] = plan.remote_objects
        self.assertTrue(obj['rule']['set_by_soc'])
        self.assertEqual({r['source_net'] for r in plan.preview['rules']} | {r['destination_net'] for r in plan.preview['rules']},
                         {qfeeds_devices.TABLE, 'any'})
        qfeeds_devices.rollback_plugin(obj, firewall, None, delete=True)
        self.assertEqual(firewall.key, '')

    def test_staging_stops_on_another_key_a_missing_plugin_or_a_feed_outside_the_license(self):
        item = self.license()
        for firewall, text in ((FakeFirewall(key='otra-clave-de-alguien'), 'ya tiene otra clave'),
                               (FakeFirewall(installed=False), 'instala os-q-feeds-connector'),
                               (FakeFirewall(licensed=False), 'no incluye la lista')):
            plan = self.plan(item)
            with self.assertRaisesMessage(qfeeds_devices.PublicError, text):
                qfeeds_devices.stage_plugin(plan, firewall, None, completed)
        self.assertEqual(firewall.key, CUSTOMER_KEY)  # el último sí la escribió antes de comprobar la lista

    def test_rollback_does_not_touch_a_key_changed_outside(self):
        item = self.license()
        plan = self.plan(item)
        firewall = FakeFirewall()
        qfeeds_devices.stage_plugin(plan, firewall, None, completed)
        firewall.key = 'cambiada-en-la-consola-123456'
        with self.assertRaisesMessage(ValueError, 'intervención manual'):
            qfeeds_devices.rollback_plugin(plan.remote_objects[0], firewall, None, delete=True)

    def test_page_prepares_a_change_plan_for_api_firewalls(self):
        self.device.management_method = 'api'
        self.device.save()
        OpnsenseConnection.objects.create(device=self.device, api_url='https://192.0.2.1', encrypted_api_key='x',
                                             encrypted_api_secret='y')
        item = self.license()
        login(self, 'manage_operations', 'manage_connections')
        response = self.client.post(reverse('qfeeds_licenses'), {'action': 'plan', 'license': item.pk})
        plan = ChangePlan.objects.get(template=qfeeds_devices.TEMPLATE)
        self.assertRedirects(response, reverse('change_detail', args=[plan.pk]), fetch_redirect_response=False)
        self.assertEqual(plan.preview['license'], item.pk)

    def staged(self, firewall):
        """Preparación completa con el control de cambios, con el firewall simulado."""
        from . import change_control
        self.device.management_method = 'api'
        self.device.save()
        OpnsenseConnection.objects.get_or_create(device=self.device, defaults={
            'api_url': 'https://192.0.2.1', 'encrypted_api_key': 'x', 'encrypted_api_secret': 'y'})
        plan = self.plan(QFeedsLicense.objects.get() if QFeedsLicense.objects.exists() else self.license())
        rules = {}

        def api(connection, path, payload=None, method=None):
            if path.startswith('/api/q_feeds/'):
                return firewall(connection, path, payload, method)
            if path.startswith('/api/firewall/filter/search_rule'):
                return {'rows': [{'uuid': u, **r} for u, r in rules.items()]}
            if path == '/api/firewall/filter/add_rule':
                uid = f'uuid-{len(rules) + 1}'
                rules[uid] = dict(payload['rule'])
                return {'result': 'saved', 'uuid': uid}
            if path.startswith('/api/firewall/filter/get_rule/'):
                return {'rule': rules[path.rsplit('/', 1)[1]]}
            if path.startswith('/api/firewall/filter/del_rule/'):
                rules.pop(path.rsplit('/', 1)[1])
                return {'result': 'deleted'}
            raise AssertionError(path)
        with mock.patch.object(change_control, 'api', api):
            change_control.stage(plan)
        plan.refresh_from_db()
        return plan, rules

    def test_change_control_stages_the_plugin_and_two_disabled_rules(self):
        firewall = FakeFirewall()
        plan, rules = self.staged(firewall)
        self.assertEqual(plan.status, 'staged')
        self.assertEqual(sorted(o['kind'] for o in plan.remote_objects), ['firewall', 'firewall', 'qfeeds'])
        self.assertEqual({(r['direction'], r['enabled']) for r in rules.values()}, {('in', '0'), ('out', '0')})
        self.assertEqual(firewall.key, CUSTOMER_KEY)

    def test_a_failed_preparation_explains_why_and_leaves_nothing(self):
        firewall = FakeFirewall(licensed=False)
        plan, rules = self.staged(firewall)
        self.assertEqual(plan.status, 'failed')
        self.assertIn('no incluye la lista', plan.result)
        self.assertEqual((rules, firewall.key), ({}, ''))

    def vendor(self, index=None, error=None):
        def opener(req):
            self.assertNotIn(CUSTOMER_KEY, req.full_url)
            if error:
                raise urlerror.HTTPError(req.full_url, error, 'error', {}, None)
            return io.BytesIO(json.dumps(index).encode())
        return mock.patch.object(threat_intel, '_open', opener)

    def test_vendor_check_confirms_the_key_and_flags_a_different_expiry(self):
        item = self.license()
        index = {'company_info': {'token_expiration': '2027-11-01T23:59:59Z', 'premium_access': False},
                 'feeds': [{'feed_type': 'malware_ip', 'licensed': True}]}
        with self.vendor(index):
            qfeeds_devices.check(self.now)
        item.refresh_from_db()
        self.assertEqual((item.vendor_status['ok'], item.vendor_status['feeds']), (True, ['malware_ip']))
        self.assertFalse(OperationalIssue.objects.filter(key=qfeeds_devices.issue_key(self.device), active=True).exists())
        QFeedsLicense.objects.filter(pk=item.pk).update(expires_on=date(2027, 6, 1), vendor_checked_at=None)
        with self.vendor(index):
            qfeeds_devices.check(self.now)
        issue = OperationalIssue.objects.get(key=qfeeds_devices.issue_key(self.device), active=True)
        self.assertIn('Revisar la ficha', issue.details)

    def test_rejected_key_and_upcoming_or_past_expiry_raise_issues(self):
        today = timezone.localdate(self.now)
        item = self.license(expires_on=today + timedelta(days=10))
        with self.vendor(error=401):
            qfeeds_devices.check(self.now)
        issue = OperationalIssue.objects.get(key=qfeeds_devices.issue_key(self.device))
        self.assertIn('no reconoce la clave', issue.details)
        QFeedsLicense.objects.filter(pk=item.pk).update(vendor_status={}, vendor_checked_at=self.now)
        qfeeds_devices.check(self.now)
        issue.refresh_from_db()
        self.assertIn('renovarla', issue.details)
        QFeedsLicense.objects.filter(pk=item.pk).update(expires_on=today - timedelta(days=1))
        qfeeds_devices.check(self.now)
        issue.refresh_from_db()
        self.assertEqual(issue.severity, 'critical')

    def test_active_rule_without_loaded_ips_is_an_issue(self):
        item = self.license()
        QFeedsLicense.objects.filter(pk=item.pk).update(vendor_status={'ok': True, 'feeds': ['malware_ip'],
                                                                       'expires': '2027-11-01T00:00:00+00:00'},
                                                        vendor_checked_at=self.now)
        ChangePlan.objects.create(device=self.device, template=qfeeds_devices.TEMPLATE, title='t', status='active', preview={})
        with mock.patch.object(qfeeds_devices, '_read_plugin', return_value={'entries': 0}):
            qfeeds_devices.check(self.now)
        issue = OperationalIssue.objects.get(key=qfeeds_devices.issue_key(self.device), active=True)
        self.assertIn('ninguna IP cargada', issue.details)


LOOKUP = {'value': C2, 'matched': True, 'ioc': {
    'verdict': 'malicious', 'score': 85, 'source_count': 3, 'first_seen': '2026-10-01T08:00:00Z', 'last_seen': '2026-11-19T08:00:00Z',
    'verdict_reasons': ['Seen on 3 independent sources (+30)'], 'tags': [{'name': 'c2'}],
    'notes': [{'text': 'nota interna del analista'}],
    'mitre_attack': [{'id': 'T1071.001', 'name': 'Web Protocols', 'tactics': [{'name': 'Command and Control'}]}],
    'enrichments': [{'source': 'geoip', 'data': {'country_name': 'Netherlands', 'asn_org': 'Example Hosting'}}],
    'linked_iocs': {'outbound_total': 1, 'inbound_total': 0}},
    'meta': {'lookups_limit_month': 5000, 'lookups_used_month': 11, 'lookups_remaining_month': 4989}}


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class LookupTests(Base):
    def request(self, value=C2):
        return self.client.post(reverse('threat_intel_lookup'), {'value': value})

    def test_sync_records_the_soc_license_and_lookup_quota(self):
        index = {**json.loads(json.dumps(FakeApi().index)),
                 'company_info': {'token_expiration': (self.now + timedelta(days=10)).isoformat(), 'premium_access': True}}
        self.sync(FakeApi(index=index))
        values = threat_intel.details()
        self.assertEqual((values['lookup']['available'], values['lookup']['remaining']), (True, 4990))
        self.assertTrue(values['license']['premium'])
        self.assertTrue(OperationalIssue.objects.filter(key=threat_intel.LICENSE_ISSUE, active=True).exists())

    def test_lookup_not_in_the_license_does_not_pause_the_lists(self):
        self.sync(FakeApi(lookup=403))
        values = threat_intel.details()
        self.assertFalse(values['lookup']['available'])
        self.assertNotIn('paused_until', values)
        self.assertTrue(threat_intel.usable_feeds())

    def test_only_indicators_already_in_the_lists_are_queued_once(self):
        self.ready()
        login(self, 'manage_operations')
        self.request('8.8.8.8')
        self.assertFalse(ThreatIntelLookup.objects.exists())
        self.request()
        self.request()
        self.assertEqual(ThreatIntelLookup.objects.filter(value=C2, status='queued').count(), 1)

    def test_without_lookup_in_the_license_nothing_is_queued(self):
        self.sync(FakeApi(lookup=403))
        login(self, 'manage_operations')
        self.request()
        self.assertFalse(ThreatIntelLookup.objects.exists())

    def test_job_stores_a_bounded_summary_and_keeps_the_queue_on_429(self):
        ThreatIntelLookup.objects.create(value=C2)

        def opener(req):
            self.assertNotIn(KEY, req.full_url)
            return io.BytesIO(json.dumps(LOOKUP).encode())
        with mock.patch.dict(os.environ, {'SOC_PORTAL_QFEEDS_KEY': KEY}), mock.patch.object(threat_intel, '_open', opener):
            self.assertEqual(threat_intel.process_lookups(self.now), 1)
        item = ThreatIntelLookup.objects.get()
        self.assertEqual((item.status, item.matched, item.result['score'], item.result['mitre'][0]['id']),
                         ('done', True, 85, 'T1071.001'))
        self.assertNotIn('nota interna', json.dumps(item.result))
        self.assertEqual(threat_intel.details()['lookup']['remaining'], 4989)
        ThreatIntelLookup.objects.create(value=ATTACKER)

        def limited(req):
            raise urlerror.HTTPError(req.full_url, 429, 'error', {}, None)
        with mock.patch.dict(os.environ, {'SOC_PORTAL_QFEEDS_KEY': KEY}), mock.patch.object(threat_intel, '_open', limited):
            threat_intel.process_lookups(self.now)
        self.assertEqual(ThreatIntelLookup.objects.get(value=ATTACKER).status, 'queued')

    def test_page_shows_the_context(self):
        self.ready()
        ThreatIntelLookup.objects.create(value=C2, status='done', matched=True, done_at=self.now,
                                         result=threat_intel._clean_ioc(LOOKUP['ioc']))
        login(self, 'manage_operations')
        page = self.client.get(reverse('threat_intel'), {'q': C2})
        self.assertContains(page, 'Contexto de Q-Feeds')
        self.assertContains(page, 'puntuación 85/100')
        self.assertContains(page, 'T1071.001 Web Protocols (Command and Control)')
        self.assertContains(page, 'Maliciosa')
        self.assertContains(page, '01/10/2026')
        self.assertNotContains(page, 'gasta 1 consulta')  # consultado hace menos de 7 días


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class KeyRejectionTests(Base):
    """La clave rechazada se explica, y una clave nueva se prueba sin esperar a la pausa de una hora."""

    def test_rejections_explain_the_likely_cause(self):
        self.sync(FakeApi(error=401))
        self.assertIn('sin espacios ni comillas', threat_intel.details()['error'])
        later = self.now + timedelta(hours=2)
        self.sync(FakeApi(error=403), now=later)
        self.assertIn('no permite la IP de este servidor', threat_intel.details()['error'])
        login(self, 'manage_operations')
        with mock.patch('django.utils.timezone.now', return_value=later):
            page = self.client.get(reverse('threat_intel'))
        self.assertContains(page, 'no permite la IP de este servidor')
        self.assertContains(page, 'Se reintenta a partir de las')

    def test_a_new_key_is_tried_at_once_and_the_same_key_waits(self):
        self.sync(FakeApi(error=401))
        api = self.sync(now=self.now + timedelta(minutes=15))
        self.assertEqual(api.requests, [])  # misma clave: espera la hora de pausa
        api = self.sync(now=self.now + timedelta(minutes=15), key='otra-clave-nueva-123')
        self.assertTrue(api.requests)
        values = threat_intel.details()
        self.assertEqual(values['error'], '')
        self.assertNotIn('paused_key', values)

    def test_customer_keys_with_any_printable_character_are_accepted(self):
        login(self, 'manage_operations', 'manage_connections')
        for key, valid in (('con espacio dentro', False), ('12|AbCdEfGh:ijkl', True)):
            response = self.client.post(reverse('qfeeds_licenses'), {
                'action': 'save', 'device': self.device.pk, 'plan': 'plus', 'users_band': 'lt50', 'key': key,
                'starts_on': '2026-11-01', 'expires_on': '2027-11-01'})
            self.assertEqual(QFeedsLicense.objects.exists(), valid, key)
            if not valid:
                self.assertContains(response, 'no puede tener espacios')

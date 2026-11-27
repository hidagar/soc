"""Q-Feeds para los clientes: lista preventiva, dominios para el DNS, medición por fuente y activación masiva."""
import ipaddress
import json
import time
from datetime import timedelta
from unittest import mock

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from . import blocklist, change_control, qfeeds_distribution as qd, threat_intel
from . import test_threat_intel as base
from .blocklist import refresh_feeds
from .blocklist_efficacy import client_protection, state_name
from .change_control import stage
from .models import (AuditEvent, BlocklistFeed, ChangePlan, Device, OpnsenseConnection, StaffAccess, ThreatIntelReview,
                     UnifiBlocklistBinding, WorkerState)
from .test_blocklist import FakeOpnsenseWithAliases
from .test_threat_intel import ATTACKER, C2, IN_NETWORK, OTHER_C2, PARTNER

NETWORK = '185.220.101.0/24'


def login(test, *perms, fresh=True):
    user = get_user_model().objects.create_user('analista')
    StaffAccess.objects.create(user=user, role='operator', all_clients=True)
    for codename in perms:
        user.user_permissions.add(Permission.objects.get(codename=codename))
    test.client.force_login(user)
    if fresh:
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

    def feed(self, client=None, **extra):
        values = {'client': client or self.company, 'enabled': True, 'include_lists': False, 'include_cti': False,
                  'qfeeds_preventive': True, 'qfeeds_dns': True, **extra}
        feed = BlocklistFeed.objects.create(**values)
        self.token = blocklist.rotate_token(feed)
        return feed


class RangesTests(TestCase):
    def test_overlaps_merges_ranges_and_checks_both_versions(self):
        ranges = qd.Ranges([ipaddress.ip_network('198.51.100.0/24'), ipaddress.ip_network('2001:db8::/32')], ['203.0.113.7'])
        for value, expected in (('198.51.100.9', True), ('198.51.0.0/16', True), ('203.0.113.7', True), ('203.0.113.8', False),
                                ('198.51.101.1', False), ('2001:db8::1', True), ('2001:db9::1', False)):
            self.assertEqual(ranges.overlaps(ipaddress.ip_network(value)), expected, value)


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False, SOC_PUBLIC_ORIGIN='https://soc.example.test')
class PreventiveTests(Base):
    def test_nothing_is_served_without_current_qfeeds_lists(self):
        feed = self.feed()
        self.assertEqual((qd.servable_preventive(feed), qd.servable_dns(feed)), ([], []))

    def test_preventive_list_has_attackers_first_then_the_rest_without_protected_or_dismissed(self):
        self.ready()
        ThreatIntelReview.objects.create(client=self.other, ip=OTHER_C2, decision='dismissed')
        feed = self.feed()
        values = qd.servable_preventive(feed)
        # Primero las que atacaron a algún cliente (también la IP vista dentro de una red de la lista).
        self.assertEqual(values[:2], sorted([ATTACKER, IN_NETWORK]))
        self.assertEqual(set(values[2:]), {C2, NETWORK})
        self.assertNotIn(PARTNER, values, 'IP de un cliente')
        self.assertNotIn(OTHER_C2, values, 'revisada «Sin riesgo»')

    def test_exceptions_of_any_client_cap_and_brake_apply(self):
        self.ready()
        feed = self.feed(allowlist='185.220.101.0/25  # proveedor')
        self.feed(client=self.other, allowlist=C2)
        values = qd.servable_preventive(feed)
        self.assertNotIn(C2, values, 'excepción de otro cliente')
        self.assertFalse(any(v.startswith('185.220.101.') for v in values), 'la red y la IP se solapan con la excepción')
        BlocklistFeed.objects.filter(pk=feed.pk).update(preventive_max=1)
        feed.refresh_from_db()
        self.assertEqual(qd.servable_preventive(feed), [ATTACKER])
        for change in ({'stopped': True}, {'enabled': False}, {'qfeeds_preventive': False}):
            BlocklistFeed.objects.filter(pk=feed.pk).update(**{'stopped': False, 'enabled': True, 'qfeeds_preventive': True, **change})
            feed.refresh_from_db()
            self.assertEqual(qd.servable_preventive(feed), [], change)

    def test_broad_networks_never_enter(self):
        self.ready()
        from .models import ThreatIndicator
        stats = {}
        ThreatIndicator.objects.create(feed='malware_ip', kind='net', value='81.2.0.0/16')
        values = qd.preventive_values(100, stats=stats)
        self.assertNotIn('81.2.0.0/16', values)
        self.assertEqual(stats['broad'], 1)

    def test_url_serves_the_list_with_the_token_and_records_the_download(self):
        self.ready()
        feed = self.feed()
        url = reverse('blocklist_serve_qfeeds', args=[self.company.pk, self.token])
        response = self.client.get(url)
        self.assertEqual(response['Content-Type'], 'text/plain; charset=utf-8')
        self.assertIn(ATTACKER + '\n', response.content.decode())
        feed.refresh_from_db()
        self.assertIsNotNone(feed.preventive_fetch_at)
        self.assertIsNone(feed.last_fetch_at, 'cada lista registra su propia descarga')
        self.assertEqual(self.client.get(reverse('blocklist_serve_qfeeds', args=[self.company.pk, 'malo'])).status_code, 404)
        blocklist.rotate_token(feed)
        self.assertEqual(self.client.get(url).content, b'', 'la URL anterior sirve una lista vacía')

    def test_refresh_stores_counts_and_sources(self):
        self.ready()
        feed = self.feed(include_qfeeds=True)
        refresh_feeds(self.now)
        feed.refresh_from_db()
        self.assertEqual((feed.preventive_count, feed.dns_count), (5, 1))
        entry = next(e for e in feed.entries if e['ip'] == ATTACKER)
        self.assertEqual(entry['sources'], ['qfeeds'])


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False, SOC_PUBLIC_ORIGIN='https://soc.example.test')
class DnsTests(Base):
    def test_domains_without_exceptions_their_subdomains_or_the_soc_domain(self):
        self.ready()
        feed = self.feed()
        self.assertEqual(qd.servable_dns(feed), ['malo.example.com'])
        response = self.client.get(reverse('blocklist_serve_dns', args=[self.company.pk, self.token]))
        self.assertEqual(response.content, b'malo.example.com\n')
        for allow in ('example.com', '*.malo.example.com', 'www.malo.example.com  # web del proveedor'):
            BlocklistFeed.objects.filter(pk=feed.pk).update(dns_allowlist=allow)
            feed.refresh_from_db()
            self.assertEqual(qd.servable_dns(feed), [], allow)
        BlocklistFeed.objects.filter(pk=feed.pk).update(dns_allowlist='')
        feed.refresh_from_db()
        with self.settings(SOC_PUBLIC_ORIGIN='https://malo.example.com'):
            self.assertEqual(qd.servable_dns(feed), [], 'el dominio del SOC nunca se publica')

    def test_parse_domains_rejects_invalid_values(self):
        self.assertEqual(qd.parse_domains('Proveedor.Example.\n# nota\n*.cdn.example.net'), ['proveedor.example', 'cdn.example.net'])
        with self.assertRaises(ValueError):
            qd.parse_domains('no es un dominio')


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False, SOC_PUBLIC_ORIGIN='https://soc.example.test')
class ClientPageTests(Base):
    def test_settings_save_preventive_and_dns_options_and_validate_them(self):
        self.ready()
        feed = BlocklistFeed.objects.create(client=self.company)
        login(self, 'manage_operations', 'manage_connections')
        url = reverse('blocklist_detail', args=[self.company.pk])
        data = {'action': 'settings', 'enabled': 'on', 'max_entries': '100', 'qfeeds_preventive': 'on', 'preventive_max': '1000',
                'qfeeds_dns': 'on', 'dns_allowlist': 'proveedor.example'}
        self.client.post(url, data)
        feed.refresh_from_db()
        self.assertEqual((feed.qfeeds_preventive, feed.preventive_max, feed.qfeeds_dns, feed.dns_allowlist),
                         (True, 1000, True, 'proveedor.example'))
        self.assertEqual(feed.preventive_count, 5)
        page = self.client.get(url)
        self.assertContains(page, 'Lista preventiva · 5 entradas')
        self.assertContains(page, '/feeds/bloqueo/%d/' % self.company.pk)
        self.assertContains(page, '/qfeeds/')
        self.assertContains(page, '/dominios/')
        for bad in ({'dns_allowlist': 'mal dominio'}, {'preventive_max': '0'}, {'preventive_max': '300000'}):
            page = self.client.post(url, {**data, **bad})
            self.assertEqual(page.status_code, 200)
            self.assertContains(page, 'class="notice"')
        feed.refresh_from_db()
        self.assertEqual(feed.preventive_max, 1000)

    def test_preventive_plan_stages_its_own_table_and_rules_by_direction(self):
        self.ready()
        feed = self.feed()
        OpnsenseConnection.objects.create(device=self.device, api_url='https://fw.example.test', encrypted_api_key='x',
                                          encrypted_api_secret='x')
        Device.objects.filter(pk=self.device.pk).update(management_method='api')
        login(self, 'manage_operations', 'manage_connections')
        url = reverse('blocklist_detail', args=[self.company.pk])
        self.client.post(url, {'action': 'plan_q_out', 'device': self.device.pk})
        self.client.post(url, {'action': 'plan_q', 'device': self.device.pk})
        out_plan, plan = ChangePlan.objects.order_by('pk')
        self.assertEqual((plan.template, out_plan.template, plan.status), ('qfeeds', 'qfeeds_out', 'draft'))
        self.assertNotIn(self.token, json.dumps(plan.preview))
        firewall = FakeOpnsenseWithAliases({})
        with mock.patch.object(change_control, 'api', side_effect=firewall):
            stage(plan)
            stage(out_plan)
        self.assertEqual((plan.status, out_plan.status), ('staged', 'staged'))
        aliases = {a['name']: a for a in firewall.aliases.values()}
        alias = aliases[f'SOC_QFEEDS_{plan.pk}']
        self.assertTrue(alias['content'].endswith(f'/{self.token}/qfeeds/'))
        [rule] = firewall.owned(plan).values()
        [rule_out] = firewall.owned(out_plan).values()
        self.assertEqual((rule['direction'], rule['source_net'], rule['enabled']), ('in', alias['name'], '0'))
        self.assertEqual((rule_out['direction'], rule_out['destination_net']), ('out', f'SOC_QFEEDS_{out_plan.pk}'))
        BlocklistFeed.objects.filter(pk=feed.pk).update(qfeeds_preventive=False)
        self.device.refresh_from_db()
        again = ChangePlan.objects.create(device=self.device, template='qfeeds', title=qd.TITLE, parameters={'client': self.company.pk},
                                          preview=qd.plan_preview(self.device))
        with mock.patch.object(change_control, 'api', side_effect=FakeOpnsenseWithAliases({})):
            stage(again)
        self.assertEqual(again.status, 'failed', 'sin lista preventiva activada no se prepara')


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False, SOC_PUBLIC_ORIGIN='https://soc.example.test')
class MeasurementTests(Base):
    def setUp(self):
        super().setUp()
        self.ready()
        self.qfeed = self.feed(include_lists=True, entries=[
            {'ip': ATTACKER, 'reasons': ['Lista comunitaria', 'Q-Feeds: Botnet'], 'here': 1},
            {'ip': C2, 'reasons': ['Q-Feeds: Botnet'], 'qfeeds_only': True, 'here': 0},
            {'ip': '203.0.113.200', 'reasons': ['Bloqueo manual: caso'], 'manual': 1, 'here': 0}], preventive_count=4)
        refresh = timezone.localdate().isoformat()
        for template, packets in (('crowdsec', 30), ('qfeeds', 70)):
            plan = ChangePlan.objects.create(device=self.device, template=template, title=template, status='active')
            WorkerState.objects.create(name=state_name(plan), details={'checked_at': self.now.isoformat(), 'history': {refresh: packets}})

    def test_source_counts_cover_old_entries_without_sources(self):
        counts = qd.source_counts(self.qfeed.entries)
        self.assertEqual((counts['crowdsec'], counts['qfeeds'], counts['both'], counts['only_qfeeds'], counts['manual']),
                         (1, 2, 1, 1, 1))

    def test_customer_projection_separates_the_preventive_list(self):
        data = client_protection(self.company, now=self.now)
        self.assertEqual(data['inbound']['packets'], 30)
        self.assertEqual(data['inbound']['sources'], {'crowdsec': 1, 'qfeeds': 2})
        self.assertEqual({k: data['preventive'][k] for k in ('entries', 'packets', 'measured')}, {'entries': 4, 'packets': 70, 'measured': True})
        BlocklistFeed.objects.filter(pk=self.qfeed.pk).update(qfeeds_preventive=False)
        self.assertNotIn('preventive', client_protection(self.company, now=self.now))

    def test_portal_shows_both_lists_without_ips(self):
        from .models import Client
        Client.objects.filter(pk=self.company.pk).update(customer_portal_detail_enabled=True)
        customer = get_user_model().objects.create_user('cliente')
        StaffAccess.objects.create(user=customer, role='customer').clients.add(self.company)
        self.client.force_login(customer)
        page = self.client.get(reverse('customer_firewalls'))
        self.assertContains(page, 'lista preventiva')
        self.assertContains(page, '<strong>70</strong>')
        self.assertContains(page, 'en las de Q-Feeds')
        for secret in (ATTACKER, C2, '203.0.113.200', 'Bloqueo manual'):
            self.assertNotContains(page, secret)

    def test_unifi_preventive_list_takes_the_first_ipv4_entries(self):
        from .unifi_blocklist import PLACEHOLDER, desired
        unifi = Device.objects.create(site=self.device.site, name='UDM', vendor='unifi')
        binding = UnifiBlocklistBinding.objects.create(device=unifi, direction='qfeeds', site_id='s', list_id='l',
                                                       list_name='SOC Bloqueo preventivo Q-Feeds', item_format='typed')
        values = desired(binding, self.now)
        self.assertIn(ATTACKER, values)
        self.assertNotIn(PARTNER, values)
        BlocklistFeed.objects.filter(pk=self.qfeed.pk).update(stopped=True)
        self.assertEqual(desired(binding, self.now), [PLACEHOLDER])


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False, SOC_PUBLIC_ORIGIN='https://soc.example.test')
class BulkTests(Base):
    url = staticmethod(lambda: reverse('blocklist_qfeeds'))

    def setUp(self):
        super().setUp()
        self.ready()
        Device.objects.filter(pk=self.device.pk).update(management_method='api')
        self.data = {'client': [str(self.company.pk), str(self.other.pk)], 'opt_qfeeds_preventive': 'on', 'opt_include_qfeeds': 'on',
                     'mode': 'on', 'publish': 'on'}

    def test_requires_operations_permission(self):
        login(self)
        self.assertEqual(self.client.get(self.url()).status_code, 403)

    def test_status_table_lists_every_client(self):
        self.feed()
        login(self, 'manage_operations')
        page = self.client.get(self.url())
        self.assertContains(page, 'Empresa A')
        self.assertContains(page, 'Empresa B')
        self.assertContains(page, 'Sin publicar')

    def test_preview_changes_nothing_and_apply_needs_the_previewed_selection(self):
        login(self, 'manage_operations', 'manage_connections')
        page = self.client.post(self.url(), {**self.data, 'action': 'preview', 'drafts': 'on'})
        self.assertContains(page, 'Vista previa')
        self.assertContains(page, '5 entradas preventivas')
        self.assertContains(page, 'Borrador de regla preventiva en FW-A')
        self.assertFalse(BlocklistFeed.objects.exists())
        signature = page.context['previewed']
        changed = {**self.data, 'action': 'apply', 'drafts': 'on', 'previewed': signature, 'client': [str(self.company.pk)]}
        page = self.client.post(self.url(), changed)
        self.assertContains(page, 'La selección ha cambiado')
        self.assertFalse(BlocklistFeed.objects.exists())
        response = self.client.post(self.url(), {**self.data, 'action': 'apply', 'drafts': 'on', 'previewed': signature})
        self.assertRedirects(response, self.url(), fetch_redirect_response=False)
        feeds = {f.client_id: f for f in BlocklistFeed.objects.all()}
        self.assertTrue(all(f.enabled and f.qfeeds_preventive and f.include_qfeeds and f.token_hash for f in feeds.values()))
        self.assertEqual(feeds[self.company.pk].preventive_count, 5)
        self.assertEqual(list(ChangePlan.objects.values_list('template', 'device_id', 'status')), [('qfeeds', self.device.pk, 'draft')])
        self.assertEqual(AuditEvent.objects.filter(action='blocklist.qfeeds_bulk').count(), 2)
        # Repetir no duplica borradores.
        self.client.post(self.url(), {**self.data, 'action': 'apply', 'drafts': 'on', 'previewed': signature})
        self.assertEqual(ChangePlan.objects.count(), 1)

    def test_activation_needs_fresh_mfa_but_deactivation_does_not(self):
        feed = self.feed(include_qfeeds=True)
        login(self, 'manage_operations', fresh=False)
        data = {**self.data, 'publish': '', 'action': 'preview'}
        signature = self.client.post(self.url(), data).context['previewed']
        response = self.client.post(self.url(), {**data, 'action': 'apply', 'previewed': signature})
        self.assertIn(reverse('mfa_challenge'), response['Location'])
        feed.refresh_from_db()
        self.assertTrue(feed.qfeeds_preventive)
        off = {**data, 'mode': 'off'}
        signature = self.client.post(self.url(), off).context['previewed']
        self.client.post(self.url(), {**off, 'action': 'apply', 'previewed': signature})
        feed.refresh_from_db()
        self.assertFalse(feed.qfeeds_preventive or feed.include_qfeeds)
        self.assertTrue(feed.enabled, 'desactivar Q-Feeds no despublica la lista del cliente')

    def test_dns_drafts_are_prepared_too(self):
        login(self, 'manage_operations', 'manage_connections')
        data = {**self.data, 'opt_qfeeds_dns': 'on', 'drafts': 'on'}
        page = self.client.post(self.url(), {**data, 'action': 'preview'})
        self.assertContains(page, 'Borrador de lista DNS en FW-A')
        self.client.post(self.url(), {**data, 'action': 'apply', 'previewed': page.context['previewed']})
        self.assertEqual(sorted(ChangePlan.objects.values_list('template', flat=True)), ['qfeeds', 'qfeeds_dns'])

    def test_drafts_need_the_connections_permission(self):
        login(self, 'manage_operations')
        response = self.client.post(self.url(), {**self.data, 'action': 'preview', 'drafts': 'on'})
        self.assertEqual(response.status_code, 403)


class TimingTests(TestCase):
    def test_week_is_none_without_measurements(self):
        self.assertIsNone(qd._week([], timezone.now()))
        self.assertIsNone(qd._week([ChangePlan(pk=999999)], timezone.now() - timedelta(days=1)))


class FakeUnbound(FakeOpnsenseWithAliases):
    """OPNsense 25.7: listas de bloqueo DNS como elementos con descripción, y la carga de Unbound."""

    def __init__(self, supported=True, unbound_enabled='1'):
        super().__init__({})
        self.dnsbl = {'operador': {'description': 'Lista del operador', 'enabled': '1', 'lists': 'https://otra.example/l.txt'}}
        self.supported, self.unbound_enabled, self.reloads, self.fail_reload = supported, unbound_enabled, 0, False

    def __call__(self, connection, path, payload=None, method=None):
        if path.startswith('/api/unbound/'):
            self.calls.append(path)
            if not self.supported:
                from .opnsense_api import OpnsenseApiError
                raise OpnsenseApiError('OPNsense devolvió un error HTTP 404.')
            uid = path.rsplit('/', 1)[1]
            if path.startswith('/api/unbound/settings/search_dnsbl'):
                return {'rows': [{'uuid': k, **v} for k, v in self.dnsbl.items()]}
            if path == '/api/unbound/settings/get':
                return {'unbound': {'general': {'enabled': self.unbound_enabled}}}
            if path == '/api/unbound/settings/add_dnsbl':
                self.dnsbl['dnsbl-1'] = dict(payload['blocklist'])
                return {'result': 'saved', 'uuid': 'dnsbl-1'}
            if path.startswith('/api/unbound/settings/get_dnsbl/'):
                return {'blocklist': dict(self.dnsbl.get(uid, {}))}
            if path.startswith('/api/unbound/settings/set_dnsbl/'):
                self.dnsbl[uid].update(payload['blocklist'])
                return {'result': 'saved'}
            if path.startswith('/api/unbound/settings/del_dnsbl/'):
                self.dnsbl.pop(uid)
                return {'result': 'deleted'}
            if path == '/api/unbound/service/dnsbl':
                self.reloads += 1
                return {'status': 'Error' if self.fail_reload else 'OK'}
        return super().__call__(connection, path, payload, method)


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False, SOC_PUBLIC_ORIGIN='https://soc.example.test')
class DnsTemplateTests(Base):
    def setUp(self):
        super().setUp()
        self.ready()
        self.qfeed = self.feed(qfeeds_preventive=False)
        OpnsenseConnection.objects.create(device=self.device, api_url='https://fw.example.test', encrypted_api_key='x',
                                          encrypted_api_secret='x')
        Device.objects.filter(pk=self.device.pk).update(management_method='api')
        self.device.refresh_from_db()

    def plan(self):
        login(self, 'manage_operations', 'manage_connections')
        self.client.post(reverse('blocklist_detail', args=[self.company.pk]), {'action': 'plan_dns', 'device': self.device.pk})
        return ChangePlan.objects.get(template=qd.DNS_TEMPLATE)

    def run_with(self, firewall, function, plan):
        with mock.patch.object(change_control, 'api', side_effect=firewall):
            function(plan)
        plan.refresh_from_db()

    def test_stage_creates_a_disabled_own_list_and_never_touches_the_operator_list(self):
        plan = self.plan()
        self.assertEqual((plan.status, plan.preview['dnsbl']['nxdomain']), ('draft', '1'))
        self.assertNotIn(self.token, json.dumps(plan.preview))
        firewall = FakeUnbound()
        self.run_with(firewall, stage, plan)
        self.assertEqual(plan.status, 'staged')
        item = firewall.dnsbl['dnsbl-1']
        self.assertEqual((item['enabled'], item['description']), ('0', f'SOC PLAN {plan.pk} dnsbl'))
        self.assertTrue(item['lists'].endswith(f'/{self.token}/dominios/'))
        self.assertNotIn(self.token, json.dumps(plan.remote_objects))
        self.assertEqual(firewall.dnsbl['operador']['enabled'], '1')
        self.assertFalse(any('/api/firewall/filter/add_rule' in c for c in firewall.calls))
        self.run_with(firewall, stage, plan)  # repetir no duplica
        self.assertEqual(len(firewall.dnsbl), 2)

    def test_old_versions_get_the_guided_mode_and_inactive_unbound_fails(self):
        plan = self.plan()
        self.run_with(FakeUnbound(supported=False), stage, plan)
        self.assertEqual(plan.status, 'manual')
        self.assertIn('25.7', plan.result)
        other = qd.create_dns_draft(self.qfeed, self.device, None)
        firewall = FakeUnbound(unbound_enabled='0')
        self.run_with(firewall, stage, other)
        self.assertEqual(other.status, 'failed')
        self.assertEqual(list(firewall.dnsbl), ['operador'])

    def test_activation_waits_for_confirmation_and_expiry_disables_it(self):
        from .change_control import enable, process_queue
        plan = self.plan()
        firewall = FakeUnbound()
        self.run_with(firewall, stage, plan)
        self.run_with(firewall, enable, plan)
        self.assertEqual(plan.status, 'awaiting_confirmation')
        self.assertEqual(firewall.dnsbl['dnsbl-1']['enabled'], '1')
        self.assertEqual(firewall.reloads, 1)
        self.assertGreater(plan.confirmation_deadline, timezone.now() + timedelta(minutes=9))
        self.assertFalse(any('savepoint' in c for c in firewall.calls))
        # Confirmar: sin punto de restauración del filtro que cancelar.
        ChangePlan.objects.filter(pk=plan.pk).update(status='confirm_queued')
        with mock.patch.object(change_control, 'api', side_effect=firewall):
            process_queue()
        plan.refresh_from_db()
        self.assertEqual(plan.status, 'active')
        self.assertFalse(any('cancel_rollback' in c for c in firewall.calls))
        # Revertir la retira y recarga Unbound; la del operador sigue.
        ChangePlan.objects.filter(pk=plan.pk).update(status='rollback_queued')
        with mock.patch.object(change_control, 'api', side_effect=firewall):
            process_queue()
        plan.refresh_from_db()
        self.assertEqual(plan.status, 'rolled_back')
        self.assertEqual(firewall.dnsbl['dnsbl-1']['enabled'], '0')
        self.assertEqual(firewall.reloads, 2)
        self.assertEqual(firewall.dnsbl['operador']['enabled'], '1')

    def test_unconfirmed_or_failed_activation_is_disabled_again(self):
        from .change_control import enable, process_queue
        plan = self.plan()
        firewall = FakeUnbound()
        self.run_with(firewall, stage, plan)
        self.run_with(firewall, enable, plan)
        ChangePlan.objects.filter(pk=plan.pk).update(confirmation_deadline=timezone.now() - timedelta(seconds=1))
        with mock.patch.object(change_control, 'api', side_effect=firewall):
            process_queue()
        plan.refresh_from_db()
        self.assertEqual((plan.status, firewall.dnsbl['dnsbl-1']['enabled']), ('rolled_back', '0'))
        other = qd.create_dns_draft(self.qfeed, self.device, None)
        firewall = FakeUnbound()
        self.run_with(firewall, stage, other)
        firewall.fail_reload = True
        self.run_with(firewall, enable, other)
        self.assertNotEqual(other.status, 'awaiting_confirmation')
        self.assertEqual(firewall.dnsbl['dnsbl-1']['enabled'], '0')

    def test_client_page_shows_modes_per_device_and_the_dns_button(self):
        from .models import Site
        Device.objects.create(site=Site.objects.get(client=self.company), name='HS-Oficina', vendor='hillstone')
        login(self, 'manage_operations', 'manage_connections')
        page = self.client.get(reverse('blocklist_detail', args=[self.company.pk]))
        self.assertContains(page, 'Preparar bloqueo DNS en FW-A')
        self.assertContains(page, 'HS-Oficina')
        self.assertContains(page, 'capability-pending')
        self.assertContains(page, 'capability-auto')


class CapabilityTests(TestCase):
    def test_matrix_is_complete_and_modes_depend_on_the_connection(self):
        from . import vendor_capabilities as vc
        for vendor, _ in vc.VENDORS:
            for feature, _ in vc.FEATURES:
                self.assertIn(vc.capability(vendor, feature)[0], vc.MODES, (vendor, feature))
        self.assertEqual(vc.for_device(Device(vendor='opnsense', management_method='api'), 'dns')[0], 'auto')
        self.assertEqual(vc.for_device(Device(vendor='opnsense', management_method='ssh'), 'dns')[0], 'guided')
        self.assertEqual(vc.for_device(Device(vendor='unifi'), 'blocklist')[0], 'guided')
        self.assertEqual(vc.for_device(Device(vendor='other'), 'dns')[0], 'pending')

    @override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
    def test_page_lists_every_vendor(self):
        user = get_user_model().objects.create_user('lector')
        StaffAccess.objects.create(user=user, role='operator', all_clients=True)
        self.client.force_login(user)
        page = self.client.get(reverse('vendor_capabilities'))
        for name in ('OPNsense', 'UniFi', 'Hillstone', 'Grandstream GCC', 'Bloqueo de dominios por DNS', 'Por comprobar'):
            self.assertContains(page, name)

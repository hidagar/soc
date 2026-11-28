"""Dominios de Q-Feeds en UniFi: política de bloqueo por dominios del SOC (filtro de destino DOMAINS)."""
from unittest import mock

from django.urls import reverse

from . import qfeeds_distribution, unifi_blocklist
from .blocklist_efficacy import client_protection
from .models import BlocklistFeed, ChangePlan, UnifiBlocklistBinding
from .test_unifi_blocklist import ZONES, UnifiTestCase
from .unifi_blocklist import DNS_MAX_ITEMS, DNS_PLACEHOLDER, sync

DOMAINS = ['malo.example.com', 'c2.example.net']


class UnifiDomainTests(UnifiTestCase):
    def setUp(self):
        super().setUp()
        BlocklistFeed.objects.filter(pk=self.feed.pk).update(qfeeds_dns=True)
        self.domains = list(DOMAINS)
        patcher = mock.patch.object(qfeeds_distribution, 'servable_dns', side_effect=lambda feed: list(self.domains)
                                    if feed.enabled and not feed.stopped and feed.qfeeds_dns else [])
        patcher.start()
        self.addCleanup(patcher.stop)

    def create(self):
        if not getattr(self, 'url', None):
            self.url = self.login()
        url = self.url
        response = self.client.post(url, {'action': 'unifi_create', 'device': self.device.pk, 'direction': 'dns'})
        return url, response

    def test_creates_a_disabled_domain_policy_without_any_list(self):
        url, response = self.create()
        self.assertRedirects(response, url, fetch_redirect_response=False)
        binding = UnifiBlocklistBinding.objects.get(direction='dns')
        [policy] = self.console.policy_posts
        self.assertEqual((policy['enabled'], policy['action'], policy['name']),
                         (False, {'type': 'BLOCK'}, 'SOC Bloqueo dominios Q-Feeds Internal→External'))
        self.assertEqual((policy['source']['zoneId'], policy['destination']['zoneId']), (ZONES['Internal'], ZONES['External']))
        self.assertEqual(policy['destination']['trafficFilter'],
                         {'type': 'DOMAIN', 'domainFilter': {'type': 'DOMAINS', 'domains': sorted(DOMAINS)}})
        self.assertNotIn('trafficFilter', policy['source'])
        self.assertEqual(self.console.posts, [], 'no se crea ninguna traffic matching list')
        self.assertEqual((binding.pushed_count, binding.error), (2, ''))
        page = self.client.get(url)
        self.assertContains(page, '2 dominios escritos')
        self.assertContains(page, 'política por dominios')
        # Repetir no duplica la política.
        self.create()
        self.assertEqual(len(self.console.policy_posts), 1)

    def test_sync_rewrites_only_the_soc_policy_and_brake_leaves_a_placeholder(self):
        self.create()
        binding = UnifiBlocklistBinding.objects.get(direction='dns')
        operator = dict(self.console.policies['66666666-6666-6666-6666-666666666666'])
        self.domains.append('nuevo.example.org')
        self.assertTrue(sync(binding))
        uid = binding.policies[0]['id']
        self.assertEqual(self.console.policies[uid]['destination']['trafficFilter']['domainFilter']['domains'],
                         sorted(self.domains))
        self.assertEqual(self.console.policies['66666666-6666-6666-6666-666666666666'], operator)
        BlocklistFeed.objects.filter(pk=self.feed.pk).update(stopped=True)
        binding.refresh_from_db()
        self.assertTrue(sync(binding))
        self.assertEqual(self.console.policies[uid]['destination']['trafficFilter']['domainFilter']['domains'], [DNS_PLACEHOLDER])
        binding.refresh_from_db()
        self.assertEqual(binding.pushed_count, 0)

    def test_cap_unconfirmed_write_and_changed_policy_are_errors(self):
        self.domains = [f'd{i}.example.com' for i in range(DNS_MAX_ITEMS + 50)]
        self.create()
        binding = UnifiBlocklistBinding.objects.get(direction='dns')
        self.assertEqual(binding.pushed_count, DNS_MAX_ITEMS)
        uid = binding.policies[0]['id']
        original = self.console.__call__

        def lossy(api_key, host_id, path, method='GET', payload=None, query=None):
            return {} if method == 'PUT' else original(api_key, host_id, path, method, payload, query)
        self.domains = ['otro.example.com']
        with mock.patch.object(unifi_blocklist, 'call', side_effect=lossy):
            self.assertFalse(sync(binding, force=True))
        binding.refresh_from_db()
        self.assertIn('no confirmó los dominios', binding.error)
        self.console.policies[uid]['name'] = 'Renombrada'
        self.assertFalse(sync(binding, force=True))
        binding.refresh_from_db()
        self.assertIn('ha cambiado en UniFi', binding.error)

    def test_needs_the_dns_option_and_cannot_bind_an_ip_list(self):
        BlocklistFeed.objects.filter(pk=self.feed.pk).update(qfeeds_dns=False)
        url, response = self.create()
        self.assertContains(response, 'Activa primero los dominios de Q-Feeds')
        self.assertFalse(UnifiBlocklistBinding.objects.exists())
        BlocklistFeed.objects.filter(pk=self.feed.pk).update(qfeeds_dns=True)
        response = self.client.post(url, {'action': 'unifi_bind', 'device': self.device.pk, 'direction': 'dns', 'list_id': 'x'})
        self.assertContains(response, 'no van en una lista de UniFi')

    def test_activation_unbind_and_customer_projection(self):
        url, _ = self.create()
        binding = UnifiBlocklistBinding.objects.get(direction='dns')
        self.client.post(url, {'action': 'unifi_policy_enable', 'binding': binding.pk})
        binding.refresh_from_db()
        uid = binding.policies[0]['id']
        self.assertTrue(binding.policies_enabled and self.console.policies[uid]['enabled'])
        ChangePlan.objects.all().delete()
        data = client_protection(self.company)
        self.assertEqual({k: data['dns'][k] for k in ('entries', 'firewalls', 'measured')}, {'entries': 2, 'firewalls': ['UDM-BCM'],
                                                                                             'measured': False})
        self.client.post(url, {'action': 'unifi_unbind', 'binding': binding.pk})
        self.assertFalse(UnifiBlocklistBinding.objects.filter(direction='dns').exists())
        self.assertNotIn(uid, self.console.policies)

    def test_status_page_and_capability(self):
        from .vendor_capabilities import for_device
        self.create()
        self.assertEqual(for_device(self.device, 'dns')[0], 'partial')
        page = self.client.get(reverse('blocklist_qfeeds'))
        self.assertContains(page, 'UniFi sin activar')


class UnifiPreventiveOutboundTests(UnifiTestCase):
    def setUp(self):
        super().setUp()
        BlocklistFeed.objects.filter(pk=self.feed.pk).update(qfeeds_preventive=True)
        patcher = mock.patch.object(qfeeds_distribution, 'servable_preventive', return_value=['45.155.205.10', '185.220.101.0/28'])
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_outbound_preventive_list_blocks_internal_to_external_with_its_own_list(self):
        url = self.login()
        self.client.post(url, {'action': 'unifi_create', 'device': self.device.pk, 'direction': 'qout'})
        binding = UnifiBlocklistBinding.objects.get(direction='qout')
        [policy] = self.console.policy_posts
        self.assertEqual((policy['enabled'], policy['name']), (False, 'SOC Bloqueo preventivo salida Q-Feeds Internal→External'))
        self.assertEqual((policy['source']['zoneId'], policy['destination']['zoneId']), (ZONES['Internal'], ZONES['External']))
        self.assertEqual(policy['destination']['trafficFilter']['ipAddressFilter']['trafficMatchingListId'], binding.list_id)
        self.assertNotIn('trafficFilter', policy['source'])
        self.assertEqual(unifi_blocklist.desired(binding), ['185.220.101.0/28', '45.155.205.10'])
        self.client.post(url, {'action': 'unifi_policy_enable', 'binding': binding.pk})
        ChangePlan.objects.all().delete()
        self.assertIn('UDM-BCM', client_protection(self.company)['preventive']['firewalls'])

    def test_needs_the_preventive_option(self):
        BlocklistFeed.objects.filter(pk=self.feed.pk).update(qfeeds_preventive=False)
        url = self.login()
        response = self.client.post(url, {'action': 'unifi_create', 'device': self.device.pk, 'direction': 'qout'})
        self.assertContains(response, 'Activa primero la lista preventiva')
        self.assertFalse(UnifiBlocklistBinding.objects.exists())

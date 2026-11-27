"""DNS del SOC por la VPN de sedes: zonas por cliente, acceso solo de sus sedes, freno y recuento."""
import subprocess
import tempfile
from pathlib import Path
from unittest import mock

from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from . import dns_resolver, qfeeds_distribution, vpn
from .blocklist_efficacy import client_protection
from .models import BlocklistFeed, Client, Device, Site, VpnPeer, WorkerState

DOMAINS = ['malo.example.com', 'c2.example.net']


def peer(site, address, **extra):
    return VpnPeer.objects.create(site=site, address=address, public_key='k' * 43 + address[-1], encrypted_private_key='x',
                                  encrypted_preshared_key='x', enabled=True, **extra)


class Base(TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        (root / 'conf').mkdir()
        for name, value in (('CONF_DIR', root / 'conf'), ('ZONE_DIR', root / 'zones')):
            patcher = mock.patch.object(dns_resolver, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.conf, self.zones = root / 'conf', root / 'zones'
        self.company = Client.objects.create(name='Oficinas', code='o')
        self.other = Client.objects.create(name='Otra', code='x')
        self.site = Site.objects.create(client=self.company, name='Inca', code='i')
        self.other_site = Site.objects.create(client=self.other, name='Palma', code='p')
        Device.objects.create(site=self.site, name='GCC-Inca', vendor='grandstream_gcc')
        self.peer = peer(self.site, '10.255.251.5', status='connected')
        peer(self.other_site, '10.255.251.6')
        self.feed = BlocklistFeed.objects.create(client=self.company, enabled=True, qfeeds_dns=True, dns_resolver=True,
                                                 dns_count=2)
        BlocklistFeed.objects.create(client=self.other, enabled=True, qfeeds_dns=True)
        self.domains = list(DOMAINS)
        patcher = mock.patch.object(qfeeds_distribution, 'servable_dns', side_effect=lambda feed: list(self.domains))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.commands = []

    def fake_run(self, args, **kwargs):
        self.commands.append(args)
        if args[0] == 'journalctl':
            return subprocess.CompletedProcess(args, 0, stdout=self.journal, stderr='')
        return subprocess.CompletedProcess(args, 0, stdout='', stderr='')

    journal = '-- cursor: c1\n'

    def sync(self, now=None):
        with mock.patch.object(dns_resolver.subprocess, 'run', side_effect=self.fake_run):
            return dns_resolver.synchronize(now)


class GenerationTests(Base):
    def test_does_nothing_without_the_soc_unbound(self):
        details = self.sync()
        self.assertFalse(details['configured'])
        self.assertEqual(self.commands, [])

    def test_only_enabled_clients_and_their_sites_get_a_zone(self):
        (self.conf / 'soc-base.conf').write_text('server:\n')
        details = self.sync()
        self.assertTrue(details['configured'])
        conf = (self.conf / 'soc-qfeeds.conf').read_text()
        name = f'soc-c{self.company.pk}'
        self.assertIn('access-control: 10.255.251.5/32 allow', conf)
        self.assertIn(f'access-control-tag: 10.255.251.5/32 "{name}"', conf)
        self.assertNotIn('10.255.251.6', conf, 'la sede de un cliente sin DNS del SOC no tiene acceso')
        zone = (self.zones / f'{name}.rpz').read_text()
        self.assertIn(f'$ORIGIN {name}.', zone)
        self.assertIn('malo.example.com CNAME .', zone)
        self.assertEqual(self.commands[:2], [['unbound-checkconf'], ['unbound-control', 'reload']])
        # Sin cambios no se recarga.
        self.commands.clear()
        self.sync()
        self.assertNotIn(['unbound-control', 'reload'], self.commands)

    def test_brake_empties_the_zone_but_keeps_the_site_resolving(self):
        (self.conf / 'soc-base.conf').write_text('server:\n')
        self.sync()
        BlocklistFeed.objects.filter(pk=self.feed.pk).update(stopped=True)
        self.sync()
        name = f'soc-c{self.company.pk}'
        self.assertNotIn('CNAME', (self.zones / f'{name}.rpz').read_text())
        self.assertIn('10.255.251.5/32 allow', (self.conf / 'soc-qfeeds.conf').read_text())
        BlocklistFeed.objects.filter(pk=self.feed.pk).update(stopped=False, dns_resolver=False)
        self.sync()
        self.assertNotIn('10.255.251.5', (self.conf / 'soc-qfeeds.conf').read_text())
        self.assertFalse((self.zones / f'{name}.rpz').exists())

    def test_rejected_configuration_is_restored(self):
        (self.conf / 'soc-base.conf').write_text('server:\n')
        self.sync()
        good = (self.conf / 'soc-qfeeds.conf').read_text()
        self.peer.address = '10.255.251.9'
        self.peer.save()

        def reject(args, **kwargs):
            if args == ['unbound-checkconf']:
                raise subprocess.CalledProcessError(1, args)
            return self.fake_run(args, **kwargs)
        with mock.patch.object(dns_resolver.subprocess, 'run', side_effect=reject):
            details = dns_resolver.synchronize()
        self.assertIn('no aceptó', details['error'])
        self.assertEqual((self.conf / 'soc-qfeeds.conf').read_text(), good)

    def test_blocked_queries_are_counted_per_client_and_the_cursor_only_moves_on_success(self):
        (self.conf / 'soc-base.conf').write_text('server:\n')
        name = f'soc-c{self.company.pk}'
        self.journal = (f'info: rpz: applied [{name}] malo.example.com. nxdomain 10.255.251.5@5353 malo.example.com. A IN\n'
                        f'info: rpz: applied [{name}] c2.example.net. nxdomain 10.255.251.5@5353 c2.example.net. A IN\n'
                        'info: otra línea\n-- cursor: c2\n')
        details = self.sync()
        self.assertEqual(details['cursor'], 'c2')
        state = WorkerState.objects.get(name=f'dns-resolver:{self.company.pk}')
        self.assertEqual(sum(state.details['history'].values()), 2)

        def broken(args, **kwargs):
            if args[0] == 'journalctl':
                raise subprocess.TimeoutExpired(args, 1)
            return self.fake_run(args, **kwargs)
        with mock.patch.object(dns_resolver.subprocess, 'run', side_effect=broken):
            details = dns_resolver.synchronize()
        self.assertEqual(details['cursor'], 'c2')
        self.assertTrue(details['journal_error'])
        data = client_protection(self.company)
        self.assertEqual({k: data['dns'][k] for k in ('queries', 'measured')}, {'queries': 2, 'measured': True})
        self.assertIn('Inca (DNS del SOC)', data['dns']['firewalls'])


class VpnRuleTests(Base):
    def test_nft_rules_open_dns_only_for_enabled_sites(self):
        rules = vpn.dns_rules()
        self.assertIn('ip saddr { 10.255.251.5 }', rules)
        self.assertNotIn('10.255.251.6', rules)
        self.assertIn('udp dport 53 accept', rules)
        self.assertIn('tcp dport 53 accept', rules)
        BlocklistFeed.objects.filter(pk=self.feed.pk).update(dns_resolver=False)
        self.assertEqual(vpn.dns_rules(), '', 'sin clientes con DNS del SOC las reglas no cambian')


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False, SOC_PUBLIC_ORIGIN='https://soc.example.test')
class PageTests(Base):
    def test_client_page_shows_status_and_the_gcc_guide(self):
        from django.contrib.auth import get_user_model
        admin = get_user_model().objects.create_superuser('admin', 'a@example.test', 'x')
        self.client.force_login(admin)
        page = self.client.get(reverse('blocklist_detail', args=[self.company.pk]))
        self.assertContains(page, 'DNS del SOC por la VPN de sedes')
        self.assertContains(page, 'deploy/configurar_dns_soc.sh --instalar')
        self.assertContains(page, 'Conectada')
        self.assertContains(page, 'VPN Static DNS')
        (self.conf / 'soc-base.conf').write_text('server:\n')
        self.sync(timezone.now())
        page = self.client.get(reverse('blocklist_detail', args=[self.company.pk]))
        self.assertNotContains(page, 'deploy/configurar_dns_soc.sh --instalar')

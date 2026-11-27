"""Modo guiado: Hillstone con listas por URL y comprobación de qué equipo descarga cada lista."""
import time
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from . import blocklist
from .models import BlocklistFeed, Client, Device, ExportConfiguration, Site, StaffAccess
from .vendor_capabilities import capability, for_device

HS_IP, OTHER_IP = '203.0.113.7', '198.51.100.20'


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False, SOC_PUBLIC_ORIGIN='https://soc.example.test',
                   SOC_TRUSTED_PROXIES=[])
class GuidedListsTests(TestCase):
    def setUp(self):
        self.company = Client.objects.create(name='Talleres', code='t')
        site = Site.objects.create(client=self.company, name='Palma', code='p')
        self.hillstone = Device.objects.create(site=site, name='HS-Palma', vendor='hillstone')
        ExportConfiguration.objects.create(device=self.hillstone, source_ip=HS_IP)
        self.feed = BlocklistFeed.objects.create(client=self.company, enabled=True, generated_at=timezone.now(),
                                                 outbound_enabled=True, entries=[{'ip': '45.155.205.10', 'reasons': ['x']}])
        self.token = blocklist.rotate_token(self.feed)

    def fetch(self, name='blocklist_serve', ip=HS_IP):
        return self.client.get(reverse(name, args=[self.company.pk, self.token]), REMOTE_ADDR=ip)

    def test_each_list_records_who_downloads_it_and_maps_the_device(self):
        self.assertEqual(self.fetch().content, b'45.155.205.10\n')
        self.fetch('blocklist_serve_out', OTHER_IP)
        self.feed.refresh_from_db()
        self.assertEqual(set(self.feed.fetch_sources), {'in', 'out'})
        rows = {(r['kind'], r['ip']): r['devices'] for r in blocklist.fetch_rows(self.feed)}
        self.assertEqual(rows, {('in', HS_IP): ['HS-Palma'], ('out', OTHER_IP): []})
        # Un token anterior o equivocado no anota nada.
        self.client.get(reverse('blocklist_serve', args=[self.company.pk, 'malo']), REMOTE_ADDR='192.0.2.50')
        self.feed.refresh_from_db()
        self.assertNotIn('192.0.2.50', str(self.feed.fetch_sources))

    def test_only_the_ten_most_recent_addresses_are_kept(self):
        for index in range(12):
            self.fetch(ip=f'198.51.100.{index + 1}')
        self.feed.refresh_from_db()
        kept = self.feed.fetch_sources['in']
        self.assertEqual(len(kept), blocklist.FETCH_SOURCES_PER_LIST)
        self.assertNotIn('198.51.100.1', kept)

    def test_hillstone_is_guided_with_steps_and_the_download_is_checked(self):
        self.assertEqual(capability('hillstone', 'blocklist')[0], 'guided')
        self.assertEqual(capability('hillstone', 'dns')[0], 'pending')
        self.assertEqual(for_device(self.hillstone, 'blocklist_out')[0], 'guided')
        admin = get_user_model().objects.create_superuser('admin', 'a@example.test', 'x')
        StaffAccess.objects.create(user=admin, role='manager', all_clients=True)
        self.client.force_login(admin)
        session = self.client.session
        session.update({'soc_mfa_user': admin.pk, 'soc_mfa_at': time.time()})
        session.save()
        url = reverse('blocklist_detail', args=[self.company.pk])
        page = self.client.get(url)
        self.assertContains(page, 'Perimeter Traffic Filtering')
        self.assertContains(page, 'External Dynamic List')
        self.assertContains(page, 'Aún no consta ninguna descarga desde la IP conocida de este equipo.')
        self.fetch()
        page = self.client.get(url)
        self.assertContains(page, 'Descarga comprobada desde este equipo')
        self.assertContains(page, HS_IP)

    def test_stopped_list_still_records_the_download(self):
        BlocklistFeed.objects.filter(pk=self.feed.pk).update(stopped=True, stopped_at=timezone.now() - timedelta(minutes=1))
        self.assertEqual(self.fetch().content, b'')
        self.feed.refresh_from_db()
        self.assertIn(HS_IP, self.feed.fetch_sources['in'])


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False, SOC_PUBLIC_ORIGIN='https://soc.example.test')
class GrandstreamCapabilityTests(TestCase):
    def test_gcc_lists_are_not_offered_and_the_page_says_why(self):
        self.assertEqual({capability('grandstream_gcc', f)[0] for f in ('blocklist', 'blocklist_out', 'preventive', 'measure')},
                         {'unavailable'})
        self.assertEqual(capability('grandstream_gcc', 'dns')[0], 'guided')
        company = Client.objects.create(name='Oficinas', code='o')
        site = Site.objects.create(client=company, name='Inca', code='i')
        gcc = Device.objects.create(site=site, name='GCC-Inca', vendor='grandstream_gcc')
        self.assertEqual(for_device(gcc, 'blocklist'), capability('grandstream_gcc', 'blocklist'))
        BlocklistFeed.objects.create(client=company, enabled=True)
        admin = get_user_model().objects.create_superuser('admin', 'a@example.test', 'x')
        self.client.force_login(admin)
        page = self.client.get(reverse('blocklist_detail', args=[company.pk]))
        self.assertContains(page, 'GCC-Inca')
        self.assertContains(page, 'capability-unavailable')
        self.assertContains(page, 'no descarga listas de IPs por URL')
        self.assertNotContains(page, 'Aún no consta ninguna descarga')

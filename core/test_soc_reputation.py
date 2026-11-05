"""Reputación propia del SOC (observación): niveles, frenos, medida preventiva, página y permisos."""
from datetime import timedelta
from itertools import count

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from . import soc_reputation
from .background_jobs import JOBS
from .models import (Client, Device, ExportConfiguration, IpReputation, SecurityEvidence, Site, SocReputation, StaffAccess,
                     ThreatIndicator, WorkerState)

EXPLOITER = '45.155.205.10'
SCANNER = '91.92.240.5'
ONE_DAY = '185.220.101.33'
UDP_ONLY = '94.102.49.7'
PARTNER = '81.0.0.5'
LONELY = '62.210.10.4'
OLD = '193.32.162.8'
NOISY = '80.82.77.33'
LISTED = '141.98.11.20'
QFEEDS = '87.120.84.9'


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class SocReputationTests(TestCase):
    def setUp(self):
        self.now = timezone.now()
        self.uid = count()
        self.clients, self.devices = [], []
        for index in range(4):
            client = Client.objects.create(name=f'Cliente {index}', code=f'c{index}')
            self.clients.append(client)
            self.devices.append(Device.objects.create(site=Site.objects.create(client=client, name='Sede', code=f's{index}'),
                                                      name=f'FW-{index}', vendor='opnsense'))
        ExportConfiguration.objects.create(device=self.devices[3], source_ip=PARTNER)
        day1, day2 = self.now - timedelta(days=3), self.now - timedelta(days=1)
        self.attack(EXPLOITER, 0, day1, family='intrusion', action='allowed')
        self.attack(EXPLOITER, 1, day2, family='intrusion')
        for client, when in ((0, day1), (1, day2), (2, day2)):
            self.attack(SCANNER, client, when, family='scan')
        for client in (0, 1, 2):
            self.attack(ONE_DAY, client, day2, family='scan')
            self.attack(UDP_ONLY, client, day1 if client else day2, family='intrusion', protocol='UDP')
            self.attack(PARTNER, client, day1 if client else day2, family='intrusion')
        self.attack(LONELY, 0, day1, family='intrusion', events=5)
        self.attack(LONELY, 0, day2, family='intrusion', events=5)
        self.attack(OLD, 0, self.now - timedelta(days=20), family='intrusion')
        self.attack(OLD, 1, self.now - timedelta(days=18), family='intrusion')
        self.attack(NOISY, 0, day1, family='intrusion')
        self.attack(NOISY, 1, day2, family='intrusion')
        IpReputation.objects.create(ip=NOISY, cti_found=True, reputation='malicious', background_noise='high', cti_checked_at=self.now)
        self.attack(LISTED, 0, day1, family='intrusion')
        self.attack(LISTED, 1, day2, family='intrusion')
        IpReputation.objects.create(ip=LISTED, listed=True, lists_checked_at=self.now)
        self.attack(QFEEDS, 0, day1, family='intrusion')
        self.attack(QFEEDS, 1, day2, family='intrusion')
        ThreatIndicator.objects.create(feed='malware_ip', kind='ip', value=QFEEDS)
        WorkerState.objects.create(name='threat-intel', details={'configured': True, 'feeds': {'malware_ip': {
            'licensed': True, 'ready': True, 'checked_at': self.now.isoformat()}}})

    def attack(self, ip, client, when, family='intrusion', protocol='TCP', action='blocked', events=2):
        device = self.devices[client]
        for _ in range(events):
            SecurityEvidence.objects.create(uid=f'{next(self.uid):064x}', device=device, observed_at=when, engine='suricata',
                                            signature='Firma', source_ip=ip, destination_ip='10.0.0.5', action=action, level=8,
                                            client_scope_id=device.site.client_id, flow={'protocol': protocol},
                                            interpretation={'event_family': family})

    def levels(self):
        return dict(SocReputation.objects.values_list('ip', 'level'))

    def test_levels_follow_the_criteria_and_the_brakes(self):
        self.assertEqual(soc_reputation.refresh(self.now), 4)
        levels = self.levels()
        self.assertEqual(levels[EXPLOITER], 'own')
        self.assertEqual(levels[SCANNER], 'own')
        self.assertEqual(levels[ONE_DAY], 'watch')
        self.assertEqual(levels[OLD], 'watch')
        self.assertEqual(levels[NOISY], 'watch')
        self.assertEqual(levels[LISTED], 'confirmed')
        self.assertEqual(levels[QFEEDS], 'confirmed')
        for excluded in (UDP_ONLY, PARTNER, LONELY):
            self.assertNotIn(excluded, levels)
        row = SocReputation.objects.get(ip=EXPLOITER)
        self.assertEqual((row.clients, row.strong_clients, row.days, row.events, row.allowed, row.families),
                         (2, 2, 2, 4, 2, ['intrusion']))
        self.assertEqual(SocReputation.objects.get(ip=LISTED).sources, ['crowdsec'])
        self.assertEqual(SocReputation.objects.get(ip=QFEEDS).sources, ['qfeeds'])
        self.assertIn('14 días', SocReputation.objects.get(ip=OLD).note)

    def test_later_attacks_on_new_clients_are_measured(self):
        soc_reputation.refresh(self.now)
        flagged = SocReputation.objects.get(ip=EXPLOITER)
        self.assertEqual((flagged.flagged_clients, flagged.later_clients), ([self.clients[0].pk, self.clients[1].pk], []))
        later = self.now + timedelta(hours=2)
        self.attack(EXPLOITER, 2, later - timedelta(minutes=5))
        soc_reputation.refresh(later)
        row = SocReputation.objects.get(ip=EXPLOITER)
        self.assertEqual(row.flagged_at, flagged.flagged_at)
        self.assertEqual(row.later_clients, [self.clients[2].pk])
        self.assertEqual(SocReputation.objects.get(ip=ONE_DAY).flagged_at, None)

    def test_ips_that_stop_qualifying_are_removed(self):
        soc_reputation.refresh(self.now)
        soc_reputation.refresh(self.now + timedelta(days=31))
        self.assertFalse(SocReputation.objects.exists())

    def test_page_requires_global_access_and_shows_the_measure(self):
        soc_reputation.refresh(self.now)
        SocReputation.objects.filter(ip=EXPLOITER).update(flagged_at=self.now - timedelta(days=2), later_clients=[self.clients[2].pk])
        user = get_user_model().objects.create_user('analista')
        user.user_permissions.add(Permission.objects.get(codename='manage_operations'))
        access = StaffAccess.objects.create(user=user, role='operator')
        access.clients.add(self.clients[0])
        self.client.force_login(user)
        self.assertEqual(self.client.get(reverse('soc_reputation')).status_code, 403)
        access.all_clients = True
        access.save()
        page = self.client.get(reverse('soc_reputation'))
        self.assertContains(page, EXPLOITER)
        self.assertContains(page, '1 cliente más')
        self.assertContains(page, '(100 %) atacaron después')
        self.assertNotContains(page, ONE_DAY)
        self.assertContains(self.client.get(reverse('soc_reputation'), {'nivel': 'watch'}), ONE_DAY)

    def test_ip_investigation_shows_it_only_with_global_access(self):
        soc_reputation.refresh(self.now)
        user = get_user_model().objects.create_user('global')
        access = StaffAccess.objects.create(user=user, role='operator', all_clients=True)
        self.client.force_login(user)
        url = reverse('ip_investigation')
        self.assertContains(self.client.get(url, {'ip': EXPLOITER, 'days': 7}), 'Reputación propia del SOC')
        access.all_clients = False
        access.save()
        access.clients.add(self.clients[0])
        self.assertNotContains(self.client.get(url, {'ip': EXPLOITER, 'days': 7}), 'Reputación propia del SOC')

    def test_job_is_registered(self):
        self.assertIn('soc_reputation', JOBS)
        from .background_jobs import execute
        self.assertEqual(execute('soc_reputation'), SocReputation.objects.filter(level__in=('own', 'confirmed')).count())

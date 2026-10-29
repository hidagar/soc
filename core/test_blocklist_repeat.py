"""Lista de bloqueo: atacantes repetidos que CrowdSec no conoce y eficacia de las políticas UniFi."""
from datetime import timedelta
from itertools import count

from django.test import override_settings

from .blocklist import refresh_feeds
from .models import IpReputation, SecurityEvidence
from .test_blocklist import ALLOWED_BY_CLIENT, HERE, FeedTestCase

REPEAT, ONE_DAY, NOISY = '103.145.13.9', '61.177.172.60', '162.142.125.11'
_uid = count(10_000)


@override_settings(SECURE_SSL_REDIRECT=False)
class RepeatAttackerTests(FeedTestCase):
    def hit(self, ip, days_ago, action='blocked', times=1):
        for _ in range(times):
            SecurityEvidence.objects.create(uid=f'{next(_uid):064x}', device=self.device,
                                            observed_at=self.now - timedelta(days=days_ago, hours=1), engine='suricata',
                                            signature='ET SCAN', source_ip=ip, destination_ip='10.0.0.5', action=action,
                                            level=8, client_scope_id=self.rosello.pk)

    def setUp(self):
        super().setUp()
        self.hit(REPEAT, 1, times=3)
        self.hit(REPEAT, 3, action='allowed', times=2)   # 5 detecciones en 2 días: entra
        self.hit(ONE_DAY, 1, times=8)                     # muchas, pero un solo día: no entra
        self.hit(NOISY, 1, times=3)
        self.hit(NOISY, 2, times=3)                       # ruido de fondo según la CTI: no entra
        IpReputation.objects.create(ip=NOISY, cti_found=True, reputation='suspicious', background_noise='high',
                                    cti_checked_at=self.now)
        self.hit(ALLOWED_BY_CLIENT, 1, times=3)
        self.hit(ALLOWED_BY_CLIENT, 2, times=3)           # excepción del cliente: nunca
        self.hit(HERE, 2, times=5)                        # ya está por CrowdSec: suma el motivo

    def entry(self, ip):
        self.feed.refresh_from_db()
        return next((e for e in self.feed.entries if e['ip'] == ip), None)

    def test_off_by_default(self):
        refresh_feeds(self.now)
        self.assertIsNone(self.entry(REPEAT))

    def test_repeated_attackers_join_with_their_reason(self):
        self.feed.include_repeat_attackers = True
        self.feed.save()
        refresh_feeds(self.now)
        entry = self.entry(REPEAT)
        self.assertEqual(entry['reasons'], ['Ataques repetidos a este cliente: 5 detecciones en 2 días'])
        self.assertEqual((entry['here'], entry['here_allowed']), (5, 2))
        for ip in (ONE_DAY, NOISY, ALLOWED_BY_CLIENT):
            self.assertIsNone(self.entry(ip), ip)
        here = self.entry(HERE)
        self.assertEqual(here['reasons'][0], 'Lista comunitaria')
        self.assertTrue(here['reasons'][-1].startswith('Ataques repetidos a este cliente'))

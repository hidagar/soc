"""Reputación propia del SOC en las listas de bloqueo y reputación de los orígenes en el portal del cliente."""
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from .blocklist import refresh_feeds, servable
from .models import (BlocklistFeed, Client, Device, IpReputation, SecurityEvidence, Site, SocReputation, StaffAccess,
                     ThreatIntelMatch)

REPEAT = '45.155.205.20'    # ataca a otros clientes, todavía no a este
HERE = '45.155.205.21'      # ataca a este cliente y figura en CrowdSec
NOISE = '45.155.205.22'


def reputation(ip, level='own', clients=3, age=timedelta(minutes=10), now=None):
    now = now or timezone.now()
    return SocReputation.objects.create(ip=ip, level=level, score=40, clients=clients, strong_clients=2, days=3, events=12,
                                        first_seen=now - timedelta(days=5), last_seen=now - timedelta(hours=1),
                                        updated_at=now - age)


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class Base(TestCase):
    def setUp(self):
        self.now = timezone.now()
        self.company = Client.objects.create(name='Talleres', code='t', customer_portal_detail_enabled=True)
        self.other = Client.objects.create(name='Otra empresa', code='o')
        self.device = Device.objects.create(site=Site.objects.create(client=self.company, name='Palma', code='p'),
                                            name='FW-Palma', vendor='opnsense')
        self.feed = BlocklistFeed.objects.create(client=self.company, enabled=True, include_cti=False)
        for index, ip in enumerate((HERE, NOISE)):
            SecurityEvidence.objects.create(uid=f'{index:064x}', device=self.device, observed_at=self.now - timedelta(hours=2),
                                            engine='suricata', signature='ET SCAN', source_ip=ip, destination_ip='10.0.0.5',
                                            action='blocked', level=8, client_scope_id=self.company.pk,
                                            geography={'direction': 'inbound', 'status': 'located', 'country': 'NL'})

    def entries(self):
        refresh_feeds(self.now)
        self.feed.refresh_from_db()
        return {e['ip']: e for e in self.feed.entries}


class BlocklistReputationTests(Base):
    def test_new_and_existing_lists_have_the_option_on(self):
        self.assertTrue(BlocklistFeed.objects.create(client=self.other).include_soc_reputation)
        self.assertTrue(self.feed.include_soc_reputation)

    def test_blockable_reputation_enters_even_if_it_has_not_attacked_this_client(self):
        reputation(REPEAT, 'confirmed', clients=4)
        entries = self.entries()
        self.assertIn(REPEAT, entries)
        entry = entries[REPEAT]
        self.assertEqual((entry['sources'], entry['here'], entry['clients']), (['soc'], 0, 4))
        self.assertIn('Reputación del SOC: ataca a 4 clientes (confirmada', entry['reasons'][0])
        self.assertIn(REPEAT, servable(self.feed, self.now))

    def test_watch_level_stale_data_exceptions_and_disabled_option_keep_it_out(self):
        reputation(REPEAT, 'watch')
        self.assertNotIn(REPEAT, self.entries())
        SocReputation.objects.all().delete()
        reputation(REPEAT, 'own', age=timedelta(hours=3))
        self.assertNotIn(REPEAT, self.entries(), 'cálculo de más de 2 horas: no es motivo para bloquear')
        SocReputation.objects.all().delete()
        reputation(REPEAT, 'own')
        BlocklistFeed.objects.filter(pk=self.feed.pk).update(allowlist=REPEAT)
        self.assertNotIn(REPEAT, self.entries())
        BlocklistFeed.objects.filter(pk=self.feed.pk).update(allowlist='', include_soc_reputation=False)
        self.assertNotIn(REPEAT, self.entries())

    def test_reputation_adds_its_reason_to_an_existing_entry(self):
        IpReputation.objects.create(ip=HERE, listed=True, lists_checked_at=self.now)
        reputation(HERE, 'confirmed')
        entry = self.entries()[HERE]
        self.assertEqual(entry['sources'], ['crowdsec', 'soc'])
        self.assertTrue(any(r.startswith('Reputación del SOC') for r in entry['reasons']))


class CustomerReputationTests(Base):
    def setUp(self):
        super().setUp()
        IpReputation.objects.create(ip=HERE, listed=True, lists_checked_at=self.now, list_scenarios=['ssh-bf-ESCENARIO'])
        IpReputation.objects.create(ip=NOISE, cti_found=True, reputation='malicious', cti_checked_at=self.now,
                                    background_noise='high', false_positives=['cdn'])
        reputation(HERE, 'confirmed', clients=7)
        ThreatIntelMatch.objects.create(client=self.other, ip=NOISE, role='source', first_seen=self.now, last_seen=self.now)
        ThreatIntelMatch.objects.create(client=self.company, ip=HERE, role='source', first_seen=self.now, last_seen=self.now)
        customer = get_user_model().objects.create_user('cliente')
        StaffAccess.objects.create(user=customer, role='customer').clients.add(self.company)
        self.client.force_login(customer)

    def test_detections_show_only_the_published_labels(self):
        page = self.client.get(reverse('customer_detections'))
        self.assertContains(page, 'En listas de bloqueo de CrowdSec')
        self.assertContains(page, 'En listas de amenazas de Q-Feeds')
        self.assertContains(page, 'Ataca también a otras empresas del servicio')
        for secret in ('ssh-bf-ESCENARIO', 'Otra empresa', '7 clientes', 'cdn'):
            self.assertNotContains(page, secret)

    def test_possible_false_positive_has_no_crowdsec_label_and_other_clients_matches_do_not_leak(self):
        from .customer_portal import reputation_labels
        labels = reputation_labels(self.company, [HERE, NOISE, '10.0.0.5'])
        self.assertNotIn(NOISE, labels, 'posible falso positivo y la coincidencia de Q-Feeds es de otro cliente')
        self.assertNotIn('10.0.0.5', labels)
        self.assertEqual([label for label, _ in labels[HERE]],
                         ['En listas de bloqueo de CrowdSec', 'En listas de amenazas de Q-Feeds',
                          'Ataca también a otras empresas del servicio'])

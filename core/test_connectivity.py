"""Conexión a Internet por sede: caídas notificadas por el firewall, sin inventar duraciones."""
from datetime import date, datetime, timedelta
from datetime import timezone as dt_timezone

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from . import connectivity
from .models import (Client, ConnectivityEvent, Device, ExportConfiguration, Site, SourceOwnership, StaffAccess, WeeklyReport,
                     WorkerState)

UNIFI_IP = '81.0.0.10'
OTHER_IP = '81.0.0.20'


def hit(index, name, when, location=UNIFI_IP):
    return {'_index': 'wazuh-alerts-1', '_id': str(index), 'sort': [index],
            '_source': {'timestamp': when.isoformat(), 'location': location, 'data': {'unifi': {'event_name': name}}}}


class FakeIndexer:
    def __init__(self, hits, timed_out=False):
        self.hits, self.timed_out, self.bodies = hits, timed_out, []

    def __call__(self, body):
        self.bodies.append(body)
        return {'timed_out': self.timed_out, '_shards': {'failed': 0}, 'hits': {'hits': self.hits}}


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class ConnectivityTests(TestCase):
    def setUp(self):
        self.now = timezone.now()
        self.company = Client.objects.create(name='Empresa A', code='a')
        self.palma = Site.objects.create(client=self.company, name='Palma', code='palma')
        self.inca = Site.objects.create(client=self.company, name='Inca', code='inca')
        self.udm = Device.objects.create(site=self.palma, name='UDM-Palma', vendor='unifi')
        self.opn = Device.objects.create(site=self.inca, name='FW-Inca', vendor='opnsense')
        ExportConfiguration.objects.create(device=self.udm, source_ip=UNIFI_IP, receiver_ready=True)
        ExportConfiguration.objects.create(device=self.opn, source_ip=OTHER_IP, receiver_ready=True)
        # La propiedad del origen se crea con la exportación; se adelanta para cubrir los eventos de prueba.
        SourceOwnership.objects.filter(source__in=(UNIFI_IP, OTHER_IP)).update(valid_from=self.now - timedelta(days=20))
        self.assertEqual(SourceOwnership.objects.filter(client_scope_id=self.company.pk).count(), 2)

    def test_outages_are_saved_once_and_assigned_to_their_firewall(self):
        indexer = FakeIndexer([hit(1, 'Internet Down', self.now - timedelta(days=2)),
                               hit(2, 'Multiple Internet Disconnections', self.now - timedelta(days=1)),
                               hit(3, 'Device Offline', self.now - timedelta(hours=5)),
                               hit(1, 'Internet Down', self.now - timedelta(days=2)),
                               hit(4, 'Threat Detected and Blocked', self.now - timedelta(hours=1)),
                               hit(5, 'Internet Down', self.now - timedelta(days=30))])
        self.assertEqual(connectivity.collect(self.now, search=indexer), 3)
        self.assertEqual(sorted(ConnectivityEvent.objects.values_list('kind', flat=True)), ['device_offline', 'internet_down', 'repeated'])
        self.assertEqual(set(ConnectivityEvent.objects.values_list('device_id', flat=True)), {self.udm.pk})
        self.assertEqual(connectivity.collect(self.now + timedelta(minutes=15), search=indexer), 0)

    def test_incomplete_query_does_not_move_the_cursor(self):
        with self.assertRaises(ValueError):
            connectivity.collect(self.now, search=FakeIndexer([hit(1, 'Internet Down', self.now)], timed_out=True))
        self.assertFalse(WorkerState.objects.filter(name=connectivity.STATE).exists())
        self.assertFalse(ConnectivityEvent.objects.exists())

    def test_next_run_starts_from_the_cursor_with_a_margin(self):
        connectivity.collect(self.now, search=FakeIndexer([]))
        indexer = FakeIndexer([])
        connectivity.collect(self.now + timedelta(minutes=15), search=indexer)
        start = indexer.bodies[0]['query']['bool']['filter'][1]['range']['timestamp']['gte']
        self.assertEqual(start, (self.now - connectivity.OVERLAP).isoformat())

    def test_summary_separates_no_outages_from_no_data(self):
        ConnectivityEvent.objects.create(client=self.company, device=self.udm, kind='internet_down',
                                         observed_at=self.now - timedelta(days=3), event_key='a')
        data = connectivity.last_days(self.company, now=self.now)
        rows = {r['firewall']: r for r in data['rows']}
        self.assertEqual((rows['UDM-Palma']['outages'], rows['UDM-Palma']['reports']), (1, True))
        self.assertFalse(rows['FW-Inca']['reports'])
        self.assertEqual((data['total'], data['reporting'], data['firewalls']), (1, 1, 2))

    def test_customer_portal_soc_page_and_monthly_report(self):
        ConnectivityEvent.objects.create(client=self.company, device=self.udm, kind='internet_down',
                                         observed_at=self.now - timedelta(days=3), event_key='a')
        customer = get_user_model().objects.create_user('cliente-a')
        StaffAccess.objects.create(user=customer, role='customer').clients.add(self.company)
        self.client.force_login(customer)
        self.assertNotContains(self.client.get(reverse('customer_home')), 'UDM-Palma')  # sin el detalle de firewalls activado
        Client.objects.filter(pk=self.company.pk).update(customer_portal_detail_enabled=True)
        home = self.client.get(reverse('customer_home'))
        self.assertContains(home, 'Conexión a Internet · 30 días')
        self.assertContains(home, '1 caída')
        self.assertContains(home, 'Este firewall no informa de caídas')
        staff = get_user_model().objects.create_user('operador')
        StaffAccess.objects.create(user=staff, role='operator', all_clients=True)
        self.client.force_login(staff)
        page = self.client.get(reverse('client_detail', args=[self.company.pk]))
        self.assertContains(page, 'Internet (30 d)')
        self.assertContains(page, 'No informa')
        from .monthly_report import customer_context
        ConnectivityEvent.objects.create(client=self.company, device=self.udm, kind='repeated',
                                         observed_at=datetime(2026, 10, 14, 10, tzinfo=dt_timezone.utc), event_key='b')
        for monday in (date(2026, 10, 5), date(2026, 10, 12), date(2026, 10, 19), date(2026, 10, 26)):
            WeeklyReport.objects.create(client=self.company, week_start=monday)
        october = customer_context(self.company, date(2026, 10, 1))['connectivity']
        self.assertEqual(october['total'], 1)
        self.assertNotIn('recent', october)

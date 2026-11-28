"""Agentes Linux: sistema del equipo, datos que llegan, estado sin Defender, portal e instrucciones de instalación."""
import time
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from . import endpoints
from .endpoints import platform_of
from .models import Client, EndpointAccessAlert, EndpointAgent, EndpointPolicyCheck, Site, StaffAccess
from .operations import ingest_events
from .test_endpoint_access import linux
from .test_endpoint_hardening import check
from .test_endpoint_integrity import fim
from .test_endpoints import alert as defender_alert


def heartbeat(stamp, ident, agent='007', location='/var/log/syslog'):
    """Un evento cualquiera del agente Linux (sin datos de seguridad)."""
    return {'timestamp': stamp.isoformat(), 'id': ident, 'location': location,
            'agent': {'id': agent, 'name': 'SRV-WEB', 'ip': '10.0.0.30'},
            'rule': {'id': '1002', 'level': 2, 'groups': ['syslog', 'errors'], 'description': 'Unknown problem'},
            'data': {}}


def as_agent(source, agent='007', name='SRV-WEB'):
    return {**source, 'agent': {'id': agent, 'name': name, 'ip': '10.0.0.30'}}


class PlatformTests(SimpleTestCase):
    def test_events_reveal_the_system(self):
        now = timezone.now()
        win_sca = check('1', 'passed', 'a', now)
        ubuntu_sca = check('1', 'passed', 'b', now)
        ubuntu_sca['data']['sca']['policy_id'] = 'cis_ubuntu22-04'
        mac_sca = check('1', 'passed', 'c', now)
        mac_sca['data']['sca']['policy_id'] = 'cis_apple_macOS_14.x'
        cases = [(defender_alert('1150'), 'windows'), (win_sca, 'windows'), (ubuntu_sca, 'linux'), (mac_sca, 'macos'),
                 (fim(r'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run', 'r', now, registry=True), 'windows'),
                 (fim(r'C:\Windows\System32\drivers\etc\hosts', 'h', now), 'windows'), (fim('/etc/hosts', 'l', now), ''),
                 (linux(['sshd', 'authentication_failed'], 's', now), 'linux'), (heartbeat(now, 'j', location='journald'), 'linux'),
                 ({'location': 'EventChannel', 'data': {}}, '')]
        for source, expected in cases:
            with self.subTest(expected=expected, location=source.get('location')):
                self.assertEqual(platform_of(source), expected)


class LinuxBase(TestCase):
    def setUp(self):
        self.now = timezone.now()
        self.company = Client.objects.create(name='Talleres Ejemplo', code='te', customer_endpoints_enabled=True)
        self.site = Site.objects.create(client=self.company, name='Palma', code='palma')

    def assign(self, hours=30):
        ingest_events([heartbeat(self.now - timedelta(hours=hours + 1), 'seed')], self.now)
        EndpointAgent.objects.update(status='assigned', client=self.company, site=self.site,
                                     assigned_at=self.now - timedelta(hours=hours))
        return EndpointAgent.objects.get()


class LinuxAgentTests(LinuxBase):
    def test_a_linux_agent_is_recognised_before_assignment_and_keeps_its_features(self):
        agent = self.assign()
        self.assertEqual(agent.platform, 'linux')
        stamp = self.now - timedelta(minutes=20)
        sca = as_agent(check('5001', 'failed', 'c1', stamp))
        sca['data']['sca'].update(policy_id='cis_ubuntu22-04', policy='CIS Ubuntu Linux 22.04 LTS Benchmark')
        events = [as_agent(linux(['syslog', 'sshd', 'authentication_failed'], f's{i}', stamp + timedelta(seconds=i)))
                  for i in range(5)] + [sca, as_agent(fim('/etc/sudoers.d/web', 'f1', stamp))]
        for event in events:
            event['agent']['id'] = '007'
        ingest_events(events, self.now)
        agent.refresh_from_db()
        self.assertEqual(EndpointAccessAlert.objects.get().kind, 'repeated')
        self.assertEqual(EndpointPolicyCheck.objects.get().result, 'failed')
        self.assertTrue(agent.file_changes.exists())
        self.assertEqual((agent.auth_seen_at, agent.sca_seen_at, agent.fim_seen_at), (stamp, stamp, stamp))
        self.assertEqual(endpoints.state(agent, self.now), ('other_os', 'Sin Defender (Linux)'))
        self.assertFalse(endpoints.auth_missing(agent, self.now))

    def test_a_windows_event_wins_over_an_earlier_guess(self):
        agent = self.assign()
        ingest_events([defender_alert('1150', agent='007', stamp=self.now - timedelta(minutes=5), ident='w')], self.now)
        agent.refresh_from_db()
        self.assertEqual(agent.platform, 'windows')
        ingest_events([heartbeat(self.now - timedelta(minutes=1), 'l2')], self.now)
        agent.refresh_from_db()
        self.assertEqual(agent.platform, 'windows')
        self.assertEqual(endpoints.state(agent, self.now)[0], 'unknown')  # Windows sin informe de salud reciente

    def test_signal_dates_are_written_at_most_once_an_hour(self):
        self.assign()
        stamp = self.now - timedelta(minutes=80)
        first = [as_agent(linux(['sshd', 'authentication_failed'], 'a', stamp))]
        ingest_events(first, self.now)
        ingest_events([as_agent(linux(['sshd', 'authentication_failed'], 'b', stamp + timedelta(minutes=30)))], self.now)
        self.assertEqual(EndpointAgent.objects.get().auth_seen_at, stamp)
        ingest_events([as_agent(linux(['sshd', 'authentication_failed'], 'c', stamp + timedelta(minutes=61)))], self.now)
        self.assertEqual(EndpointAgent.objects.get().auth_seen_at, stamp + timedelta(minutes=61))

    def test_missing_access_logs_are_flagged_only_for_reporting_assigned_agents(self):
        agent = self.assign(hours=30)
        ingest_events([heartbeat(self.now - timedelta(minutes=5), 'hb')], self.now)
        agent.refresh_from_db()
        self.assertTrue(endpoints.auth_missing(agent, self.now))
        self.assertFalse(endpoints.auth_missing(agent, self.now + timedelta(days=4)))  # sin informar: otro estado
        recent = self.assign(hours=2)
        self.assertFalse(endpoints.auth_missing(recent, self.now))

    def test_linux_without_defender_does_not_count_as_needing_attention(self):
        self.assign()
        summary = endpoints.client_summary(self.company, self.now)
        self.assertEqual((summary['total'], summary['protected'], summary['attention']), (1, 0, 0))
        portal = endpoints.portal_summary(self.company, self.now)
        self.assertEqual(portal['attention'], 0)
        [device] = endpoints.customer_context(self.company, now=self.now)['devices']
        self.assertEqual((device['state'], device['tone']), ('Sin antivirus vigilado (Linux o macOS)', 'paused'))


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class PageTests(LinuxBase):
    def test_soc_page_shows_the_system_and_the_data_that_arrives(self):
        self.assign()
        ingest_events([heartbeat(self.now - timedelta(minutes=5), 'hb')], self.now)
        user = get_user_model().objects.create_user('analista')
        StaffAccess.objects.create(user=user, role='operator', all_clients=True)
        user.user_permissions.add(Permission.objects.get(codename='manage_operations'))
        self.client.force_login(user)
        session = self.client.session
        session.update({'soc_mfa_user': user.pk, 'soc_mfa_at': time.time()})
        session.save()
        page = self.client.get(reverse('endpoints'))
        self.assertContains(page, 'agente 007 · Linux')
        self.assertContains(page, 'Sin Defender (Linux)')
        self.assertContains(page, 'Sin registros de acceso')


class BackfillTests(TestCase):
    def test_existing_agents_get_their_system_from_stored_data(self):
        import importlib
        from django.apps import apps
        from .models import EndpointPolicy
        migration = importlib.import_module('core.migrations.0097_agentes_linux')
        now = timezone.now()
        windows = EndpointAgent.objects.create(agent_id='1', name='PC', defender_seen_at=now)
        server = EndpointAgent.objects.create(agent_id='2', name='SRV')
        unknown = EndpointAgent.objects.create(agent_id='3', name='X')
        EndpointPolicy.objects.create(agent=server, client_scope_id=1, policy_id='cis_rhel9_linux')
        migration.backfill_platform(apps, None)
        self.assertEqual([EndpointAgent.objects.get(pk=a.pk).platform for a in (windows, server, unknown)],
                         ['windows', 'linux', ''])

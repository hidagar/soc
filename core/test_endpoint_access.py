"""Accesos fallidos a los equipos (Windows, SSH, sudo): ráfagas, gravedad, avisos, revisión, portal y recuperación."""
import time
from datetime import timedelta
from unittest import mock

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from . import endpoint_access, endpoints
from .models import (Client, EndpointAccessAlert, EndpointAccessEvent, EndpointAgent, Incident, Site, StaffAccess,
                     UrgentAlert, WorkerState)
from .operations import ingest_events
from .test_endpoints import alert as defender_alert

PUBLIC = '45.155.205.10'
INTERNAL = '10.0.0.40'
WIN_FAIL = ['windows', 'windows_security', 'authentication_failed']


def win(event_id, user='ana.garcia', ip=PUBLIC, ident='1', stamp=None, rule='60122', groups=WIN_FAIL, agent='003', level=5):
    return {'timestamp': (stamp or timezone.now()).isoformat(), 'id': ident, 'location': 'EventChannel',
            'agent': {'id': agent, 'name': 'SRV-CONTA', 'ip': '10.0.0.25'},
            'rule': {'id': rule, 'level': level, 'groups': groups, 'description': 'Windows logon'},
            'decoder': {'name': 'windows_eventchannel'},
            'data': {'win': {'system': {'channel': 'Security', 'eventID': event_id},
                             'eventdata': {'targetUserName': user, 'ipAddress': ip, 'logonType': '10'}}}}


def linux(groups, ident, stamp, srcip=PUBLIC, dstuser='root', srcuser=None, rule='5760', level=5):
    data = {'dstuser': dstuser}
    if srcip:
        data['srcip'] = srcip
    if srcuser:
        data['srcuser'] = srcuser
    return {'timestamp': stamp.isoformat(), 'id': ident, 'location': '/var/log/auth.log',
            'agent': {'id': '003', 'name': 'SRV-CONTA', 'ip': '10.0.0.25'},
            'rule': {'id': rule, 'level': level, 'groups': groups, 'description': 'auth'}, 'decoder': {'name': 'sshd'},
            'data': data}


class AccessBase(TestCase):
    def setUp(self):
        self.now = timezone.now()
        self.company = Client.objects.create(name='Talleres Ejemplo', code='te', urgent_alerts_enabled=True,
                                             urgent_email='it@te.test', customer_endpoints_enabled=True)
        self.other = Client.objects.create(name='Empresa B', code='b')
        self.site = Site.objects.create(client=self.company, name='Palma', code='palma')
        ingest_events([defender_alert('1150', stamp=self.now - timedelta(hours=2), ident='seed')], self.now)
        EndpointAgent.objects.update(status='assigned', client=self.company, site=self.site,
                                     assigned_at=self.now - timedelta(hours=1))
        self.agent = EndpointAgent.objects.get()

    def failures(self, count, start=0, ip=PUBLIC, users=('ana.garcia',), prefix='f'):
        return [win('4625', user=users[i % len(users)], ip=ip, ident=f'{prefix}{start + i}',
                    stamp=self.now - timedelta(minutes=30) + timedelta(seconds=start + i)) for i in range(count)]

    def success(self, ip=PUBLIC, user='ana.garcia', ident='ok', minutes=20):
        return win('4624', user=user, ip=ip, ident=ident, stamp=self.now - timedelta(minutes=minutes), rule='60106',
                   groups=['windows', 'authentication_success'], level=3)


class BurstTests(AccessBase):
    def test_public_brute_force_then_success_is_one_burst_and_one_urgent_alert(self):
        ingest_events(self.failures(6, users=('administrador', 'ana.garcia', 'admin')), self.now)
        row = EndpointAccessAlert.objects.get()
        self.assertEqual((row.kind, row.failures, row.source_ip, row.source_public, row.client_scope_id),
                         ('repeated', 6, PUBLIC, True, self.company.pk))
        self.assertEqual(row.users, ['administrador', 'ana.garcia', 'admin'])
        self.assertFalse(UrgentAlert.objects.exists())
        ingest_events([self.success()], self.now)
        row.refresh_from_db()
        self.assertEqual((row.kind, row.success_user), ('success', 'ana.garcia'))
        [urgent] = UrgentAlert.objects.all()
        self.assertEqual((urgent.kind, urgent.status, urgent.external_ip, urgent.asset_name, urgent.site_name),
                         ('endpoint_access', 'pending', PUBLIC, 'SRV-CONTA', 'Palma'))
        self.assertEqual(urgent.signature, '6 intentos fallidos y después un acceso correcto')
        self.assertEqual(urgent.rule_level, 3)
        stored = str(urgent.interpretation) + urgent.signature + urgent.asset_name
        for secret in ('ana.garcia', 'administrador', INTERNAL):
            self.assertNotIn(secret, stored)  # invariante 3: ni cuentas ni IP interna

    def test_rereading_the_same_alerts_does_not_inflate_attempts_or_alerts(self):
        events = self.failures(6) + [self.success()]
        ingest_events(events, self.now)
        ingest_events(events, self.now)
        row = EndpointAccessAlert.objects.get()
        self.assertEqual((row.failures, EndpointAccessEvent.objects.count(), UrgentAlert.objects.count()), (6, 6, 1))

    def test_few_failures_are_isolated_until_wazuh_correlates_them(self):
        ingest_events(self.failures(2), self.now)
        self.assertEqual(EndpointAccessAlert.objects.get().kind, 'isolated')
        ingest_events([self.success()], self.now)
        self.assertEqual(EndpointAccessAlert.objects.get().kind, 'isolated')  # un usuario que se equivocó dos veces
        correlated = win('4625', ident='c', stamp=self.now - timedelta(minutes=19), rule='60204', level=10,
                         groups=['windows', 'authentication_failures'])
        ingest_events([correlated], self.now)
        row = EndpointAccessAlert.objects.get()
        self.assertEqual((row.kind, row.failures, row.correlated), ('repeated', 3, True))

    def test_internal_success_after_failures_goes_to_the_soc_but_does_not_alert_the_customer(self):
        ingest_events(self.failures(5, ip=INTERNAL) + [self.success(ip=INTERNAL)], self.now)
        row = EndpointAccessAlert.objects.get()
        self.assertEqual((row.kind, row.source_public, row.urgent), ('success', False, False))
        self.assertFalse(UrgentAlert.objects.exists())
        self.assertEqual(endpoint_access.review_queue(), [row])

    def test_success_from_another_origin_or_too_late_is_not_matched(self):
        ingest_events(self.failures(5), self.now)
        ingest_events([self.success(ip='81.0.0.9', ident='a'),
                       self.success(ident='b', minutes=-40)], self.now + timedelta(hours=1))
        self.assertEqual(EndpointAccessAlert.objects.get().kind, 'repeated')

    def test_far_apart_failures_are_separate_bursts(self):
        first = self.failures(5)
        later = [win('4625', ident='late', stamp=self.now + timedelta(hours=2))]
        ingest_events(first, self.now)
        ingest_events(later, self.now + timedelta(hours=2))
        self.assertEqual(EndpointAccessAlert.objects.count(), 2)

    def test_lockout_joins_the_burst_that_tried_that_account(self):
        kerberos = [win('4771', user='ana.garcia', ip='::ffff:10.0.0.40', ident=f'k{i}', rule='60300',
                        stamp=self.now - timedelta(minutes=10, seconds=-i)) for i in range(3)]
        lockout = win('4740', user='ana.garcia', ip='', ident='lock', rule='60115', level=9,
                      stamp=self.now - timedelta(minutes=9), groups=['windows', 'account_changed'])
        ingest_events(kerberos + [lockout], self.now)
        row = EndpointAccessAlert.objects.get()
        self.assertEqual((row.kind, row.failures, row.source_ip, bool(row.locked_out_at)), ('lockout', 3, INTERNAL, True))
        self.assertEqual(endpoint_access.badge(), (1, False))

    def test_machine_and_system_accounts_without_origin_are_ignored(self):
        ingest_events([win('4625', user='SRV-CONTA$', ip='-', ident='m1'), win('4625', user='SYSTEM', ip='-', ident='m2')],
                      self.now)
        self.assertFalse(EndpointAccessAlert.objects.exists())

    def test_ssh_brute_force_and_wazuh_success_after_failures(self):
        stamp = self.now - timedelta(minutes=15)
        events = [linux(['syslog', 'sshd', 'authentication_failed'], f's{i}', stamp + timedelta(seconds=i), dstuser=user)
                  for i, user in enumerate(('root', 'admin', 'oracle', 'root', 'test'))]
        ingest_events(events, self.now)
        row = EndpointAccessAlert.objects.get()
        self.assertEqual((row.kind, row.failures, row.users), ('repeated', 5, ['root', 'admin', 'oracle', 'test']))
        accepted = linux(['syslog', 'sshd', 'authentication_success'], 'acc', stamp + timedelta(minutes=2), dstuser='root',
                         rule='40112', level=12)
        ingest_events([accepted], self.now)
        row.refresh_from_db()
        self.assertEqual(row.kind, 'success')
        self.assertEqual(UrgentAlert.objects.get().rule_level, 12)

    def test_wazuh_success_after_failures_alone_creates_the_burst(self):
        accepted = linux(['syslog', 'sshd', 'authentication_success'], 'acc', self.now - timedelta(minutes=5),
                         rule='40112', level=12)
        ingest_events([accepted], self.now)
        row = EndpointAccessAlert.objects.get()
        self.assertEqual((row.kind, row.failures, row.correlated), ('success', 0, True))
        self.assertEqual(endpoint_access.attempts_label(row), 'Varios intentos fallidos')

    def test_sudo_failures_group_by_the_user_who_failed(self):
        stamp = self.now - timedelta(minutes=15)
        events = [linux(['syslog', 'sudo', 'authentication_failed'], f'u{i}', stamp + timedelta(seconds=i), srcip=None,
                        srcuser='pedro', dstuser='root', rule='5401') for i in range(5)]
        ingest_events(events, self.now)
        row = EndpointAccessAlert.objects.get()
        self.assertEqual((row.kind, row.source_ip, row.group_user, row.users), ('repeated', None, 'pedro', ['pedro']))

    def test_unassigned_agents_and_events_before_the_assignment_are_not_counted(self):
        ingest_events(self.failures(5, start=0, prefix='old'), self.now)  # 30 min antes: después de la asignación
        EndpointAccessAlert.objects.all().delete()
        EndpointAgent.objects.update(assigned_at=self.now)
        ingest_events(self.failures(5, prefix='before'), self.now)
        ingest_events([win('4625', agent='009', ident='x')], self.now)
        self.assertFalse(EndpointAccessAlert.objects.exists())
        self.assertEqual(EndpointAgent.objects.get(agent_id='009').status, 'pending')

    def test_a_reviewed_burst_returns_when_it_gets_worse(self):
        ingest_events(self.failures(5), self.now)
        EndpointAccessAlert.objects.update(review='reviewed')
        ingest_events([self.success()], self.now)
        self.assertEqual(EndpointAccessAlert.objects.get().review, 'pending')

    def test_late_success_is_recorded_but_the_alert_expires(self):
        ingest_events(self.failures(5), self.now)
        ingest_events([self.success()], self.now + timedelta(hours=3))
        self.assertEqual(UrgentAlert.objects.get().status, 'expired')

    def test_no_urgent_alert_when_the_customer_has_them_off(self):
        Client.objects.filter(pk=self.company.pk).update(urgent_alerts_enabled=False)
        ingest_events(self.failures(5) + [self.success()], self.now)
        self.assertFalse(UrgentAlert.objects.exists())
        self.assertEqual(EndpointAccessAlert.objects.get().kind, 'success')

    def test_old_ids_and_isolated_bursts_are_pruned(self):
        from .retention import prune
        ingest_events(self.failures(2), self.now)
        EndpointAccessAlert.objects.update(last_at=self.now - timedelta(days=8))
        EndpointAccessEvent.objects.update(observed_at=self.now - timedelta(days=31))
        prune(self.now)
        self.assertFalse(EndpointAccessAlert.objects.exists())
        self.assertFalse(EndpointAccessEvent.objects.exists())


class MessageTests(AccessBase):
    def test_email_and_chat_explain_it_without_the_account(self):
        from . import chat_alerts
        from .models import MailSettings
        from .urgent_alerts import deliver_pending
        ingest_events(self.failures(7) + [self.success()], self.now)
        MailSettings.objects.update_or_create(pk=1, defaults={'enabled': True, 'last_test_ok': True})
        with mock.patch('core.urgent_alerts.send_customer_email', return_value='m1') as send:
            self.assertEqual(deliver_pending(self.now), 1)
        subject, plain, html = send.call_args.args[1:4]
        self.assertIn('SRV-CONTA', subject)
        self.assertIn('Acceso a un equipo tras varios intentos fallidos desde Internet', plain)
        self.assertIn('IP de origen observada: ' + PUBLIC, plain)
        self.assertIn('Qué se registró: 7 intentos fallidos y después un acceso correcto', plain)
        self.assertIn('Puede ser el propio usuario', plain)
        self.assertNotIn('Nivel Wazuh: 0', html)
        self.assertNotIn('Acción del firewall', plain + html)
        self.assertNotIn('ana.garcia', plain + html)
        text = chat_alerts.telegram_text(UrgentAlert.objects.get())
        self.assertIn('Resultado: acceso correcto', text)
        self.assertNotIn('ana.garcia', text)


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class ViewTests(AccessBase):
    def login(self, *perms, all_clients=True, name='analista', client=None):
        user = get_user_model().objects.create_user(name)
        access = StaffAccess.objects.create(user=user, role='operator', all_clients=all_clients)
        if not all_clients:
            access.clients.add(client or self.company)
        for codename in ('manage_operations', *perms):
            user.user_permissions.add(Permission.objects.get(codename=codename))
        self.client.force_login(user)
        session = self.client.session
        session.update({'soc_mfa_user': user.pk, 'soc_mfa_at': time.time()})
        session.save()
        return user

    def test_soc_page_lists_bursts_with_accounts_and_opens_an_incident(self):
        ingest_events(self.failures(6, users=('administrador',)) + [self.success(user='administrador')], self.now)
        self.login('add_incident')
        page = self.client.get(reverse('endpoint_access'))
        self.assertContains(page, 'Acceso correcto tras los fallos')
        self.assertContains(page, 'administrador')
        self.assertContains(page, 'Internet: acceso remoto expuesto')
        row = EndpointAccessAlert.objects.get()
        response = self.client.post(reverse('endpoint_access'), {'action': 'incident', 'alert': row.pk})
        incident = Incident.objects.get()
        self.assertRedirects(response, reverse('incident_detail', args=[incident.pk]), fetch_redirect_response=False)
        self.assertEqual((incident.client, incident.severity), (self.company, 'critical'))
        self.assertIn('administrador', incident.description)
        self.assertEqual(EndpointAccessAlert.objects.get().review, 'incident')

    def test_isolated_failures_are_hidden_and_repeated_ones_are_reviewed_in_bulk(self):
        ingest_events(self.failures(2, ip='81.0.0.9', prefix='i') + self.failures(5), self.now)
        self.login()
        page = self.client.get(reverse('endpoint_access'))
        self.assertNotContains(page, '81.0.0.9')
        self.assertContains(page, PUBLIC)
        self.client.post(reverse('endpoint_access'), {'action': 'reviewed_repeated'})
        self.assertEqual(EndpointAccessAlert.objects.get(source_ip=PUBLIC).review, 'reviewed')
        self.assertEqual(EndpointAccessAlert.objects.get(source_ip='81.0.0.9').review, 'pending')

    def test_limited_operators_see_only_their_clients(self):
        ingest_events(self.failures(5), self.now)
        self.login(all_clients=False, client=self.other, name='otro')
        page = self.client.get(reverse('endpoint_access'))
        self.assertNotContains(page, PUBLIC)
        row = EndpointAccessAlert.objects.get()
        self.client.post(reverse('endpoint_access'), {'action': 'reviewed', 'alert': row.pk})
        self.assertEqual(EndpointAccessAlert.objects.get().review, 'pending')

    def test_work_queue_and_menu_show_success_after_failures(self):
        ingest_events(self.failures(5) + [self.success()], self.now)
        self.login()
        page = self.client.get(reverse('work_queue'))
        self.assertContains(page, 'Accesos a equipos de clientes')
        self.assertContains(page, 'Acceso correcto tras los fallos')

    def test_customer_sees_what_happened_without_accounts_or_internal_addresses(self):
        ingest_events(self.failures(6, users=('administrador',)) + [self.success(user='administrador')]
                      + self.failures(5, ip=INTERNAL, users=('pedro.lopez',), prefix='n', start=100), self.now)
        rows = endpoint_access.customer_rows(self.company)
        self.assertEqual({r['origin'] for r in rows}, {'Internet', 'Red interna'})
        self.assertEqual({r['public_ip'] for r in rows}, {PUBLIC, ''})
        self.assertNotIn('administrador', str(rows))
        self.assertNotIn(INTERNAL, str(rows))
        self.assertEqual(endpoint_access.customer_rows(self.other), [])
        context = endpoints.customer_context(self.company)
        self.assertEqual(context['summary']['access_after_failures'], 1)
        user = get_user_model().objects.create_user('cliente')
        access = StaffAccess.objects.create(user=user, role='customer', all_clients=False)
        access.clients.add(self.company)
        self.client.force_login(user)
        session = self.client.session
        session.update({'soc_mfa_user': user.pk, 'soc_mfa_at': time.time()})
        session.save()
        page = self.client.get(reverse('customer_endpoints'))
        self.assertContains(page, 'Acceso correcto después de varios intentos fallidos')
        self.assertContains(page, PUBLIC)
        for secret in ('administrador', 'pedro.lopez', INTERNAL):
            self.assertNotContains(page, secret)


class RecoveryTests(AccessBase):
    """Recuperación de los intentos desde el indexador: cursor propio, invariante 5 y sin inflar contadores."""

    def run_with(self, *responses):
        replies = list(responses)
        with mock.patch('core.reporting.indexer_authorization', return_value='Basic x'), \
                mock.patch('core.reporting._search', side_effect=lambda body, auth: replies.pop(0)) as search:
            count = endpoints.reconcile(self.now, stream='access')
        return count, search

    @staticmethod
    def page(*sources):
        hits = [{'_index': 'wazuh-alerts-4.x-2026.11.23', '_id': s['id'], '_source': s,
                 'sort': [s['timestamp'], s['id'], 'wazuh-alerts-4.x-2026.11.23']} for s in sources]
        return {'timed_out': False, '_shards': {'failed': 0}, 'hits': {'hits': hits}}

    def state(self):
        return WorkerState.objects.filter(name='endpoint-access-reconciliation').first()

    def test_missing_failures_are_recovered_once_with_their_own_cursor(self):
        ingest_events(self.failures(3), self.now)  # llegaron por alerts.json
        page = self.page(*self.failures(6))  # el indexador tiene esos y tres más
        count, search = self.run_with(page)
        body = search.call_args.args[0]
        self.assertIn(endpoint_access.recovery_filter(), body['query']['bool']['filter'])
        self.assertEqual(count, 6)
        self.assertEqual(EndpointAccessAlert.objects.get().failures, 6)
        self.assertIn('completed_until', self.state().details)
        self.assertIsNone(WorkerState.objects.filter(name=endpoints.RECONCILE_STATE).first())
        self.run_with(page)  # solape de la ventana siguiente
        self.assertEqual(EndpointAccessAlert.objects.get().failures, 6)

    def test_incomplete_answer_keeps_the_cursor_and_counts_nothing(self):
        from .models import OperationalIssue
        self.run_with(self.page())
        before = dict(self.state().details)
        broken = self.page(*self.failures(6))
        broken['timed_out'] = True
        self.run_with(broken)
        self.assertEqual(self.state().details, before)
        self.assertFalse(EndpointAccessAlert.objects.exists())
        self.assertTrue(OperationalIssue.objects.filter(key='platform:endpoint-access-reconciliation', active=True).exists())

    def test_the_job_runs_both_streams(self):
        from .background_jobs import execute
        with mock.patch('core.endpoints.reconcile', return_value=1) as run:
            self.assertEqual(execute('endpoint_reconciliation'), 3)
        self.assertEqual([c.kwargs.get('stream', 'defender') for c in run.call_args_list], ['defender', 'access', 'sca'])

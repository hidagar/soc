"""Integridad de archivos de los equipos (syscheck de Wazuh): clasificación, ingesta, revisión, portal y recuperación."""
import time
from datetime import timedelta
from unittest import mock

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from . import endpoint_integrity, endpoints
from .endpoint_integrity import category
from .models import Client, EndpointAgent, EndpointFileChange, Incident, Site, StaffAccess, WorkerState
from .operations import ingest_events
from .test_endpoints import alert as defender_alert

SHA = 'a' * 64


def fim(path, ident, stamp, event='modified', agent='003', registry=False, value=None, whodata=False):
    syscheck = {'path': path, 'event': event, 'mode': 'whodata' if whodata else 'realtime',
                'changed_attributes': ['size', 'mtime', 'sha256'], 'sha256_after': SHA, 'size_after': '120'}
    if value:
        syscheck['value_name'] = value
    if whodata:
        syscheck['audit'] = {'user': {'id': '1001', 'name': 'jlopez'}, 'process': {'id': '77', 'name': '/usr/bin/vim'}}
    groups = ['ossec', 'syscheck', 'syscheck_entry_' + event, 'syscheck_registry' if registry else 'syscheck_file']
    return {'timestamp': stamp.isoformat(), 'id': ident, 'location': 'syscheck',
            'agent': {'id': agent, 'name': 'SRV-FICHEROS', 'ip': '10.0.0.25'},
            'rule': {'id': '594' if registry else '550', 'level': 7, 'groups': groups, 'description': 'Integrity checksum changed.'},
            'decoder': {'name': 'syscheck_integrity_changed'}, 'syscheck': syscheck,
            'full_log': f"File '{path}' modified"}


class CategoryTests(SimpleTestCase):
    def test_paths_are_classified_by_what_they_control(self):
        cases = {
            r'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run': 'persistence',
            r'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\EvilSvc': 'persistence',
            r'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\update.lnk': 'persistence',
            r'C:\Windows\System32\Tasks\Actualizador': 'persistence',
            '/etc/cron.d/backup': 'persistence', '/etc/systemd/system/miner.service': 'persistence',
            '/etc/ld.so.preload': 'persistence',
            '/etc/shadow': 'identity', '/etc/sudoers.d/90-admin': 'identity', '/root/.ssh/authorized_keys': 'identity',
            '/etc/ssh/sshd_config': 'identity', r'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa': 'identity',
            r'C:\Windows\System32\drivers\etc\hosts': 'network', '/etc/hosts': 'network',
            r'C:\Windows\System32\kernel32.dll': 'binary', '/usr/bin/sudo': 'binary', '/boot/vmlinuz': 'binary',
            '/etc/nginx/nginx.conf': 'config', r'HKEY_LOCAL_MACHINE\Software\Classes\.txt': 'config',
            '/srv/datos/informe.docx': 'other',
        }
        for path, expected in cases.items():
            with self.subTest(path=path):
                self.assertEqual(category(path), expected)


class IntegrityBase(TestCase):
    def setUp(self):
        self.now = timezone.now()
        self.company = Client.objects.create(name='Talleres Ejemplo', code='te', customer_endpoints_enabled=True)
        self.other = Client.objects.create(name='Empresa B', code='b')
        self.site = Site.objects.create(client=self.company, name='Palma', code='palma')
        ingest_events([defender_alert('1150', stamp=self.now - timedelta(hours=3), ident='seed')], self.now)
        EndpointAgent.objects.update(status='assigned', client=self.company, site=self.site,
                                     assigned_at=self.now - timedelta(hours=2))
        self.stamp = self.now - timedelta(minutes=30)

    def changes(self):
        return [fim('/etc/sudoers.d/90-admin', 'f1', self.stamp, event='added', whodata=True),
                fim(r'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run', 'f2', self.stamp, registry=True,
                    value='Actualizador'),
                fim('/usr/bin/sudo', 'f3', self.stamp), fim('/etc/nginx/nginx.conf', 'f4', self.stamp)]


class IngestTests(IntegrityBase):
    def test_changes_are_stored_once_and_only_sensitive_ones_wait_for_review(self):
        ingest_events(self.changes(), self.now)
        ingest_events(self.changes(), self.now)  # relectura
        self.assertEqual(EndpointFileChange.objects.count(), 4)
        sudoers = EndpointFileChange.objects.get(event_id='f1')
        self.assertEqual((sudoers.category, sudoers.event, sudoers.sensitive, sudoers.review, sudoers.actor, sudoers.process,
                          sudoers.sha256, sudoers.mode, sudoers.client_scope_id),
                         ('identity', 'added', True, 'pending', 'jlopez', '/usr/bin/vim', SHA, 'whodata', self.company.pk))
        run = EndpointFileChange.objects.get(event_id='f2')
        self.assertEqual((run.category, run.registry, run.value_name), ('persistence', True, 'Actualizador'))
        self.assertEqual(set(EndpointFileChange.objects.filter(sensitive=False).values_list('review', flat=True)), {'reviewed'})
        self.assertEqual(endpoint_integrity.badge(), (2, False))
        self.assertEqual(len(endpoint_integrity.review_queue()), 2)

    def test_unassigned_agents_old_events_and_incomplete_alerts_are_ignored(self):
        ingest_events([fim('/etc/shadow', 'a', self.now - timedelta(hours=2, minutes=30)),
                       fim('/etc/shadow', 'b', self.stamp, agent='009'),
                       fim('/etc/shadow', '', self.stamp), fim('/etc/shadow', 'c', self.stamp, event='raro')], self.now)
        self.assertFalse(EndpointFileChange.objects.exists())

    def test_old_routine_changes_are_pruned_and_pending_sensitive_ones_kept(self):
        from .retention import prune
        ingest_events(self.changes(), self.now)
        EndpointFileChange.objects.update(observed_at=self.now - timedelta(days=200))
        prune(self.now)
        self.assertEqual(set(EndpointFileChange.objects.values_list('event_id', flat=True)), {'f1', 'f2'})


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class ViewTests(IntegrityBase):
    def login(self, role='operator', all_clients=True, client=None, perms=('manage_operations', 'add_incident')):
        user = get_user_model().objects.create_user(role + str(time.time_ns()))
        access = StaffAccess.objects.create(user=user, role=role, all_clients=all_clients)
        if not all_clients:
            access.clients.add(client or self.company)
        for codename in perms:
            user.user_permissions.add(Permission.objects.get(codename=codename))
        self.client.force_login(user)
        session = self.client.session
        session.update({'soc_mfa_user': user.pk, 'soc_mfa_at': time.time()})
        session.save()

    def test_soc_page_reviews_sensitive_changes_and_summarises_the_rest(self):
        updates = [fim(f'C:\\Windows\\System32\\file{i}.dll', f'u{i}', self.stamp) for i in range(55)]
        ingest_events(self.changes() + updates, self.now)
        self.login()
        page = self.client.get(reverse('endpoint_integrity'))
        self.assertContains(page, '/etc/sudoers.d/90-admin')
        self.assertContains(page, 'jlopez')
        self.assertContains(page, 'Probable actualización')
        row = EndpointFileChange.objects.get(event_id='f2')
        response = self.client.post(reverse('endpoint_integrity'), {'action': 'incident', 'change': row.pk})
        incident = Incident.objects.get()
        self.assertRedirects(response, reverse('incident_detail', args=[incident.pk]), fetch_redirect_response=False)
        self.assertIn('Actualizador', incident.description)
        self.client.post(reverse('endpoint_integrity'), {'action': 'reviewed_all'})
        self.assertEqual(dict(EndpointFileChange.objects.filter(sensitive=True).values_list('event_id', 'review')),
                         {'f1': 'reviewed', 'f2': 'incident'})

    def test_limited_operators_see_only_their_clients(self):
        ingest_events(self.changes(), self.now)
        self.login(all_clients=False, client=self.other)
        self.assertNotContains(self.client.get(reverse('endpoint_integrity')), 'sudoers')
        self.client.post(reverse('endpoint_integrity'), {'action': 'reviewed_all'})
        self.assertEqual(EndpointFileChange.objects.filter(review='pending').count(), 2)

    def test_work_queue_lists_sensitive_changes(self):
        ingest_events(self.changes(), self.now)
        self.login()
        self.assertContains(self.client.get(reverse('work_queue')), 'Cambios sensibles en equipos de clientes')

    def test_customer_sees_the_kind_of_change_without_paths_users_or_hashes(self):
        ingest_events(self.changes(), self.now)
        rows = endpoint_integrity.customer_rows(self.company)
        self.assertEqual(sorted(r['what'] for r in rows), ['Programas que se ejecutan al arrancar',
                                                           'Usuarios, contraseñas y permisos'])
        self.assertEqual(endpoint_integrity.customer_rows(self.other), [])
        self.login(role='customer', all_clients=False, perms=())
        page = self.client.get(reverse('customer_endpoints'))
        self.assertContains(page, 'Cambios en archivos importantes')
        for secret in ('sudoers', 'jlopez', 'vim', SHA, 'Actualizador', 'nginx', 'CurrentVersion'):
            self.assertNotContains(page, secret)


class RecoveryTests(IntegrityBase):
    def test_missing_changes_are_recovered_once_with_their_own_cursor(self):
        sources = self.changes()
        ingest_events(sources[:2], self.now)
        hits = [{'_index': 'wazuh-alerts-4.x', '_id': s['id'], '_source': s, 'sort': [s['timestamp'], s['id'], 'wazuh-alerts-4.x']}
                for s in sources]
        replies = [{'timed_out': False, '_shards': {'failed': 0}, 'hits': {'hits': hits}}]
        with mock.patch('core.reporting.indexer_authorization', return_value='Basic x'), \
                mock.patch('core.reporting._search', side_effect=lambda body, auth: replies.pop(0)) as search:
            endpoints.reconcile(self.now, stream='fim')
        self.assertIn(endpoint_integrity.recovery_filter(), search.call_args.args[0]['query']['bool']['filter'])
        self.assertEqual(EndpointFileChange.objects.count(), 4)
        self.assertIn('completed_until', WorkerState.objects.get(name='endpoint-fim-reconciliation').details)

    def test_the_job_runs_every_stream(self):
        from .background_jobs import execute
        with mock.patch('core.endpoints.reconcile', return_value=1) as run:
            self.assertEqual(execute('endpoint_reconciliation'), 4)
        self.assertEqual([c.kwargs.get('stream', 'defender') for c in run.call_args_list], ['defender', 'access', 'sca', 'fim'])

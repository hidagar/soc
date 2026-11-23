"""Antivirus de equipos vía agente Wazuh (Microsoft Defender): descubrimiento, asignación, eventos, estado y revisión."""
import os
import shutil
import subprocess
import tempfile
import time
from datetime import timedelta
from pathlib import Path

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from . import endpoints
from .models import Client, Device, EndpointAgent, EndpointDetection, Incident, Site, StaffAccess
from .operations import ingest_events

ROOT = Path(__file__).resolve().parent.parent
DETECTION = '{3E1A5C0B-1111-4C2B-9A6E-ABCDEF012345}'


def alert(event_id, eventdata=None, agent='003', stamp=None, ident='1', name='PC-CONTA-01'):
    stamp = stamp or timezone.now()
    return {'timestamp': stamp.isoformat(), 'id': ident, 'location': 'EventChannel',
            'agent': {'id': agent, 'name': name, 'ip': '10.0.0.25'},
            'rule': {'id': '62123', 'level': 12, 'description': 'Windows Defender'},
            'decoder': {'name': 'windows_eventchannel'},
            'data': {'win': {'system': {'channel': endpoints.CHANNEL, 'eventID': event_id,
                                        'providerName': 'Microsoft-Windows-Windows Defender'},
                             'eventdata': eventdata or {}}}}


def detected(**extra):
    return {'detection ID': DETECTION, 'threatName': 'Trojan:Win32/Wacatac.B!ml', 'severityName': 'Severe',
            'categoryName': 'Trojan', 'path': 'file:_C:\\Users\\ana\\Downloads\\factura.exe', 'processName': 'explorer.exe',
            'detectionUser': 'EMPRESA\\ana', **extra}


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class EndpointTests(TestCase):
    def setUp(self):
        self.now = timezone.now()
        self.company = Client.objects.create(name='Empresa A', code='a')
        self.other = Client.objects.create(name='Empresa B', code='b')
        self.site = Site.objects.create(client=self.company, name='Palma', code='palma')

    def user(self, *perms, all_clients=True, name='analista'):
        user = get_user_model().objects.create_user(name)
        access = StaffAccess.objects.create(user=user, role='operator', all_clients=all_clients)
        if not all_clients:
            access.clients.add(self.company)
        for codename in ('manage_operations', *perms):
            user.user_permissions.add(Permission.objects.get(codename=codename))
        self.client.force_login(user)
        session = self.client.session
        session.update({'soc_mfa_user': user.pk, 'soc_mfa_at': time.time()})
        session.save()
        return user

    def assign(self, stamp=None):
        ingest_events([alert('1150', stamp=(stamp or self.now) - timedelta(minutes=5), ident='seed')], self.now)
        agent = EndpointAgent.objects.get()
        EndpointAgent.objects.filter(pk=agent.pk).update(status='assigned', client=self.company, site=self.site,
                                                         assigned_at=(stamp or self.now) - timedelta(minutes=1))
        return EndpointAgent.objects.get()

    def test_unknown_agents_are_discovered_but_their_events_are_not_attributed(self):
        ingest_events([alert('1116', detected())], self.now)
        agent = EndpointAgent.objects.get()
        self.assertEqual((agent.agent_id, agent.name, agent.status, agent.client), ('003', 'PC-CONTA-01', 'pending', None))
        self.assertFalse(EndpointDetection.objects.exists())

    def test_events_from_firewall_agents_are_not_endpoints(self):
        device = Device.objects.create(site=self.site, name='FW', vendor='opnsense', log_method='wazuh_agent', wazuh_identifier='003')
        self.assertTrue(device.pk)
        ingest_events([alert('1116', detected())], self.now)
        self.assertFalse(EndpointAgent.objects.exists())

    def test_detection_and_later_action_are_one_detection(self):
        agent = self.assign()
        ingest_events([alert('1116', detected(), ident='a')], self.now)
        row = EndpointDetection.objects.get()
        self.assertEqual((row.action, row.client_scope_id, row.severity, row.threat),
                         ('detected', self.company.pk, 'Severe', 'Trojan:Win32/Wacatac.B!ml'))
        ingest_events([alert('1117', detected(actionName='Quarantine'), ident='b', stamp=self.now + timedelta(seconds=5))], self.now)
        row.refresh_from_db()
        self.assertEqual((EndpointDetection.objects.count(), row.action, row.action_name), (1, 'contained', 'Quarantine'))
        EndpointDetection.objects.filter(pk=row.pk).update(review='reviewed')
        ingest_events([alert('1118', detected(), ident='c', stamp=self.now + timedelta(seconds=9))], self.now)
        row.refresh_from_db()
        self.assertEqual((row.action, row.review), ('failed', 'pending'))  # empeora: vuelve a la cola
        self.assertEqual(agent.detections.count(), 1)

    def test_events_before_the_assignment_are_not_attributed(self):
        self.assign()
        ingest_events([alert('1116', detected(), stamp=self.now - timedelta(hours=2))], self.now)
        self.assertFalse(EndpointDetection.objects.exists())

    def test_state_follows_health_reports_and_protection_changes(self):
        agent = self.assign()
        self.assertEqual(endpoints.state(agent, self.now)[0], 'unknown')
        ingest_events([alert('1151', {'rTP state': 'Enabled', 'aV Signature Age': '1', 'last quick scan age': '2',
                                      'aV Signature Version': '1.421.33.0'}, ident='h')], self.now)
        agent.refresh_from_db()
        self.assertEqual((agent.realtime_enabled, agent.signature_age_days, agent.signature_version), (True, 1, '1.421.33.0'))
        self.assertEqual(endpoints.state(agent, self.now)[0], 'protected')
        ingest_events([alert('5001', ident='off', stamp=self.now + timedelta(seconds=30))], self.now)
        agent.refresh_from_db()
        self.assertEqual(endpoints.state(agent, self.now)[0], 'unprotected')
        ingest_events([alert('5000', ident='on', stamp=self.now + timedelta(seconds=60))], self.now)
        EndpointAgent.objects.filter(pk=agent.pk).update(signature_age_days=6)
        agent.refresh_from_db()
        self.assertEqual(endpoints.state(agent, self.now)[0], 'outdated')
        self.assertEqual(endpoints.state(agent, self.now + timedelta(days=4))[0], 'silent')

    def test_global_operator_assigns_pending_agents_in_bulk(self):
        ingest_events([alert('1150', agent='004', name='PC-1'), alert('1150', agent='005', name='PC-2', ident='2')], self.now)
        self.user('manage_connections')
        page = self.client.get(reverse('endpoints'))
        self.assertContains(page, 'Agentes sin asignar · 2')
        ids = list(EndpointAgent.objects.values_list('pk', flat=True))
        self.client.post(reverse('endpoints'), {'action': 'assign', 'agent': ids, 'client': self.company.pk, 'site': self.site.pk})
        self.assertEqual(set(EndpointAgent.objects.values_list('status', 'client_id')), {('assigned', self.company.pk)})

    def test_limited_operators_see_only_their_clients_and_cannot_assign(self):
        self.assign()
        ingest_events([alert('1116', detected(), ident='x')], self.now)
        ingest_events([alert('1150', agent='009', name='PC-OTRO', ident='p')], self.now)
        self.user(all_clients=False)
        page = self.client.get(reverse('endpoints'))
        self.assertContains(page, 'Trojan:Win32/Wacatac.B!ml')
        self.assertNotContains(page, 'PC-OTRO')  # sin asignar: solo acceso global
        pending = EndpointAgent.objects.get(agent_id='009')
        response = self.client.post(reverse('endpoints'), {'action': 'assign', 'agent': [pending.pk], 'client': self.company.pk})
        self.assertEqual(response.status_code, 403)
        EndpointDetection.objects.update(client_scope_id=self.other.pk)
        self.assertNotContains(self.client.get(reverse('endpoints')), 'Trojan:Win32/Wacatac.B!ml')

    def test_review_and_incident_from_a_detection(self):
        self.assign()
        ingest_events([alert('1116', detected(), ident='a'), alert('1118', detected(), ident='b')], self.now)
        row = EndpointDetection.objects.get()
        self.user('add_incident')
        response = self.client.post(reverse('endpoints'), {'action': 'incident', 'detection': row.pk})
        incident = Incident.objects.get()
        self.assertRedirects(response, reverse('incident_detail', args=[incident.pk]), fetch_redirect_response=False)
        self.assertEqual((incident.client, incident.site, incident.severity), (self.company, self.site, 'critical'))
        self.assertIn('no descarta una ejecución previa', incident.description)
        row.refresh_from_db()
        self.assertEqual((row.review, row.incident), ('incident', incident))

    def test_work_queue_menu_and_client_page_show_pending_detections(self):
        self.assign()
        ingest_events([alert('1116', detected(), ident='a')], self.now)
        self.user()
        self.assertContains(self.client.get(reverse('work_queue')), 'Malware en equipos de clientes')
        self.assertEqual(endpoints.badge(), (1, False))
        page = self.client.get(reverse('client_detail', args=[self.company.pk]))
        self.assertContains(page, 'Antivirus de equipos')
        self.assertContains(page, '1 detección por revisar')


class DefenderScriptTests(SimpleTestCase):
    """deploy/wazuh/configurar_defender.sh con un gestor simulado (binarios de Wazuh y systemctl de prueba)."""

    def setUp(self):
        d = self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        for sub in ('ossec/bin', 'ossec/etc/rules', 'ossec/etc/shared', 'bin', 'backups'):
            (d / sub).mkdir(parents=True)
        self.stub('ossec/bin/wazuh-analysisd', f'[[ -f {d}/fail ]] && exit 1\nexit 0')
        self.stub('ossec/bin/agent_groups', f'mkdir -p {d}/ossec/etc/shared/"$3"\n'
                                           f'printf "<agent_config>\\n  <!-- Shared agent configuration here -->\\n</agent_config>\\n" '
                                           f'> {d}/ossec/etc/shared/"$3"/agent.conf')
        self.stub('bin/systemctl', f'echo "$*" >> {d}/calls.log')
        self.stub('bin/chown', 'exit 0')

    def stub(self, name, body):
        path = self.dir / name
        path.write_text('#!/bin/bash\n' + body + '\n')
        path.chmod(0o755)

    def run_script(self, *args):
        env = {**os.environ, 'PATH': f'{self.dir}/bin:{os.environ["PATH"]}', 'SOC_WAZUH_DIR': str(self.dir / 'ossec'),
               'SOC_BACKUP_DIR': str(self.dir / 'backups')}
        return subprocess.run(['bash', str(ROOT / 'deploy/wazuh/configurar_defender.sh'), *args, '--yes'], env=env,
                              capture_output=True, text=True, timeout=60)

    def test_group_is_created_with_the_defender_channel_once(self):
        result = self.run_script('--grupo', 'talleres')
        self.assertEqual(result.returncode, 0, result.stderr)
        conf = (self.dir / 'ossec/etc/shared/soc-talleres/agent.conf').read_text()
        self.assertIn('Microsoft-Windows-Windows Defender/Operational', conf)
        self.assertIn('WAZUH_AGENT_GROUP="soc-talleres"', result.stdout)
        self.run_script('--grupo', 'talleres')
        conf_again = (self.dir / 'ossec/etc/shared/soc-talleres/agent.conf').read_text()
        self.assertEqual(conf_again.count('Microsoft-Windows-Windows Defender/Operational'), 1)
        self.assertNotEqual(self.run_script('--grupo', '../etc').returncode, 0)

    def test_rules_are_installed_only_if_wazuh_accepts_them(self):
        (self.dir / 'fail').touch()
        result = self.run_script('--reglas')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.dir / 'ossec/etc/rules/soc_defender_rules.xml').exists())
        self.assertFalse((self.dir / 'calls.log').exists())
        (self.dir / 'fail').unlink()
        result = self.run_script('--reglas')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.dir / 'ossec/etc/rules/soc_defender_rules.xml').read_text(),
                         (ROOT / 'deploy/wazuh/soc_defender_rules.xml').read_text())
        self.assertIn('restart wazuh-manager', (self.dir / 'calls.log').read_text())
        self.assertIn('ya está instalada', self.run_script('--reglas').stdout)


class EndpointRetentionTests(TestCase):
    def test_old_reviewed_detections_and_stale_agents_are_pruned(self):
        from .retention import prune
        now = timezone.now()
        company = Client.objects.create(name='Empresa A', code='a')
        stale = EndpointAgent.objects.create(agent_id='1', name='viejo', last_seen_at=now - timedelta(days=91))
        retired = EndpointAgent.objects.create(agent_id='2', name='retirado', status='retired', client=company,
                                               retired_at=now - timedelta(days=401))
        live = EndpointAgent.objects.create(agent_id='3', name='activo', status='assigned', client=company, assigned_at=now)
        old = EndpointDetection.objects.create(agent=live, client_scope_id=company.pk, detection_key='a', threat='t',
                                               observed_at=now - timedelta(days=200), review='reviewed')
        pending = EndpointDetection.objects.create(agent=live, client_scope_id=company.pk, detection_key='b', threat='t',
                                                   observed_at=now - timedelta(days=200))
        prune(now)
        self.assertEqual(set(EndpointAgent.objects.values_list('pk', flat=True)), {live.pk})
        self.assertFalse(EndpointAgent.objects.filter(pk__in=[stale.pk, retired.pk]).exists())
        self.assertEqual(list(EndpointDetection.objects.values_list('pk', flat=True)), [pending.pk])
        self.assertFalse(EndpointDetection.objects.filter(pk=old.pk).exists())


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class EndpointUrgentAlertTests(TestCase):
    """Aviso urgente al cliente cuando una detección queda permitida o el antivirus no pudo actuar."""

    def setUp(self):
        self.now = timezone.now()
        self.company = Client.objects.create(name='Talleres Ejemplo', code='te', urgent_alerts_enabled=True,
                                             urgent_email='it@te.test')
        self.site = Site.objects.create(client=self.company, name='Palma', code='palma')
        ingest_events([alert('1150', stamp=self.now - timedelta(minutes=5), ident='seed')], self.now)
        EndpointAgent.objects.update(status='assigned', client=self.company, site=self.site,
                                     assigned_at=self.now - timedelta(minutes=1))

    def alerts(self):
        from .models import UrgentAlert
        return list(UrgentAlert.objects.all())

    def test_contained_detections_do_not_alert_but_failed_ones_do_once(self):
        ingest_events([alert('1116', detected(), ident='a'),
                       alert('1117', detected(actionName='Quarantine'), ident='b', stamp=self.now + timedelta(seconds=3))],
                      self.now)
        self.assertEqual(self.alerts(), [])
        other = detected(**{'detection ID': '{AAAA}'})
        ingest_events([alert('1116', other, ident='c'), alert('1118', other, ident='d', stamp=self.now + timedelta(seconds=5)),
                       alert('1119', other, ident='e', stamp=self.now + timedelta(seconds=8))], self.now)
        [urgent] = self.alerts()
        self.assertEqual((urgent.kind, urgent.action, urgent.asset_name, urgent.site_name, urgent.signature, urgent.status),
                         ('endpoint_malware', 'failed', 'PC-CONTA-01', 'Palma', 'Trojan:Win32/Wacatac.B!ml', 'pending'))
        self.assertEqual(urgent.source_ip, '10.0.0.25')
        self.assertNotIn('Downloads', str(urgent.interpretation))  # sin la ruta del archivo
        self.assertNotIn('ana', str(urgent.interpretation))  # ni el usuario

    def test_allowed_by_the_user_alerts_and_the_message_explains_it(self):
        from unittest import mock
        from . import chat_alerts
        from .models import MailSettings
        from .urgent_alerts import deliver_pending
        ingest_events([alert('1117', detected(actionName='Allow'), ident='a')], self.now)
        [urgent] = self.alerts()
        self.assertEqual(urgent.action, 'allowed')
        MailSettings.objects.update_or_create(pk=1, defaults={'enabled': True, 'last_test_ok': True})
        with mock.patch('core.urgent_alerts.send_customer_email', return_value='m1') as send:
            self.assertEqual(deliver_pending(self.now), 1)
        subject, plain, html = send.call_args.args[1:4]
        self.assertIn('PC-CONTA-01', subject)
        self.assertIn('Malware permitido en un equipo', plain)
        self.assertIn('Resultado del antivirus: permitida', plain)
        self.assertIn('Amenaza: Trojan:Win32/Wacatac.B!ml', plain)
        self.assertNotIn('Acción del firewall', plain + html)
        self.assertNotIn('Downloads', plain + html)
        text = chat_alerts.telegram_text(urgent)
        self.assertIn('Resultado del antivirus: permitida', text)
        self.assertIn('Amenaza: Trojan:Win32/Wacatac.B!ml', text)

    def test_no_alert_without_urgent_alerts_or_before_the_assignment(self):
        Client.objects.filter(pk=self.company.pk).update(urgent_alerts_enabled=False)
        ingest_events([alert('1118', detected(), ident='a')], self.now)
        self.assertEqual(self.alerts(), [])
        self.assertEqual(EndpointDetection.objects.count(), 1)  # el SOC la ve igual en su cola

    def test_late_events_are_recorded_as_expired(self):
        ingest_events([alert('1118', detected(), ident='a', stamp=self.now)],
                      self.now + timedelta(hours=3))
        [urgent] = self.alerts()
        self.assertEqual(urgent.status, 'expired')


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class EndpointReconciliationTests(TestCase):
    """Recuperación de eventos de Defender desde el indexador (invariante 5 y sin duplicados)."""

    def setUp(self):
        from .models import WorkerState
        self.now = timezone.now()
        self.company = Client.objects.create(name='Talleres Ejemplo', code='te', urgent_alerts_enabled=True,
                                             urgent_email='it@te.test')
        ingest_events([alert('1150', stamp=self.now - timedelta(hours=5), ident='seed')], self.now)
        EndpointAgent.objects.update(status='assigned', client=self.company, assigned_at=self.now - timedelta(hours=4))
        self.state = lambda: WorkerState.objects.filter(name=endpoints.RECONCILE_STATE).first()

    def hit(self, event_id, eventdata=None, minutes=30, ident='x', agent='003'):
        source = alert(event_id, eventdata, agent=agent, stamp=self.now - timedelta(minutes=minutes), ident=ident)
        return {'_index': 'wazuh-alerts-4.x-2026.11.23', '_id': ident, '_source': source,
                'sort': [source['timestamp'], ident, 'wazuh-alerts-4.x-2026.11.23']}

    def run_with(self, *responses, **kwargs):
        from unittest import mock
        replies = list(responses)
        with mock.patch('core.reporting.indexer_authorization', return_value='Basic x'), \
                mock.patch('core.reporting._search', side_effect=lambda body, auth: replies.pop(0)) as search:
            count = endpoints.reconcile(self.now, **kwargs)
        return count, search

    @staticmethod
    def page(*hits):
        return {'timed_out': False, '_shards': {'failed': 0}, 'hits': {'hits': list(hits)}}

    def test_missing_detection_and_its_alert_are_recovered_once(self):
        from .models import UrgentAlert
        page = self.page(self.hit('1116', detected(), ident='a'), self.hit('1118', detected(), minutes=29, ident='b'))
        count, search = self.run_with(page)
        body = search.call_args.args[0]
        self.assertIn({'term': {'data.win.system.channel': endpoints.CHANNEL}}, body['query']['bool']['filter'])
        self.assertEqual(count, 2)
        row = EndpointDetection.objects.get()
        self.assertEqual(row.action, 'failed')
        self.assertIn('completed_until', self.state().details)
        self.assertEqual(UrgentAlert.objects.get().status, 'pending')  # 29 min: todavía a tiempo
        # La siguiente ventana vuelve a ver los mismos eventos por el solape: nada se duplica.
        EndpointAgent.objects.update(name='PC-CONTA-01')
        self.run_with(page)
        self.assertEqual((EndpointDetection.objects.count(), UrgentAlert.objects.count()), (1, 1))

    def test_incomplete_answer_keeps_the_cursor_and_raises_an_issue(self):
        from .models import OperationalIssue
        self.run_with(self.page())
        before = dict(self.state().details)
        broken = {'timed_out': True, '_shards': {'failed': 0}, 'hits': {'hits': [self.hit('1116', detected())]}}
        self.run_with(broken)
        self.assertEqual(self.state().details, before)  # invariante 5
        self.assertFalse(EndpointDetection.objects.exists())
        self.assertTrue(OperationalIssue.objects.filter(key=endpoints.RECONCILE_ISSUE, active=True).exists())
        self.run_with(self.page())
        self.assertFalse(OperationalIssue.objects.filter(key=endpoints.RECONCILE_ISSUE, active=True).exists())

    def test_pages_resume_with_a_stable_cursor(self):
        first = self.page(self.hit('1116', detected(), ident='a'))
        second = self.page()
        self.run_with(first, second, page_size=1)
        self.assertEqual(EndpointDetection.objects.count(), 1)
        self.assertIn('completed_until', self.state().details)

    def test_firewall_agents_are_left_to_the_firewall_reconciliation(self):
        site = Site.objects.create(client=self.company, name='Palma', code='palma')
        Device.objects.create(site=site, name='FW', vendor='opnsense', log_method='wazuh_agent', wazuh_identifier='007')
        self.run_with(self.page(self.hit('1116', detected(), agent='007')))
        self.assertFalse(EndpointAgent.objects.filter(agent_id='007').exists())

    def test_a_late_old_event_does_not_undo_a_newer_state(self):
        self.run_with(self.page(self.hit('5000', minutes=10, ident='on'), self.hit('5010', minutes=60, ident='old-off')))
        agent = EndpointAgent.objects.get()
        self.assertTrue(agent.realtime_enabled)
        self.assertIsNone(agent.scanning_disabled_at)

"""Propagación a los firewalls y mejoras de plantilla con el control de cambios."""
import json
from datetime import timedelta
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from . import blocklist, change_control, propagation, template_updates
from .change_control import process_queue, stage
from .models import (BlocklistFeed, ChangePlan, Client, Device, ExportConfiguration, IpReputation, ManualBlock,
                     OperationalIssue, OpnsenseConnection, SecurityEvidence, Site, WorkerState)
from .test_blocklist import FakeOpnsenseWithAliases

FW_IP = '203.0.113.7'
ATTACKER = '45.155.205.10'


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False, SOC_PUBLIC_ORIGIN='https://soc.example.test',
                   SOC_TRUSTED_PROXIES=[])
class Base(TestCase):
    def setUp(self):
        self.now = timezone.now()
        self.company = Client.objects.create(name='Talleres', code='t')
        self.site = Site.objects.create(client=self.company, name='Palma', code='p')
        self.device = Device.objects.create(site=self.site, name='FW-Palma', vendor='opnsense', management_method='api')
        OpnsenseConnection.objects.create(device=self.device, api_url='https://fw.example.test', encrypted_api_key='x',
                                          encrypted_api_secret='x')
        ExportConfiguration.objects.create(device=self.device, source_ip=FW_IP)
        self.feed = BlocklistFeed.objects.create(client=self.company, enabled=True, include_cti=False)
        self.token = blocklist.rotate_token(self.feed)
        SecurityEvidence.objects.create(uid='a' * 64, device=self.device, observed_at=self.now - timedelta(hours=2),
                                        engine='suricata', signature='x', source_ip=ATTACKER, destination_ip='10.0.0.5',
                                        action='blocked', level=8, client_scope_id=self.company.pk)
        IpReputation.objects.create(ip=ATTACKER, listed=True, lists_checked_at=self.now)
        self.plan = ChangePlan.objects.create(device=self.device, template='crowdsec', title=blocklist.TITLE, status='active',
                                              template_version='1.0', parameters={'client': self.company.pk},
                                              preview={**blocklist.plan_preview(self.device), 'alias': {'type': 'urltable', 'updatefreq': '0.04'}},
                                              remote_objects=[{'kind': 'alias', 'uuid': 'alias-1',
                                                               'rule': {'description': 'SOC PLAN 1 alias', 'name': 'SOC_CROWDSEC_1'}}])

    def run_job(self, now=None):
        with mock.patch.object(change_control, 'api', side_effect=FakeOpnsenseWithAliases({})):
            return propagation.propagate(now or self.now)

    def fetch(self, ip=FW_IP):
        return self.client.get(reverse('blocklist_serve', args=[self.company.pk, self.token]), REMOTE_ADDR=ip)

    def rows(self, now=None):
        return {(r['device'].name if r.get('device') else r['site'].name, r['kind']): r for r in
                propagation.overview_rows(now or self.now)[0]}


class PropagationTests(Base):
    def test_new_source_data_is_recalculated_at_once_and_tracked_per_firewall(self):
        self.run_job()
        self.feed.refresh_from_db()
        self.assertEqual([e['ip'] for e in self.feed.entries], [ATTACKER], 'recalculada sin esperar al trabajo de 15 minutos')
        row = self.rows()[('FW-Palma', 'in')]
        self.assertEqual(row['state'], 'pending')
        self.fetch()
        self.assertEqual(self.rows()[('FW-Palma', 'in')]['state'], 'ok')
        self.assertTrue(self.rows()[('FW-Palma', 'in')]['exact'], 'por la IP conocida del equipo')

    def test_a_change_without_download_becomes_late_with_an_issue_that_closes_itself(self):
        self.run_job()
        self.fetch()
        ManualBlock.objects.create(client=self.company, network='198.51.100.0/24', reason='Caso 12', direction='in',
                                   expires_at=self.now + timedelta(days=1))
        later = self.now + timedelta(minutes=5)
        self.run_job(later)
        self.assertEqual(self.rows(later)[('FW-Palma', 'in')]['state'], 'pending')
        # Versión 1.0: tabla cada ~58 min + 30 de margen.
        much_later = later + timedelta(hours=2)
        self.run_job(much_later)
        self.assertEqual(self.rows(much_later)[('FW-Palma', 'in')]['state'], 'late')
        issue = OperationalIssue.objects.get(key__startswith=propagation.ISSUE_PREFIX, active=True)
        self.assertIn('FW-Palma', issue.title)
        # El firewall descarga después del cambio (reloj simulado: se anota como lo haría `serve`).
        BlocklistFeed.objects.filter(pk=self.feed.pk).update(
            fetch_sources={'in': {FW_IP: (much_later + timedelta(minutes=1)).isoformat()}})
        self.run_job(much_later + timedelta(minutes=2))
        self.assertFalse(OperationalIssue.objects.filter(key__startswith=propagation.ISSUE_PREFIX, active=True).exists())

    def test_unchanged_sources_do_not_recalculate_every_run(self):
        self.run_job()
        with mock.patch.object(blocklist, 'refresh_feeds') as refresh:
            self.run_job(self.now + timedelta(minutes=5))
        refresh.assert_not_called()

    def test_dns_lists_are_reloaded_on_change_at_most_every_fifteen_minutes(self):
        from .qfeeds_distribution import DNS_TEMPLATE
        BlocklistFeed.objects.filter(pk=self.feed.pk).update(qfeeds_dns=True)
        ChangePlan.objects.create(device=self.device, template=DNS_TEMPLATE, title='DNS', status='active',
                                  parameters={'client': self.company.pk},
                                  remote_objects=[{'kind': 'dnsbl', 'uuid': 'd1', 'rule': {'description': 'x'}}])
        calls = []

        def fake(connection, path, payload=None, method=None):
            calls.append(path)
            return {'status': 'OK'}
        with mock.patch('core.qfeeds_distribution.servable_dns', return_value=['malo.example.com']), \
                mock.patch.object(change_control, 'api', side_effect=fake):
            propagation.propagate(self.now)
            propagation.propagate(self.now + timedelta(minutes=5))
            propagation.propagate(self.now + timedelta(minutes=20))
        self.assertEqual(calls.count('/api/unbound/service/dnsbl'), 2)


class TemplateUpdateTests(Base):
    def test_job_prepares_one_draft_and_approval_changes_only_the_soc_alias(self):
        self.run_job()
        self.run_job(self.now + timedelta(minutes=5))
        update = ChangePlan.objects.get(template=template_updates.UPDATE_TEMPLATE)
        self.assertEqual((update.status, update.parameters['plan'], update.preview['update']['changes']),
                         ('draft', self.plan.pk, {'updatefreq': '0.01'}))
        self.assertEqual(self.rows()[('FW-Palma', 'in')]['update'], update)
        firewall = FakeOpnsenseWithAliases({})
        firewall.aliases['alias-1'] = {'name': 'SOC_CROWDSEC_1', 'description': 'SOC PLAN 1 alias', 'updatefreq': '0.04',
                                       'type': 'urltable'}
        firewall.aliases['ajeno'] = {'name': 'CLIENTE', 'description': 'Del cliente', 'updatefreq': '1'}

        def fw(connection, path, payload=None, method=None):
            if path.startswith('/api/firewall/alias/set_item/'):
                firewall.aliases[path.rsplit('/', 1)[1]].update(payload['alias'])
                return {'result': 'saved'}
            return firewall(connection, path, payload, method)
        with mock.patch.object(change_control, 'api', side_effect=fw):
            stage(update)
            self.assertEqual(update.status, 'staged')
            self.assertEqual(update.remote_objects[0]['previous'], '0.04')
            update.approved_by = get_user_model().objects.create_user('aprobador')
            update.status = 'apply_queued'
            update.save()
            process_queue()
            update.refresh_from_db()
            self.assertEqual(update.status, 'awaiting_confirmation')
            self.assertEqual(firewall.aliases['alias-1']['updatefreq'], '0.01')
            self.assertEqual(firewall.aliases['ajeno']['updatefreq'], '1')
            ChangePlan.objects.filter(pk=update.pk).update(status='confirm_queued')
            process_queue()
        update.refresh_from_db()
        self.plan.refresh_from_db()
        self.assertEqual((update.status, self.plan.parameters['version_applied']), ('active', '1.1'))
        self.assertFalse(template_updates.outdated(self.plan))
        self.assertEqual(template_updates.prepare_all(), 0)
        # Revertir vuelve al valor anotado y a la versión anterior.
        ChangePlan.objects.filter(pk=update.pk).update(status='rollback_queued')
        with mock.patch.object(change_control, 'api', side_effect=fw):
            process_queue()
        self.plan.refresh_from_db()
        self.assertEqual((firewall.aliases['alias-1']['updatefreq'], self.plan.parameters['version_applied']), ('0.04', '1.0'))

    def test_alias_owned_by_someone_else_is_never_changed(self):
        update = template_updates.create(self.plan)
        firewall = FakeOpnsenseWithAliases({})
        firewall.aliases['alias-1'] = {'name': 'SOC_CROWDSEC_1', 'description': 'Cambiado por alguien', 'updatefreq': '0.04'}
        with mock.patch.object(change_control, 'api', side_effect=firewall):
            stage(update)
        self.assertEqual(update.status, 'failed')
        self.assertEqual(firewall.aliases['alias-1']['updatefreq'], '0.04')

    def test_new_plans_already_use_the_faster_refresh(self):
        self.assertEqual(blocklist.plan_preview(self.device)['alias']['updatefreq'], '0.01')
        from .qfeeds_distribution import dns_plan_preview
        self.assertEqual(dns_plan_preview(self.device)['dnsbl']['cache_ttl'], '900')
        self.assertEqual(blocklist.VERSION, template_updates.LATEST)


class PageTests(Base):
    def test_blocklists_page_shows_propagation_and_pending_improvements(self):
        self.run_job()
        admin = get_user_model().objects.create_superuser('admin', 'a@example.test', 'x')
        self.client.force_login(admin)
        page = self.client.get(reverse('blocklists'))
        self.assertContains(page, 'Propagación a los firewalls')
        self.assertContains(page, 'FW-Palma')
        self.assertContains(page, 'Mejora de plantilla preparada')
        update = ChangePlan.objects.get(template=template_updates.UPDATE_TEMPLATE)
        page = self.client.get(reverse('change_detail', args=[update.pk]))
        self.assertContains(page, 'updatefreq')
        self.assertNotIn(self.token, json.dumps(update.preview))
        self.assertTrue(WorkerState.objects.filter(name=propagation.STATE).exists())

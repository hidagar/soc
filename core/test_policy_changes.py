"""Fase 2 de las políticas: restringir un servicio publicado con el control de cambios (OPNsense simulado)."""
import time
from datetime import timedelta
from unittest import mock

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from . import change_control, policy_changes, policy_proposals
from .change_control import enable, rollback, stage
from .models import ChangePlan, Client, Device, ExposureFinding, OpnsenseConnection, PolicyProposal, Site, StaffAccess
from .test_blocklist import FakeOpnsenseWithAliases


class FakeFirewall(FakeOpnsenseWithAliases):
    """Añade la consulta de la tabla cargada de un alias; `empty_tables` simula que no se cargó."""
    empty_tables = False

    def __call__(self, connection, path, payload=None, method=None):
        if path.startswith('/api/firewall/alias_util/list/'):
            name = path.rsplit('/', 1)[1]
            alias = next((a for a in self.aliases.values() if a.get('name') == name), None)
            rows = [] if self.empty_tables or not alias else [{'ip': ip} for ip in alias['content'].split('\n')]
            return {'total': len(rows), 'rows': rows}
        return super().__call__(connection, path, payload, method)


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class PolicyChangeTests(TestCase):
    def setUp(self):
        self.now = timezone.now()
        self.company = Client.objects.create(name='Empresa A', code='a')
        site = Site.objects.create(client=self.company, name='Palma', code='palma')
        self.fw = Device.objects.create(site=site, name='FW-Palma', vendor='opnsense', management_method='api')
        OpnsenseConnection.objects.create(device=self.fw, api_url='https://fw.example.test', encrypted_api_key='x', encrypted_api_secret='x')
        self.finding = ExposureFinding.objects.create(
            device=self.fw, section='nat', remote_id='r1', kind='publication', title='Servicio publicado en WAN', severity='high',
            recommendation='-', fingerprint='x', evidence={'name': 'RDP contabilidad', 'source': 'any', 'interface': 'wan', 'protocol': 'tcp',
                                                            'port': '3389', 'target_port': '3389', 'destination': '10.0.0.20'})
        self.proposal = PolicyProposal.objects.create(
            client=self.company, device=self.fw, exposure=self.finding, kind='restrict_service', key=f'restrict:{self.finding.pk}',
            title='Restringir RDP', change='c', risk='r', status='approved', evidence={'service': 'escritorio remoto (RDP)', 'ports': ['3389']})
        self.firewall = FakeFirewall({'existing': {'description': 'Regla del cliente', 'enabled': '1'}})
        patcher = mock.patch.object(change_control, 'api', side_effect=self.firewall)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.user = get_user_model().objects.create_user('admin-soc')
        StaffAccess.objects.create(user=self.user, role='manager', all_clients=True)
        self.user.user_permissions.add(*Permission.objects.filter(codename__in=['change_device', 'manage_connections', 'change_incident']))

    def plan(self, origins=('203.0.113.10', '198.51.100.0/28')):
        return policy_changes.create_plan(self.proposal, list(origins), self.user)

    def test_origins_are_validated(self):
        self.assertEqual(policy_changes.parse_origins('203.0.113.10, 198.51.100.7/28\n203.0.113.10'), ['203.0.113.10', '198.51.100.0/28'])
        for bad in ('', 'proveedor', '0.0.0.0/0', '10.0.0.0/8', '2001:db8::1'):
            with self.assertRaises(ValueError, msg=bad):
                policy_changes.parse_origins(bad)
        with self.assertRaises(ValueError):
            policy_changes.parse_origins('\n'.join(f'203.0.113.{n}' for n in range(1, 23)))

    def test_only_safe_cases_are_automated(self):
        self.assertEqual(policy_changes.automatable(self.proposal), '')
        for field, value in (('interface', 'wan,opt1'), ('destination', '(self)'), ('port', 'PUERTOS_WEB'), ('protocol', 'any')):
            evidence = {**self.finding.evidence, field: value}
            if field == 'port':
                evidence['target_port'] = value
            ExposureFinding.objects.filter(pk=self.finding.pk).update(evidence=evidence)
            self.proposal.refresh_from_db()
            self.assertIn('a mano', policy_changes.automatable(self.proposal), field)
        ExposureFinding.objects.filter(pk=self.finding.pk).update(evidence=self.finding.evidence)
        Device.objects.filter(pk=self.fw.pk).update(vendor='unifi')
        self.proposal.refresh_from_db()
        self.assertIn('OPNsense', policy_changes.automatable(self.proposal))

    def test_stage_creates_only_owned_disabled_objects_and_rollback_removes_them(self):
        plan = self.plan()
        self.assertEqual((plan.status, self.firewall.calls), ('draft', []))  # el borrador no toca el firewall
        stage(plan)
        self.assertEqual(plan.status, 'staged')
        [alias] = self.firewall.aliases.values()
        self.assertEqual((alias['name'], alias['type'], alias['content']), (f'SOC_POL_{plan.pk}', 'network', '203.0.113.10\n198.51.100.0/28'))
        [rule] = self.firewall.owned(plan).values()
        self.assertEqual((rule['enabled'], rule['action'], rule['interface'], rule['source_net'], rule['source_not'],
                          rule['destination_net'], rule['destination_port'], rule['protocol']),
                         ('0', 'block', 'wan', alias['name'], '1', '10.0.0.20', '3389', 'TCP'))
        self.assertFalse(any('/api/ids/' in call or 'zenarmor' in call or 'nat' in call for call in self.firewall.calls))
        enable(plan)
        self.assertEqual(plan.status, 'awaiting_confirmation')
        rollback(plan, delete=True)
        self.assertEqual((self.firewall.owned(plan), self.firewall.aliases), ({}, {}))
        self.assertEqual(self.firewall.rules['existing'], {'description': 'Regla del cliente', 'enabled': '1'})

    def test_empty_table_aborts_staging_and_leaves_nothing_behind(self):
        self.firewall.empty_tables = True
        plan = self.plan()
        stage(plan)
        self.assertEqual(plan.status, 'failed')
        self.assertEqual((self.firewall.owned(plan), self.firewall.aliases), ({}, {}))

    def test_active_plan_marks_applied_verifies_and_stops_reproposing(self):
        plan = self.plan()
        ChangePlan.objects.filter(pk=plan.pk).update(status='active', approved_by=self.user)
        self.assertEqual(policy_changes.sync_applied(self.now), 1)
        self.proposal.refresh_from_db()
        self.assertEqual((self.proposal.status, self.proposal.applied_by), ('applied', self.user))
        PolicyProposal.objects.filter(pk=self.proposal.pk).update(applied_at=self.now - timedelta(days=8))
        policy_proposals.verify(self.now)
        self.proposal.refresh_from_db()
        self.assertEqual(self.proposal.status, 'verified')  # aunque la publicación siga «a cualquiera»
        self.assertIn('sigue activa', self.proposal.verification['text'])
        policy_proposals.generate(self.now)
        self.assertEqual(PolicyProposal.objects.get(pk=self.proposal.pk).status, 'verified')  # no se vuelve a proponer
        # Si alguien revierte la regla, la verificación lo detecta.
        PolicyProposal.objects.filter(pk=self.proposal.pk).update(status='applied')
        ChangePlan.objects.filter(pk=plan.pk).update(status='rolled_back')
        policy_proposals.verify(self.now)
        self.assertEqual(PolicyProposal.objects.get(pk=self.proposal.pk).status, 'not_effective')

    def test_page_creates_the_draft_and_needs_permissions(self):
        self.client.force_login(self.user)
        session = self.client.session
        session.update({'soc_mfa_user': self.user.pk, 'soc_mfa_at': time.time()})
        session.save()
        self.assertContains(self.client.get(reverse('policies')), 'Preparar con el control de cambios')
        response = self.client.post(reverse('policies'), {'action': 'plan', 'proposal': self.proposal.pk, 'origins': '0.0.0.0/0'}, follow=True)
        self.assertContains(response, 'demasiado amplia')
        self.assertFalse(ChangePlan.objects.exists())
        response = self.client.post(reverse('policies'), {'action': 'plan', 'proposal': self.proposal.pk, 'origins': '203.0.113.10'})
        plan = ChangePlan.objects.get()
        self.assertRedirects(response, reverse('change_detail', args=[plan.pk]), fetch_redirect_response=False)
        self.assertEqual((plan.status, plan.template, plan.parameters['origins']), ('draft', 'policy_restrict', ['203.0.113.10']))
        self.assertEqual(self.firewall.calls, [])
        self.assertContains(self.client.get(reverse('policies')), 'Abrir el plan')
        self.assertContains(self.client.get(reverse('change_detail', args=[plan.pk])), '203.0.113.10')
        operator = get_user_model().objects.create_user('operador')
        StaffAccess.objects.create(user=operator, role='operator', all_clients=True)
        operator.user_permissions.add(Permission.objects.get(codename='change_device'))
        self.client.force_login(operator)
        self.assertEqual(self.client.post(reverse('policies'), {'action': 'plan', 'proposal': self.proposal.pk, 'origins': '203.0.113.11'}).status_code, 403)

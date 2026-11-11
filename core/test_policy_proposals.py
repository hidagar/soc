"""Políticas de firewall propuestas: motor, revisión del SOC, aprobación del cliente y verificación."""
import hashlib
import time
from datetime import timedelta
from unittest import mock

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from . import policy_proposals as engine, policy_views
from .models import (AuditEvent, BlocklistFeed, ChangePlan, Client, Device, DeviceHealth, ExposureFinding, PolicyProposal,
                     RecoverySettings, SecurityEvidence, Site, StaffAccess, ThreatIntelMatch)

COUNTRIES = ['CN', 'RU', 'US', 'BR', 'IN']


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class PolicyProposalTests(TestCase):
    def setUp(self):
        self.now = timezone.now()
        self.company = Client.objects.create(name='Empresa A', code='a', contact_email='it@a.test', task_notices_enabled=True)
        self.other = Client.objects.create(name='Empresa B', code='b')
        self.site = Site.objects.create(client=self.company, name='Palma', code='palma')
        self.fw = Device.objects.create(site=self.site, name='FW-Palma', vendor='opnsense')
        self.rdp = ExposureFinding.objects.create(
            device=self.fw, section='nat', remote_id='r1', kind='publication', title='Servicio publicado en WAN', severity='high',
            recommendation='-', fingerprint='x', evidence={'name': 'RDP contabilidad', 'source': 'any', 'port': '3389',
                                                            'target_port': '3389', 'destination': '10.0.0.20'})
        other_site = Site.objects.create(client=self.other, name='Inca', code='inca')
        self.other_fw = Device.objects.create(site=other_site, name='FW-Inca', vendor='opnsense')
        User = get_user_model()
        self.operator = User.objects.create_user('operador')
        access = StaffAccess.objects.create(user=self.operator, role='operator')
        access.clients.add(self.company)
        self.operator.user_permissions.add(*Permission.objects.filter(codename__in=['change_incident', 'change_device']))
        self.customer = User.objects.create_user('ana', email='ana@a.test')
        StaffAccess.objects.create(user=self.customer, role='customer').clients.add(self.company)

    def attack(self, n, port='3389', action='blocked', device=None, country=None, start=0):
        for i in range(start, start + n):
            SecurityEvidence.objects.create(
                uid=hashlib.sha256(f'{port}{action}{i}'.encode()).hexdigest(), device=device or self.fw, observed_at=self.now - timedelta(days=2),
                engine='suricata', signature='ET SCAN RDP', action=action, source_ip=f'198.51.{i // 250}.{i % 250 + 1}',
                destination_ip='10.0.0.20', destination_port=port,
                geography={'country_code': country or COUNTRIES[i % len(COUNTRIES)], 'direction': 'inbound'})

    def login(self, user):
        self.client.force_login(user)
        session = self.client.session
        session.update({'soc_mfa_user': user.pk, 'soc_mfa_at': time.time()})
        session.save()

    def test_exposed_service_with_attacks_becomes_a_proposal_with_evidence(self):
        self.attack(25)
        self.attack(2, action='allowed', start=100)
        self.attack(5, port='443', start=200)  # otro puerto: no cuenta
        engine.generate(self.now)
        restrict = PolicyProposal.objects.get(key=f'restrict:{self.rdp.pk}')
        stats = restrict.evidence['attacks']
        self.assertEqual((stats['total'], stats['allowed'], restrict.confidence), (27, 2, 'high'))
        self.assertEqual(restrict.evidence['service'], 'escritorio remoto (RDP)')
        self.assertIn('NAT › Reenvío de puertos «RDP contabilidad»', restrict.change)
        geo = PolicyProposal.objects.get(key=f'geo:{self.rdp.pk}')
        self.assertEqual(geo.kind, 'geo_filter')
        self.assertFalse(PolicyProposal.objects.filter(client=self.other).exists())
        # Si la publicación deja de estar abierta antes de ofrecerla, la propuesta ya no aplica.
        self.rdp.evidence = {**self.rdp.evidence, 'source': 'PROVEEDOR'}
        self.rdp.save()
        engine.generate(self.now)
        self.assertEqual(PolicyProposal.objects.get(pk=restrict.pk).status, 'obsolete')

    def test_home_country_attacks_do_not_suggest_a_geo_filter(self):
        self.attack(30, country='ES')
        engine.generate(self.now)
        self.assertTrue(PolicyProposal.objects.filter(kind='restrict_service').exists())
        self.assertFalse(PolicyProposal.objects.filter(kind='geo_filter').exists())

    def test_ips_in_detection_c2_and_blocklist_rules(self):
        DeviceHealth.objects.create(device=self.fw, api_ok=True, checked_at=self.now, protection_checked_at=self.now, last_log_at=self.now,
                                    engines={'Suricata': {'configured': True, 'running': True, 'mode': 'ids'}})
        for port in ('80', '81', '82'):  # los mismos 12 orígenes atacan tres veces
            self.attack(12, port=port, action='allowed')
        ThreatIntelMatch.objects.create(client=self.company, ip='203.0.113.50', role='destination', events=3, allowed=2,
                                        first_seen=self.now, last_seen=self.now, peers=['10.0.0.7'])
        engine.generate(self.now)
        kinds = set(PolicyProposal.objects.values_list('kind', flat=True))
        self.assertTrue({'ips_block', 'outbound_c2', 'inbound_blocklist'} <= kinds, kinds)
        self.assertEqual(PolicyProposal.objects.get(kind='outbound_c2').evidence['internal_hosts'], 1)

    def test_full_flow_offer_approve_apply_and_verify(self):
        self.attack(25)
        engine.generate(self.now)
        proposal = PolicyProposal.objects.get(kind='restrict_service')
        self.login(self.operator)
        page = self.client.get(reverse('policies'))
        self.assertContains(page, 'Restringir el acceso a escritorio remoto (RDP)')
        planned = (timezone.localtime(self.now) + timedelta(days=2)).strftime('%Y-%m-%dT%H:%M')
        self.client.post(reverse('policies'), {'action': 'offer', 'proposal': proposal.pk, 'planned_for': planned,
                                               'customer_title': 'Limitar el acceso remoto', 'customer_text': 'Texto para el cliente'})
        proposal.refresh_from_db()
        self.assertEqual((proposal.status, proposal.notice_status, proposal.notice_recipient), ('offered', 'queued', 'it@a.test'))
        self.assertEqual(proposal.customer_summary['attacks'], 25)
        self.assertNotIn('10.0.0.20', str(proposal.customer_summary))  # nada interno en lo que ve el cliente
        with mock.patch('core.mail_delivery.send_customer_email', return_value='m1') as send:
            self.assertEqual(policy_views.send_pending(now=self.now), 1)
            self.assertEqual(policy_views.send_pending(now=self.now), 0)
        self.assertEqual(send.call_args.kwargs['delivery_context'], {'client': self.company, 'kind': 'policy'})
        self.assertNotIn('RDP', send.call_args.args[2])
        # El cliente lo ve y lo aprueba con MFA reciente.
        self.login(self.customer)
        portal = self.client.get(reverse('customer_policies'))
        self.assertContains(portal, 'Limitar el acceso remoto')
        self.assertNotContains(portal, '10.0.0.20')
        self.assertNotContains(portal, 'RDP contabilidad')
        self.assertContains(self.client.get(reverse('customer_home')), 'pendiente de vuestra decisión')
        session = self.client.session
        session['soc_mfa_at'] = 0
        session.save()
        response = self.client.post(reverse('customer_policy_decision', args=[proposal.pk]), {'decision': 'approved'})
        self.assertRedirects(response, reverse('mfa_challenge'), fetch_redirect_response=False)
        self.login(self.customer)
        self.client.post(reverse('customer_policy_decision', args=[proposal.pk]), {'decision': 'approved', 'note': 'Proveedor: 203.0.113.10'})
        proposal.refresh_from_db()
        self.assertEqual((proposal.status, proposal.decided_by, proposal.decision_note), ('approved', self.customer, 'Proveedor: 203.0.113.10'))
        self.assertTrue(AuditEvent.objects.filter(action='customer.policy_decision').exists())
        # Una segunda decisión ya no cambia nada.
        self.client.post(reverse('customer_policy_decision', args=[proposal.pk]), {'decision': 'rejected'})
        self.assertEqual(PolicyProposal.objects.get(pk=proposal.pk).status, 'approved')
        RecoverySettings.objects.update_or_create(pk=1, defaults={'notify_enabled': True, 'operational_email': 'noc@ibred.test'})
        with mock.patch('core.mail_delivery.send_customer_email', return_value='x') as send:
            self.assertEqual(policy_views.notify_soc(self.now), 1)
            self.assertEqual(policy_views.notify_soc(self.now), 0)
        self.assertIn('APROBADA', send.call_args.args[2])
        # El SOC lo aplica y la verificación lo comprueba a los 7 días.
        self.login(self.operator)
        self.client.post(reverse('policies'), {'action': 'applied', 'proposal': proposal.pk, 'note': 'Origen limitado al alias PROVEEDOR'})
        proposal.refresh_from_db()
        self.assertEqual(proposal.status, 'applied')
        self.assertEqual(engine.verify(self.now + timedelta(days=1)), 0)  # aún no toca
        later = self.now + timedelta(days=8)
        self.assertEqual(engine.verify(later), 1)
        self.assertEqual(PolicyProposal.objects.get(pk=proposal.pk).status, 'not_effective')  # sigue abierto a cualquiera
        PolicyProposal.objects.filter(pk=proposal.pk).update(status='applied')
        self.rdp.evidence = {**self.rdp.evidence, 'source': 'PROVEEDOR'}
        self.rdp.save()
        engine.verify(later)
        proposal.refresh_from_db()
        self.assertEqual(proposal.status, 'verified')
        self.assertIn('ya no está abierto', proposal.verification['text'])

    def test_customer_rejects_other_customers_cannot_decide_and_scope(self):
        self.attack(25)
        engine.generate(self.now)
        proposal = PolicyProposal.objects.get(kind='restrict_service')
        PolicyProposal.objects.filter(pk=proposal.pk).update(status='offered', offered_at=self.now, planned_for=self.now + timedelta(days=1),
                                                             customer_title='Limitar el acceso remoto', customer_text='x')
        intruder = get_user_model().objects.create_user('beto')
        StaffAccess.objects.create(user=intruder, role='customer').clients.add(self.other)
        self.login(intruder)
        self.assertEqual(self.client.post(reverse('customer_policy_decision', args=[proposal.pk]), {'decision': 'approved'}).status_code, 404)
        self.assertNotContains(self.client.get(reverse('customer_policies')), 'Limitar el acceso remoto')
        self.assertEqual(self.client.get(reverse('policies')).status_code, 403)
        self.login(self.customer)
        self.client.post(reverse('customer_policy_decision', args=[proposal.pk]), {'decision': 'rejected', 'note': 'Lo usa el proveedor'})
        self.assertEqual(PolicyProposal.objects.get(pk=proposal.pk).status, 'rejected')
        other = PolicyProposal.objects.create(client=self.other, kind='ips_block', key='ips:x', title='Ajena', change='-', risk='-')
        self.login(self.operator)
        page = self.client.get(reverse('policies') + '?state=all')
        self.assertNotContains(page, 'Ajena')
        self.client.post(reverse('policies'), {'action': 'dismiss', 'proposal': other.pk, 'reason': 'x'})
        self.assertEqual(PolicyProposal.objects.get(pk=other.pk).status, 'proposed')

    def test_offer_needs_window_dismiss_needs_reason_and_reader_cannot_act(self):
        self.attack(25)
        engine.generate(self.now)
        proposal = PolicyProposal.objects.get(kind='restrict_service')
        self.login(self.operator)
        self.client.post(reverse('policies'), {'action': 'offer', 'proposal': proposal.pk, 'customer_title': 't', 'customer_text': 'x'})
        self.assertEqual(PolicyProposal.objects.get(pk=proposal.pk).status, 'proposed')
        self.client.post(reverse('policies'), {'action': 'dismiss', 'proposal': proposal.pk})
        self.assertEqual(PolicyProposal.objects.get(pk=proposal.pk).status, 'proposed')
        reader = get_user_model().objects.create_user('lector')
        StaffAccess.objects.create(user=reader, role='reader').clients.add(self.company)
        self.login(reader)
        self.assertEqual(self.client.post(reverse('policies'), {'action': 'dismiss', 'proposal': proposal.pk, 'reason': 'x'}).status_code, 403)

    def test_blocklist_verification_and_reproposal_after_90_days(self):
        ThreatIntelMatch.objects.create(client=self.company, ip='203.0.113.50', role='destination', events=3, allowed=0,
                                        first_seen=self.now, last_seen=self.now, peers=[])
        engine.generate(self.now)
        proposal = PolicyProposal.objects.get(kind='outbound_c2')
        PolicyProposal.objects.filter(pk=proposal.pk).update(status='applied', applied_at=self.now - timedelta(days=8))
        engine.verify(self.now)
        self.assertEqual(PolicyProposal.objects.get(pk=proposal.pk).status, 'not_effective')
        BlocklistFeed.objects.create(client=self.company, enabled=True, outbound_enabled=True)
        ChangePlan.objects.create(device=self.fw, template='crowdsec_out', title='Salida C2', status='active')
        PolicyProposal.objects.filter(pk=proposal.pk).update(status='applied')
        engine.verify(self.now)
        self.assertEqual(PolicyProposal.objects.get(pk=proposal.pk).status, 'verified')
        # Rechazada hace más de 90 días y la situación sigue: se vuelve a proponer.
        self.attack(25)
        engine.generate(self.now)
        restrict = PolicyProposal.objects.get(kind='restrict_service')
        PolicyProposal.objects.filter(pk=restrict.pk).update(status='rejected', decided_at=self.now - timedelta(days=91))
        engine.generate(self.now)
        self.assertEqual(PolicyProposal.objects.get(pk=restrict.pk).status, 'proposed')

    def test_preview_is_read_only(self):
        self.attack(25)
        engine.generate(self.now)
        PolicyProposal.objects.filter(kind='restrict_service').update(status='offered', offered_at=self.now, planned_for=self.now,
                                                                     customer_title='Limitar el acceso remoto', customer_text='x')
        self.login(self.operator)
        page = self.client.get(reverse('customer_preview_policies', args=[self.company.pk]))
        self.assertContains(page, 'Limitar el acceso remoto')
        self.assertNotContains(page, 'Aprobar el cambio')

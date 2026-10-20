from datetime import timedelta
from unittest.mock import patch
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase, override_settings, Client as Browser
from django.urls import reverse
from django.utils import timezone
from .models import (Client, Site, Device, DeviceHealth, NetworkCoverage, NetworkCheck,
                     Asset, SecurityEvidence, ProtectionValidation, StaffAccess)
from .network_coverage import (opnsense_networks, unifi_networks, save_discovery,
                              discover_networks, snapshot, fingerprint, current)
from .operations_suite import ValidationForm, reconcile_validations
from .network_views import NetworkForm


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class NetworkCoverageTests(TestCase):
    def setUp(self):
        self.now = timezone.now()
        self.company = Client.objects.create(name='Empresa visible', code='network-visible')
        hidden = Client.objects.create(name='Empresa privada', code='network-hidden')
        self.device = Device.objects.create(site=Site.objects.create(client=self.company, name='Oficina', code='office'),
                                           name='Firewall oficina', vendor='opnsense', management_method='api')
        self.other = Device.objects.create(site=Site.objects.create(client=hidden, name='Privada', code='secret'),
                                          name='Firewall privado', vendor='opnsense', management_method='api')
        self.health = DeviceHealth.objects.create(device=self.device, api_ok=True, protection_checked_at=self.now,
            engines={'Suricata': {'configured': True, 'running': True, 'mode': 'ips', 'interfaces': ['lan'], 'interfaces_known': True}})
        save_discovery(self.device, [self.row()], self.now)
        save_discovery(self.other, [self.row(name='Red privada')], self.now)
        self.network = self.device.networks.get()
        self.user = get_user_model().objects.create_user('network-operator')
        self.user.groups.add(Group.objects.get(name='SOC Operador'))
        access = StaffAccess.objects.create(user=self.user, role='operator')
        access.clients.add(self.company)
        self.client.force_login(self.user)

    def row(self, **changes):
        values = {'remote_id': 'lan', 'name': 'Administración', 'interface': 'lan', 'physical_interface': 'igc0',
                  'cidrs': ['192.168.1.0/24'], 'role': 'network', 'enabled': True, 'inspection_selected': True}
        return {**values, **changes}

    def validation(self, engine='suricata'):
        return ProtectionValidation.objects.create(device=self.device, network=self.network, engine=engine,
            networks='Ordenador autorizado', test_ip='192.168.1.20', expected_signature='SOC TEST',
            started_at=self.now - timedelta(minutes=5), expires_at=self.now + timedelta(minutes=55),
            network_snapshot=self.network.cidrs, configuration_fingerprint=fingerprint(self.network, engine))

    def evidence(self, address='192.168.1.20', engine='suricata', signature='SOC TEST', action='blocked', **changes):
        asset, _ = Asset.objects.get_or_create(device=self.device, ip=address)
        return SecurityEvidence.objects.create(uid='proof-' + str(SecurityEvidence.objects.count()), device=self.device,
            asset=asset, engine=engine, signature=signature, action=action, category='security', observed_at=self.now, **changes)

    def test_interface_whitelist_never_persists_config_secrets(self):
        data = {'total': 2, 'rows': [
            {'identifier': 'lan', 'device': 'igc0', 'description': 'Oficina', 'addr4': '192.168.1.1/24',
             'enabled': True, 'config': {'password': 'PRIVATE'}, 'ipv6': [{'ipaddr': 'fd00::1/64'}]},
            {'identifier': 'lo0', 'device': 'lo0', 'addr4': '127.0.0.1/8'}]}
        rows = opnsense_networks(data, self.health.engines['Suricata'])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['cidrs'], ['192.168.1.0/24', 'fd00::/64'])
        self.assertNotIn('PRIVATE', str(rows))
        self.assertTrue(rows[0]['inspection_selected'])

    def test_does_not_inherit_parent_inspection_to_vlan(self):
        rows = opnsense_networks({'total': 1, 'rows': [{'identifier': 'opt1', 'device': 'igc0_vlan20',
            'addr4': '192.168.20.1/24'}]}, {'interfaces_known': True, 'interfaces': ['igc0']})
        self.assertFalse(rows[0]['inspection_selected'])

    def test_partial_catalogue_is_rejected(self):
        with self.assertRaises(ValueError):
            opnsense_networks({'total': 2, 'rows': [{'identifier': 'lan'}]}, {})
        with self.assertRaises(ValueError):
            save_discovery(self.device, [self.row(), self.row()])
        with self.assertRaises(ValueError):
            save_discovery(self.device, [])
        self.network.refresh_from_db()
        self.assertTrue(self.network.present)

    def test_unknown_selection_is_not_interpreted_as_all_networks(self):
        data = {'data': [{'_id': 'a', 'name': 'Invitados', 'ip_subnet': '10.20.0.1/24', 'x_password': 'PRIVATE'}]}
        self.assertIsNone(unifi_networks(data, {'data': [{'key': 'ips', 'ips_mode': 'ips'}]})[0]['inspection_selected'])
        row = unifi_networks(data, {'data': [{'key': 'ips', 'enabled_networks': []}]})[0]
        self.assertFalse(row['inspection_selected'])
        self.assertNotIn('PRIVATE', str(row))

    def test_unifi_exact_network_id_selection(self):
        rows = unifi_networks({'data': [{'_id': 'a', 'name': 'A'}, {'_id': 'b', 'name': 'B'}]},
                             {'data': [{'key': 'ips', 'enabled_networks': ['a']}]})
        self.assertEqual([r['inspection_selected'] for r in rows], [True, False])

    def test_failure_keeps_previous_data_but_marks_it_not_current(self):
        with patch('core.provisioning._api_request', side_effect=ValueError('PRIVATE')):
            self.assertEqual(discover_networks(self.device, {}), 0)
        self.network = NetworkCoverage.objects.select_related('device__network_check', 'device__health').get(pk=self.network.pk)
        self.assertTrue(self.network.present)
        self.assertFalse(snapshot(self.network)['current'])
        self.assertNotIn('PRIVATE', str(NetworkCheck.objects.get(device=self.device).__dict__))

    def test_valid_catalogue_marks_removed_and_preserves_requirements(self):
        self.network.scope = 'included'; self.network.require_ips = True; self.network.save()
        save_discovery(self.device, [self.row(name='Nombre descubierto actualizado')])
        self.network.refresh_from_db()
        self.assertTrue(self.network.require_ips)
        self.assertEqual(self.network.scope, 'included')
        save_discovery(self.device, [self.row(remote_id='opt1')])
        self.network.refresh_from_db()
        self.assertFalse(self.network.present)

    def test_client_scope_and_forged_filters(self):
        response = self.client.get(reverse('network_coverage'))
        self.assertContains(response, 'Administración')
        self.assertNotContains(response, 'Red privada')
        self.assertEqual(self.client.get(reverse('network_coverage'), {'client': self.other.site.client_id}).status_code, 404)
        self.assertEqual(self.client.get(reverse('device_coverage', args=[self.other.pk])).status_code, 404)
        self.assertEqual(self.client.post(reverse('network_requirements', args=[self.other.networks.get().pk]), {'scope': 'included'}).status_code, 404)

    def test_reader_cannot_queue_or_change_requirements(self):
        reader = get_user_model().objects.create_user('network-reader')
        access = StaffAccess.objects.create(user=reader, role='reader'); access.clients.add(self.company)
        reader.groups.add(Group.objects.get(name='SOC Consulta')); self.client.force_login(reader)
        self.assertEqual(self.client.get(reverse('device_coverage', args=[self.device.pk])).status_code, 200)
        self.assertEqual(self.client.post(reverse('device_coverage', args=[self.device.pk])).status_code, 403)
        self.assertEqual(self.client.post(reverse('network_requirements', args=[self.network.pk]), {'scope': 'included'}).status_code, 403)

    def test_customer_cannot_access_internal_matrix(self):
        customer = get_user_model().objects.create_user('network-customer')
        access = StaffAccess.objects.create(user=customer, role='customer'); access.clients.add(self.company)
        self.client.force_login(customer)
        self.assertEqual(self.client.get(reverse('network_coverage')).status_code, 403)

    def test_exclusion_requires_justification_and_future_review(self):
        form = NetworkForm({'scope': 'excluded', 'review_note': '', 'review_until': ''}, instance=self.network)
        self.assertFalse(form.is_valid())
        form = NetworkForm({'scope': 'excluded', 'review_note': 'Otro servicio gestiona invitados',
                            'review_until': (self.now + timedelta(days=20)).isoformat()}, instance=self.network)
        self.assertTrue(form.is_valid(), form.errors)
        self.network = form.save()
        self.assertTrue(snapshot(self.network, self.now)['excluded'])
        self.assertIn('ha vencido', ' '.join(snapshot(self.network, self.now + timedelta(days=21))['gaps']))

    def test_foreign_network_rejected_in_validation_form(self):
        form = ValidationForm({'engine': 'suricata', 'networks': 'Prueba', 'expected_signature': 'SOC TEST',
            'network': self.other.networks.get().pk, 'test_ip': '192.168.1.20'}, device=self.device)
        self.assertFalse(form.is_valid())
        self.assertIn('network', form.errors)

    def test_linked_validation_requires_ip_inside_network_and_current_probe(self):
        data = {'engine': 'suricata', 'networks': 'Prueba', 'expected_signature': 'SOC TEST', 'network': self.network.pk}
        form = ValidationForm({**data, 'test_ip': '192.168.2.20'}, device=self.device)
        self.assertFalse(form.is_valid())
        form = ValidationForm({**data, 'test_ip': '192.168.1.20'}, device=self.device)
        self.assertTrue(form.is_valid(), form.errors)
        DeviceHealth.objects.filter(pk=self.health.pk).update(protection_checked_at=self.now - timedelta(minutes=31))
        form = ValidationForm({**data, 'test_ip': '192.168.1.20'}, device=self.device)
        self.assertFalse(form.is_valid())

    def test_validation_matches_only_exact_test_ip_signature_engine_and_window(self):
        test = self.validation()
        self.evidence(address='192.168.1.21')
        self.evidence(engine='zenarmor')
        self.evidence(signature='Other signature')
        self.assertEqual(reconcile_validations(self.now), 0)
        correct = self.evidence()
        self.assertEqual(reconcile_validations(self.now), 1)
        test.refresh_from_db(); self.assertEqual(test.evidence, correct)

    def test_unknown_action_does_not_prove_blocking(self):
        self.network.scope = 'included'; self.network.require_ips = True; self.network.save()
        test = self.validation(); self.evidence(action='unknown'); reconcile_validations(self.now)
        row = snapshot(self.network, self.now)
        self.assertEqual(len(row['proofs']), 1)
        self.assertIn('no acredita bloqueo', ' '.join(row['gaps']))

    def test_configuration_change_invalidates_network_proof(self):
        test = self.validation(); self.evidence(); reconcile_validations(self.now)
        self.assertEqual(len(snapshot(self.network, self.now)['proofs']), 1)
        self.network.cidrs = ['192.168.2.0/24']; self.network.save()
        self.assertEqual(snapshot(self.network, self.now)['proofs'], [])
        test.refresh_from_db()
        self.assertEqual(test.network_snapshot, ['192.168.1.0/24'])
        self.assertIsNotNone(test.evidence)

    def test_removed_or_paused_network_cannot_have_current_proof(self):
        test = self.validation(); self.evidence(); reconcile_validations(self.now)
        self.network.present = False; self.network.save()
        self.assertFalse(current(self.network, self.now))
        self.assertEqual(snapshot(self.network, self.now)['proofs'], [])
        self.network.present = True; self.device.integration = 'paused'
        self.assertFalse(current(self.network, self.now))

    def test_forged_snapshot_field_is_not_saved_from_browser(self):
        response = self.client.post(reverse('validations', args=[self.device.pk]), {
            'engine': 'suricata', 'networks': 'PC autorizado', 'expected_signature': 'SOC TEST',
            'network': self.network.pk, 'test_ip': '192.168.1.20',
            'network_snapshot': '["0.0.0.0/0"]', 'configuration_fingerprint': 'forged'})
        self.assertEqual(response.status_code, 302)
        saved = ProtectionValidation.objects.get()
        self.assertEqual(saved.network_snapshot, ['192.168.1.0/24'])
        self.assertEqual(saved.configuration_fingerprint, fingerprint(self.network, 'suricata'))

    def test_csrf_is_required_for_network_changes(self):
        browser = Browser(enforce_csrf_checks=True); browser.force_login(self.user)
        self.assertEqual(browser.post(reverse('network_requirements', args=[self.network.pk]), {'scope': 'included'}).status_code, 403)

    def test_overlapping_network_cannot_claim_unique_network_proof(self):
        test = self.validation(); self.evidence(); reconcile_validations(self.now)
        self.assertEqual(len(snapshot(self.network,self.now)['proofs']),1)
        NetworkCoverage.objects.create(device=self.device,**self.row(remote_id='opt1',cidrs=['192.168.1.0/25']))
        self.assertEqual(snapshot(self.network,self.now)['proofs'],[])
        form=ValidationForm({'engine':'suricata','networks':'Prueba','expected_signature':'SOC TEST',
            'network':self.network.pk,'test_ip':'192.168.1.20'},device=self.device)
        self.assertFalse(form.is_valid());self.assertIn('test_ip',form.errors)

"""Ataques a varios clientes: detección con ámbito, bloqueo común controlado y aviso en el resumen."""
from datetime import timedelta
from itertools import count

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from .models import Client, Device, ManualBlock, SecurityEvidence, Site, StaffAccess
from .testing_access import FreshMfaClient

ATTACKER = '45.155.205.233'
_uid = count(1)


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class CampaignTests(TestCase):
    client_class = FreshMfaClient

    def setUp(self):
        self.now = timezone.now()
        self.companies = []
        for n in range(4):
            company = Client.objects.create(name=f'Empresa {n}', code=f'e{n}')
            Device.objects.create(site=Site.objects.create(client=company, name='Sede', code=f's{n}'),
                                  name=f'FW-{n}', vendor='opnsense')
            self.companies.append(company)
        self.admin = get_user_model().objects.create_superuser('admin', 'admin@example.test', 'x')

    def attack(self, company, ip=ATTACKER, action='blocked', hours=1):
        device = company.sites.first().devices.first()
        SecurityEvidence.objects.create(uid=f'{next(_uid):064x}', device=device, observed_at=self.now - timedelta(hours=hours),
                                        engine='suricata', signature='ET SCAN Escaneo', source_ip=ip,
                                        destination_ip='10.0.0.5', action=action, level=8, client_scope_id=company.pk)

    def test_ip_attacking_three_clients_is_a_campaign(self):
        for company in self.companies[:3]:
            self.attack(company)
        self.attack(self.companies[0], action='allowed')
        for company in self.companies[:2]:
            self.attack(company, ip='91.215.85.20')  # solo dos clientes: no cuenta
        self.client.force_login(self.admin)
        page = self.client.get(reverse('campaign_list'))
        rows = page.context['rows']
        self.assertEqual([r['ip'] for r in rows], [ATTACKER])
        self.assertEqual((rows[0]['clients'], rows[0]['events'], rows[0]['allowed']), (3, 4, 1))
        self.assertContains(page, 'Bloquear en todos')

    def test_private_and_old_sources_are_ignored(self):
        for company in self.companies[:3]:
            self.attack(company, ip='192.168.1.20')
            self.attack(company, ip='185.220.101.7', hours=30)  # fuera de la ventana de 24 h
        self.client.force_login(self.admin)
        self.assertEqual(self.client.get(reverse('campaign_list')).context['rows'], [])
        self.assertEqual(len(self.client.get(reverse('campaign_list') + '?ventana=72').context['rows']), 1)

    def test_scoped_operator_only_sees_own_clients(self):
        for company in self.companies[:3]:
            self.attack(company)
        operator = get_user_model().objects.create_user('operador', 'op@example.test', 'x')
        operator.groups.add(Group.objects.get(name='SOC Operador'))
        StaffAccess.objects.create(user=operator, role='operator').clients.add(*self.companies[:2])
        self.client.force_login(operator)
        page = self.client.get(reverse('campaign_list'))
        self.assertEqual(page.context['rows'], [])  # solo dos de sus clientes: no es campaña para él
        self.assertNotContains(page, 'Empresa 2')

    def test_common_block_requires_global_access_mfa_and_a_listed_ip(self):
        for company in self.companies[:3]:
            self.attack(company)
        self.client.force_login(self.admin)
        url = reverse('campaign_list')
        response = self.client.post(url, {'ip': '8.8.8.8', 'days': '7'}, follow=True)
        self.assertContains(response, 'ya no figura')
        self.assertFalse(ManualBlock.objects.exists())
        response = self.client.post(url, {'ip': ATTACKER, 'days': '7'}, follow=True)
        block = ManualBlock.objects.get()
        self.assertIsNone(block.client_id)
        self.assertEqual((block.network, block.direction), (ATTACKER, 'in'))
        self.assertIn('Ataque a 3 clientes', block.reason)
        self.assertTrue(response.context['rows'][0]['blocked'])
        self.assertContains(response, 'Bloqueo común vigente')

    def test_without_fresh_mfa_or_global_access_nothing_is_blocked(self):
        for company in self.companies[:3]:
            self.attack(company)
        self.client.force_login(self.admin)
        session = self.client.session
        session['soc_mfa_at'] = 0
        session.save()
        self.assertRedirects(self.client.post(reverse('campaign_list'), {'ip': ATTACKER, 'days': '7'}),
                             reverse('mfa_challenge'), fetch_redirect_response=False)
        operator = get_user_model().objects.create_user('operador', 'op@example.test', 'x')
        operator.groups.add(Group.objects.get(name='SOC Operador'))
        StaffAccess.objects.create(user=operator, role='operator').clients.add(*self.companies[:3])
        self.client.force_login(operator)
        self.assertEqual(self.client.post(reverse('campaign_list'), {'ip': ATTACKER, 'days': '7'}).status_code, 403)
        self.assertFalse(ManualBlock.objects.exists())

    def test_dashboard_points_to_unblocked_campaigns(self):
        for company in self.companies[:3]:
            self.attack(company)
        self.client.force_login(self.admin)
        attention = {i['title']: i['count'] for i in self.client.get(reverse('dashboard')).context['attention']}
        self.assertEqual(attention['IPs que atacan a varios clientes sin bloqueo común'], 1)

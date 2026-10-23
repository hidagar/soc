"""Portal del cliente: firewalls y detecciones. Aislamiento, opción por cliente y proyección explícita."""
from datetime import timedelta
from unittest import mock

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from .models import (Client, CustomerPublication, Device, DeviceHealth, Incident, OpnsenseConnection, SecurityEvidence,
                     Site, StaffAccess)

INTERNAL = ('NOTA INTERNA CLIENTE', 'NOTA INTERNA EQUIPO', 'ERROR API SECRETO', 'fw-gestion.example.test',
            'RECOMENDACION INTERNA', 'wazuh-raw-id', 'PORTATIL DE GERENCIA', 'INCIDENCIA NO PUBLICADA',
            'OTRA EMPRESA', 'FIREWALL AJENO', 'FIRMA AJENA', 'FIRMA REASIGNADA', 'POLITICA DE APLICACION',
            'Revisar permisos API')


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class CustomerPortalTests(TestCase):
    def setUp(self):
        self.now = timezone.now()
        self.company = Client.objects.create(name='Clínica', code='clinica', notes='NOTA INTERNA CLIENTE',
                                             customer_portal_detail_enabled=True)
        self.other = Client.objects.create(name='OTRA EMPRESA', code='otra', customer_portal_detail_enabled=True)
        site = Site.objects.create(client=self.company, name='Central', code='central')
        self.device = Device.objects.create(site=site, name='FW-Central', vendor='opnsense', model='DEC740',
                                            management_method='api', notes='NOTA INTERNA EQUIPO')
        OpnsenseConnection.objects.create(device=self.device, api_url='https://fw-gestion.example.test',
                                          encrypted_api_key='x', encrypted_api_secret='x')
        DeviceHealth.objects.create(device=self.device, api_ok=False, api_error='ERROR API SECRETO',
                                    last_log_at=self.now - timedelta(minutes=5), checked_at=self.now)
        foreign = Device.objects.create(site=Site.objects.create(client=self.other, name='S', code='s'),
                                        name='FIREWALL AJENO', vendor='opnsense')
        incident = Incident.objects.create(client=self.company, title='INCIDENCIA NO PUBLICADA', severity='high',
                                           status='open', observed_at=self.now)
        self.event('a', signature='ET SCAN Escaneo SSH', source_ip='45.155.205.233', action='blocked',
                   geography={'status': 'located', 'country': 'Países Bajos', 'country_code': 'NL', 'direction': 'inbound'},
                   recommendation='RECOMENDACION INTERNA', wazuh_id='wazuh-raw-id',
                   identity={'label': 'PORTATIL DE GERENCIA'}, incident=incident)
        self.event('b', signature='Malware permitido', source_ip='10.0.0.9', destination_ip='185.220.101.4',
                   action='allowed', interpretation={'event_family': 'malware'})
        self.event('c', device=foreign, client_scope_id=self.other.pk, signature='FIRMA AJENA')
        self.event('d', client_scope_id=self.other.pk, signature='FIRMA REASIGNADA')  # dueño histórico distinto
        self.event('e', category='application_policy', signature='POLITICA DE APLICACION')
        self.user = get_user_model().objects.create_user('cliente')
        StaffAccess.objects.create(user=self.user, role='customer').clients.add(self.company)
        self.client.force_login(self.user)

    def event(self, uid, **values):
        data = dict(device=self.device, observed_at=self.now - timedelta(hours=1), engine='suricata', signature='Firma',
                    destination_ip='10.0.0.5', action='blocked', level=5, client_scope_id=self.company.pk)
        data.update(values)
        return SecurityEvidence.objects.create(uid=uid if len(uid) == 64 else uid * 64, **data)

    def assert_no_internal(self, response):
        for text in INTERNAL:
            self.assertNotContains(response, text)

    def test_pages_require_company_opt_in(self):
        Client.objects.filter(pk=self.company.pk).update(customer_portal_detail_enabled=False)
        for name in ('customer_firewalls', 'customer_detections'):
            self.assertEqual(self.client.get(reverse(name)).status_code, 404)
        home = self.client.get(reverse('customer_home'))
        self.assertNotContains(home, reverse('customer_firewalls'))
        self.assertNotContains(home, 'FW-Central')

    def test_firewalls_show_status_without_internal_details(self):
        page = self.client.get(reverse('customer_firewalls'))
        self.assertContains(page, 'FW-Central')
        self.assertContains(page, 'DEC740')
        self.assertContains(page, 'En revisión por el SOC')  # API con error: estado sin el texto interno
        self.assertContains(page, 'Último: ')
        self.assertContains(page, '2 detecciones')
        self.assert_no_internal(page)
        home = self.client.get(reverse('customer_home'))
        self.assertContains(home, 'Vuestros firewalls')
        self.assertContains(home, 'FW-Central')
        self.assert_no_internal(home)

    def test_detections_show_own_projection_only(self):
        page = self.client.get(reverse('customer_detections'))
        for text in ('ET SCAN Escaneo SSH', '45.155.205.233', 'Países Bajos', 'Malware permitido',
                     'Malware o control remoto', 'Escaneo o reconocimiento', 'Bloqueada', 'Permitida'):
            self.assertContains(page, text)
        self.assertEqual(page.context['summary']['totals']['total'], 2)
        self.assertEqual(page.context['summary']['origins'], [('45.155.205.233', 1)])
        self.assert_no_internal(page)
        row = page.context['page'].object_list[0]
        self.assertEqual(set(row), {'observed_at', 'firewall', 'site', 'signature', 'category', 'family', 'action',
                                    'action_label', 'source', 'destination', 'port', 'country'})

    def test_filters_are_validated_and_cannot_reach_other_companies(self):
        url = reverse('customer_detections')
        allowed = self.client.get(url, {'action': 'allowed'})
        self.assertEqual([r['signature'] for r in allowed.context['page'].object_list], ['Malware permitido'])
        self.assertEqual(self.client.get(url, {'firewall': 'FIREWALL AJENO'}).status_code, 404)
        self.assertEqual(self.client.get(url, {'firewall': 'FW-Central'}).context['summary']['totals']['total'], 2)
        page = self.client.get(url, {'days': '9999', 'action': 'raro', 'client': self.other.pk})
        self.assertEqual((page.context['days'], page.context['action']), (7, 'all'))
        self.assert_no_internal(page)
        self.assertEqual(self.client.get(url, {'days': '1'}).context['summary']['totals']['total'], 2)

    def test_older_detections_are_paginated(self):
        for index in range(60):
            self.event(f'{index + 100:064x}', observed_at=self.now - timedelta(days=2, minutes=index))
        first = self.client.get(reverse('customer_detections'))
        self.assertEqual(len(first.context["page"].object_list), 25)
        second = self.client.get(reverse("customer_detections"), {"page": 3})
        self.assertEqual(len(second.context['page'].object_list), 12)

    def test_staff_cannot_use_customer_pages_and_other_customers_see_only_theirs(self):
        operator = get_user_model().objects.create_user('operador')
        StaffAccess.objects.create(user=operator, role='operator', all_clients=True)
        operator.groups.add(Group.objects.get(name='SOC Operador'))
        self.client.force_login(operator)
        self.assertEqual(self.client.get(reverse('customer_firewalls')).status_code, 404)
        neighbour = get_user_model().objects.create_user('vecino')
        StaffAccess.objects.create(user=neighbour, role='customer').clients.add(self.other)
        self.client.force_login(neighbour)
        page = self.client.get(reverse('customer_detections'))
        self.assertContains(page, 'FIRMA AJENA')
        self.assertNotContains(page, 'ET SCAN Escaneo SSH')
        self.assertNotContains(page, 'FW-Central')
        self.assertNotContains(self.client.get(reverse('customer_firewalls')), 'FW-Central')

    def test_navigation_and_advanced_panel_link(self):
        CustomerPublication.objects.create(client=self.company, title='Publicada', summary='Texto', visible=True)
        home = self.client.get(reverse('customer_home'))
        for name in ('customer_firewalls', 'customer_detections'):
            self.assertContains(home, reverse(name))
        self.assertNotContains(home, reverse('customer_map'))
        self.assertNotContains(home, 'Panel avanzado')
        with mock.patch('core.wazuh_scoped.binding_ready', return_value=True):
            self.assertContains(self.client.get(reverse('customer_firewalls')), 'Panel avanzado (Wazuh)')
        Client.objects.filter(pk=self.company.pk).update(customer_live_map_enabled=True)
        self.assertContains(self.client.get(reverse('customer_detections')), reverse('customer_map'))


class DetectionSummaryTests(TestCase):
    """El resumen agregado en la base de datos coincide con aplicar la proyección fila a fila."""

    def reference(self, qs, days, now):
        from collections import Counter
        from .customer_portal import FIELDS, _public, detection_row
        days_count, families, signatures, countries, origins, firewalls = (Counter() for _ in range(6))
        actions = {}
        for row in qs.values(*FIELDS):
            item = detection_row(row)
            days_count[timezone.localtime(item['observed_at']).date()] += 1
            families[item['family']] += 1
            signatures[item['signature']] += 1
            actions.setdefault(item['signature'], Counter())[item['action']] += 1
            firewalls[item['firewall']] += 1
            if item['country']:
                countries[item['country']] += 1
                if _public(item['source']):
                    origins[item['source']] += 1
        top = lambda counter, n=None: sorted(counter.items(), key=lambda x: (-x[1], x[0]))[:n]  # noqa: E731
        today = timezone.localtime(now).date()
        return {'timeline': [days_count[today - timedelta(days=o)] for o in range(days, -1, -1)],
                'families': top(families), 'countries': top(countries, 10), 'origins': top(origins, 10),
                'firewalls': top(firewalls),
                'signatures': [{'signature': s, 'count': c, 'blocked': actions[s]['blocked'], 'allowed': actions[s]['allowed']}
                               for s, c in top(signatures, 10)]}

    def test_aggregates_match_the_row_by_row_projection(self):
        from .customer_portal import detection_summary
        from .investigation import evidence_queryset
        now = timezone.now()
        company = Client.objects.create(name='Empresa', code='empresa')
        site = Site.objects.create(client=company, name='Sede', code='s')
        devices = [Device.objects.create(site=site, name=name, vendor='opnsense') for name in ('FW-A', 'FW-B')]
        geo = [{'status': 'located', 'country': 'Países Bajos', 'direction': 'inbound'},
               {'status': 'located', 'country': 'China', 'direction': 'inbound'},
               {'status': 'located', 'country': 'China', 'direction': 'outbound'},  # destino: no cuenta como origen
               {'status': 'unknown', 'direction': 'inbound'}, {}, 'texto']
        sources = ['45.155.205.233', '218.92.0.35', '10.0.0.9', None, '185.220.101.4']
        kinds = [{'event_family': 'malware'}, {'event_family': 'scan'}, {}, {'event_family': 'inexistente'}]
        signatures = ['ET SCAN Escaneo SSH', 'ET MALWARE Trojan', 'Credenciales robadas', 'Firma genérica', 'ET POLICY x']
        for index in range(60):
            SecurityEvidence.objects.create(
                uid=f'{index:064x}', device=devices[index % 2], observed_at=now - timedelta(hours=index * 2 + 1),
                engine=('suricata', 'zenarmor')[index % 2], signature=signatures[index % 5], category=('', 'malware', 'scan')[index % 3],
                action=('blocked', 'allowed', 'unknown', 'otra')[index % 4], level=5, source_ip=sources[index % 5],
                destination_ip='10.0.0.5', geography=geo[index % 6], interpretation=kinds[index % 4],
                client_scope_id=company.pk)
        for days in (1, 7):
            qs = evidence_queryset(company, days)
            summary = detection_summary(qs, days, now)
            expected = self.reference(qs, days, now)
            self.assertEqual([d['count'] for d in summary['timeline']], expected['timeline'])
            for key in ('families', 'countries', 'origins', 'firewalls', 'signatures'):
                self.assertEqual(list(summary[key]), expected[key], (days, key))
            self.assertEqual(summary['totals']['total'], qs.count())

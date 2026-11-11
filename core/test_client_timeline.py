"""Línea de tiempo del cliente."""
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from . import client_timeline
from .models import (Client, ConnectivityEvent, CustomerRequest, Device, DeviceExposure, Incident, PolicyProposal, Site, StaffAccess,
                     UrgentAlert, VulnerabilityAdvisory, VulnerabilityRecord)


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class ClientTimelineTests(TestCase):
    def setUp(self):
        self.now = timezone.now()
        self.company = Client.objects.create(name='Empresa A', code='a')
        self.other = Client.objects.create(name='Empresa B', code='b')
        site = Site.objects.create(client=self.company, name='Palma', code='palma')
        self.fw = Device.objects.create(site=site, name='FW-Palma', vendor='opnsense')
        self.user = get_user_model().objects.create_user('operador')
        StaffAccess.objects.create(user=self.user, role='operator').clients.add(self.company)
        self.customer = get_user_model().objects.create_user('ana', email='ana@a.test')
        ago = lambda **kw: self.now - timedelta(**kw)  # noqa: E731
        Incident.objects.create(client=self.company, title='Acceso RDP sospechoso', description='d', severity='high',
                                observed_at=ago(days=5), resolved_at=ago(days=4), status='resolved')
        Incident.objects.create(client=self.company, title='Caso antiguo', description='d', observed_at=ago(days=200))
        Incident.objects.create(client=self.other, title='Caso ajeno', description='d', observed_at=ago(days=1))
        UrgentAlert.objects.create(client=self.company, event_uid='u', fingerprint='f', kind='security_allowed', observed_at=ago(days=3),
                                   source_ip='192.0.2.1', asset_name='NAS', recipient='it@a.test')
        CustomerRequest.objects.create(client=self.company, kind='unblock', subject='No abre la web', urgent=True, created_at=ago(days=2))
        record = VulnerabilityRecord.objects.create(cve_id='CVE-2026-44194', product='a:opnsense:opnsense', severity='CRITICAL')
        DeviceExposure.objects.create(client=self.company, device=self.fw, record=record, version='25.1', first_seen=ago(days=6),
                                      resolved_at=ago(hours=5), resolved_version='26.1.8')
        VulnerabilityAdvisory.objects.create(client=self.company, cve_id='CVE-2026-44194', published_at=ago(days=5, hours=2))
        PolicyProposal.objects.create(client=self.company, kind='ips_block', key='ips', title='IPS en bloqueo', change='c', risk='r',
                                      status='applied', offered_at=ago(days=4), decided_at=ago(days=3), decided_by=self.customer,
                                      applied_at=ago(days=1), applied_note='Modo IPS activado')
        PolicyProposal.objects.create(client=self.company, kind='geo_filter', key='geo', title='Propuesta interna sin ofrecer', change='c', risk='r')
        ConnectivityEvent.objects.create(client=self.company, device=self.fw, kind='internet_down', observed_at=ago(hours=8), event_key='k')
        self.client.force_login(self.user)
        self.url = reverse('client_timeline', args=[self.company.pk])

    def test_events_are_merged_newest_first_within_the_period(self):
        rows = client_timeline.events(self.company, self.now - timedelta(days=90))
        self.assertEqual(rows, sorted(rows, key=lambda r: r['at'], reverse=True))
        titles = [r['title'] for r in rows]
        self.assertEqual(titles[0], 'Vulnerabilidad corregida: CVE-2026-44194 en FW-Palma')
        for expected in ('Incidencia abierta: Acceso RDP sospechoso', 'Incidencia resuelta: Acceso RDP sospechoso',
                         'Solicitud del cliente: No abre la web', 'Vulnerabilidad avisada al cliente: CVE-2026-44194',
                         'Cambio propuesto al cliente: IPS en bloqueo', 'Cambio aprobado por el cliente: IPS en bloqueo',
                         'Cambio aplicado: IPS en bloqueo', 'Caída de Internet'):
            self.assertIn(expected, titles)
        self.assertNotIn('Incidencia abierta: Caso antiguo', titles)
        self.assertFalse(any('sin ofrecer' in t or 'ajeno' in t for t in titles))

    def test_page_filters_and_links(self):
        page = self.client.get(self.url)
        self.assertContains(page, 'Línea de tiempo')
        self.assertContains(page, 'Aviso urgente: Seguridad permitida')
        self.assertContains(page, reverse('policies'))
        only = self.client.get(self.url, {'type': 'request'})
        self.assertContains(only, 'Solicitud del cliente: No abre la web')
        self.assertNotContains(only, 'Incidencia abierta')
        year = self.client.get(self.url, {'days': '365'})
        self.assertContains(year, 'Caso antiguo')
        self.assertEqual(self.client.get(self.url, {'days': 'x', 'type': 'nada'}).status_code, 200)
        # Las 23:30 UTC son ya el día siguiente en Madrid: la entrada se agrupa en ese día.
        from datetime import timezone as tz
        late = (self.now - timedelta(days=30)).astimezone(tz.utc).replace(hour=23, minute=30)
        CustomerRequest.objects.create(client=self.company, kind='question', subject='De madrugada', created_at=late)
        rows = self.client.get(self.url, {'type': 'request'}).context['rows']
        row = next(r for r in rows if 'De madrugada' in r['title'])
        self.assertEqual(row['day'], late.date() + timedelta(days=1))
        self.assertContains(self.client.get(reverse('client_detail', args=[self.company.pk])), self.url)

    def test_scope_and_customers(self):
        self.assertEqual(self.client.get(reverse('client_timeline', args=[self.other.pk])).status_code, 404)
        StaffAccess.objects.create(user=self.customer, role='customer').clients.add(self.company)
        self.client.force_login(self.customer)
        self.assertEqual(self.client.get(self.url).status_code, 403)

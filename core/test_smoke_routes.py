"""Prueba de humo: ninguna página responde 500 y una cuenta de cliente no ve páginas del SOC.

Recorre todas las rutas con nombre con un administrador y con un cliente, sobre datos mínimos. No
sustituye a las pruebas de cada área: detecta plantillas rotas, rutas sin vista y fugas de navegación.
"""
import time

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import NoReverseMatch, get_resolver, reverse
from django.utils import timezone

from .models import Client, CustomerRequest, Device, Incident, PolicyProposal, Site, StaffAccess

CUSTOMER_AREAS = ('/cliente/', '/security/', '/reports/', '/login', '/activate', '/healthz')
EXPECTED_UNAVAILABLE = {'/healthz/'}  # 503 sin trabajos en marcha: correcto en pruebas


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False, DEBUG=False)
class RouteSmokeTests(TestCase):
    def setUp(self):
        now = timezone.now()
        self.admin = get_user_model().objects.create_superuser('admin', 'admin@soc.test', 'x')
        company = Client.objects.create(name='Empresa A', code='a', customer_portal_detail_enabled=True, customer_live_map_enabled=True)
        site = Site.objects.create(client=company, name='Palma', code='palma')
        device = Device.objects.create(site=site, name='FW', vendor='opnsense', software_version='25.1')
        Device.objects.create(site=site, name='UDM', vendor='unifi', model='UDM Pro')
        Incident.objects.create(client=company, site=site, device=device, title='Caso', description='d')
        self.customer = get_user_model().objects.create_user('cliente', email='cliente@a.test')
        StaffAccess.objects.create(user=self.customer, role='customer').clients.add(company)
        CustomerRequest.objects.create(client=company, kind='question', subject='Consulta', created_by=self.customer)
        PolicyProposal.objects.create(client=company, device=device, kind='ips_block', key='ips', title='IPS', change='c', risk='r',
                                      status='offered', offered_at=now, planned_for=now, customer_title='IPS', customer_text='x')

    def urls(self):
        for entry in get_resolver().url_patterns:
            for pattern in getattr(entry, 'url_patterns', [entry]):
                name = getattr(pattern, 'name', None)
                if not name:
                    continue
                groups = pattern.pattern.regex.groupindex
                try:
                    url = reverse(name, kwargs={k: (1 if 'pk' in k or 'id' in k else 'x') for k in groups})
                except NoReverseMatch:
                    continue
                if not url.startswith(('/logout', '/admin')):
                    yield url

    def crawl(self, user):
        self.client.force_login(user)
        session = self.client.session
        session.update({'soc_mfa_user': user.pk, 'soc_mfa_at': time.time()})
        session.save()
        return {url: self.client.get(url).status_code for url in self.urls()}

    def test_no_page_fails_for_the_soc(self):
        results = self.crawl(self.admin)
        self.assertGreater(len(results), 100)
        failed = {u: s for u, s in results.items() if s >= 500 and u not in EXPECTED_UNAVAILABLE}
        self.assertEqual(failed, {})

    def test_customer_sees_only_the_portal_and_nothing_fails(self):
        results = self.crawl(self.customer)
        failed = {u: s for u, s in results.items() if s >= 500 and u not in EXPECTED_UNAVAILABLE}
        self.assertEqual(failed, {})
        leaked = [u for u, s in results.items() if s == 200 and not u.startswith(CUSTOMER_AREAS)]
        self.assertEqual(leaked, [])

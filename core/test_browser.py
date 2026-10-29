"""Pruebas de navegador: las pantallas principales se cargan sin errores, no desbordan en móvil y sus
controles básicos funcionan.

Solo se ejecutan con SOC_BROWSER_TESTS=1 y Playwright instalado (requirements-browser.txt); en la
batería habitual se omiten. En CI las lanza un trabajo aparte. Datos ficticios, sin red externa.
Si existe SOC_BROWSER_CHROMIUM se usa ese Chromium en lugar del que descarga Playwright.
"""
import os
import time
import unittest
from datetime import timedelta
from itertools import count

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.staticfiles.testing import StaticLiveServerTestCase
from django.test import override_settings, tag
from django.urls import reverse
from django.utils import timezone

from .models import (BlocklistFeed, Client, CustomerTask, Device, DeviceHealth, Incident, SecurityEvidence, Site,
                     StaffAccess)

ENABLED = os.environ.get('SOC_BROWSER_TESTS') == '1'
try:
    from playwright.sync_api import sync_playwright
except ImportError:  # pragma: no cover - depende del entorno
    sync_playwright = None

_uid = count(1)
WIDTHS = {'escritorio': 1440, 'movil': 390}


@tag('browser')
@unittest.skipUnless(ENABLED and sync_playwright, 'Pruebas de navegador: SOC_BROWSER_TESTS=1 y Playwright instalado.')
@override_settings(SECURE_SSL_REDIRECT=False, SESSION_COOKIE_SECURE=False, CSRF_COOKIE_SECURE=False,
                   SOC_MFA_REQUIRED=False, DEBUG=False)
class BrowserTests(StaticLiveServerTestCase):
    @classmethod
    def setUpClass(cls):
        # Playwright síncrono mantiene un bucle de eventos en este hilo; el ORM se usa entre llamadas.
        os.environ.setdefault('DJANGO_ALLOW_ASYNC_UNSAFE', 'true')
        super().setUpClass()
        cls.playwright = sync_playwright().start()
        executable = os.environ.get('SOC_BROWSER_CHROMIUM') or None
        cls.browser = cls.playwright.chromium.launch(executable_path=executable)

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.playwright.stop()
        super().tearDownClass()

    def setUp(self):
        now = timezone.now()
        self.company = Client.objects.create(name='Conservas del Norte', code='norte', customer_portal_detail_enabled=True,
                                             customer_live_map_enabled=True, notes='NOTA INTERNA DEL SOC')
        self.site = Site.objects.create(client=self.company, name='Oficina central', code='oc')
        self.device = Device.objects.create(site=self.site, name='FW-NORTE-1', vendor='opnsense')
        DeviceHealth.objects.create(device=self.device, last_log_at=now - timedelta(minutes=5))
        for n in range(30):
            SecurityEvidence.objects.create(
                uid=f'{next(_uid):064x}', device=self.device, observed_at=now - timedelta(hours=n), engine='suricata',
                signature='ET SCAN Escaneo SSH con un nombre de firma bastante largo para probar el ajuste', category='scan',
                source_ip=f'45.155.{n % 5}.{n + 1}', destination_ip='192.168.1.10', destination_port='22',
                action=('blocked', 'allowed', 'unknown')[n % 3], level=8, client_scope_id=self.company.pk)
        self.incident = Incident.objects.create(client=self.company, title='Escaneo repetido contra RDP publicado',
                                                severity='high', status='open', observed_at=now, description='Detección.')
        CustomerTask.objects.create(incident=self.incident, title='Revisar el acceso RDP publicado', visible=True,
                                    instructions='Confirmad el acceso.')
        BlocklistFeed.objects.create(client=self.company, enabled=False)
        self.admin = get_user_model().objects.create_superuser('admin', 'admin@example.test', 'x')
        self.customer = get_user_model().objects.create_user('cliente', 'cliente@example.test', 'x')
        StaffAccess.objects.create(user=self.customer, role='customer').clients.add(self.company)

    # -- utilidades --------------------------------------------------------------------------------
    def page_for(self, user, width):
        """Página con la sesión de `user` (MFA recién verificado) y el ancho pedido."""
        self.client.force_login(user)
        session = self.client.session
        session.update({'soc_mfa_user': user.pk, 'soc_mfa_at': time.time()})
        session.save()
        context = self.browser.new_context(viewport={'width': width, 'height': 900})
        self.addCleanup(context.close)
        host = self.live_server_url.split('//', 1)[1].split(':')[0]
        context.add_cookies([{'name': settings.SESSION_COOKIE_NAME, 'value': session.session_key, 'domain': host,
                              'path': '/'}])
        page = context.new_page()
        page.errors = []
        page.on('pageerror', lambda exc: page.errors.append(str(exc)))
        # El texto de consola de un 404 no dice qué falta: se anota la URL de la respuesta.
        page.on('console', lambda msg: msg.type == 'error' and not msg.text.startswith('Failed to load resource')
                and page.errors.append(msg.text))
        page.on('response', lambda r: r.status >= 400 and page.errors.append(f'HTTP {r.status} {r.url}'))
        return page

    def open(self, page, url):
        response = page.goto(self.live_server_url + url, wait_until='networkidle')
        self.assertEqual(response.status, 200, url)
        self.assertNotIn('/login/', page.url, url)
        return response

    def assert_fits(self, page, url):
        overflow = page.evaluate('document.documentElement.scrollWidth - document.documentElement.clientWidth')
        self.assertLessEqual(overflow, 1, f'{url}: la página desborda {overflow}px en horizontal')

    # -- pruebas -------------------------------------------------------------------------------------
    def test_staff_pages_load_without_errors_or_horizontal_overflow(self):
        urls = [reverse('dashboard'), reverse('work_queue'), reverse('incident_list'),
                reverse('incident_detail', args=[self.incident.pk]), reverse('client_list'),
                reverse('client_detail', args=[self.company.pk]), reverse('site_detail', args=[self.site.pk]),
                reverse('device_detail', args=[self.device.pk]), reverse('security_explore'), reverse('intelligence'),
                reverse('campaign_list'), reverse('health_list'), reverse('blocklist_detail', args=[self.company.pk]),
                reverse('api_connections'), reverse('staff')]
        for label, width in WIDTHS.items():
            page = self.page_for(self.admin, width)
            for url in urls:
                with self.subTest(ancho=label, url=url):
                    self.open(page, url)
                    self.assert_fits(page, url)
            self.assertEqual(page.errors, [], label)

    def test_customer_portal_pages_fit_and_hide_internal_data(self):
        urls = [reverse('customer_home'), reverse('customer_firewalls'), reverse('customer_detections'),
                reverse('customer_reports'), reverse('customer_tasks')]
        for label, width in WIDTHS.items():
            page = self.page_for(self.customer, width)
            for url in urls:
                with self.subTest(ancho=label, url=url):
                    self.open(page, url)
                    self.assert_fits(page, url)
                    self.assertNotIn('NOTA INTERNA DEL SOC', page.content())
            self.assertEqual(page.errors, [], label)

    def test_more_actions_menu_opens_and_stays_on_screen(self):
        for width in WIDTHS.values():
            page = self.page_for(self.admin, width)
            self.open(page, reverse('client_detail', args=[self.company.pk]))
            menu = page.locator('.page-head .more-menu')
            self.assertFalse(menu.is_visible())
            page.locator('.page-head .more-actions > summary').click()
            self.assertTrue(menu.is_visible())
            box = menu.bounding_box()
            self.assertGreaterEqual(box['x'], 0)
            self.assertLessEqual(box['x'] + box['width'], width + 1)
            self.assertTrue(menu.get_by_text('Lista de bloqueo').is_visible())

    def test_client_selector_filters_without_a_button(self):
        page = self.page_for(self.admin, 1440)
        self.open(page, reverse('work_queue'))
        with page.expect_navigation():
            page.select_option('select[name=client]', str(self.company.pk))
        self.assertIn(f'client={self.company.pk}', page.url)

    def test_blocklist_page_shows_manual_blocks_with_the_list_disabled(self):
        # Regresión de la fase 3: con la lista desactivada desaparecían bloqueos manuales y UniFi.
        page = self.page_for(self.admin, 1440)
        self.open(page, reverse('blocklist_detail', args=[self.company.pk]))
        self.assertTrue(page.get_by_role('heading', name='Bloqueos manuales del SOC').is_visible())
        self.assertTrue(page.locator('#configuracion').evaluate('el => el.open'))  # desactivada: configuración abierta

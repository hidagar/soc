"""Avisos de vulnerabilidad dirigidos: catálogo NVD, cruce por versión, revisión del SOC y portal."""
from datetime import timedelta
from unittest import mock

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from . import security_score, vulnerabilities as vuln
from .models import (AuditEvent, Client, Device, DeviceExposure, DeviceHealth, OperationalIssue, Site, StaffAccess,
                     VulnerabilityAdvisory, VulnerabilityRecord, WorkerState)


def nvd_item(cve, product, *, severity='CRITICAL', score=9.8, kev=None, status='Analyzed', **bounds):
    match = {'vulnerable': True, 'criteria': f'cpe:2.3:{product}:{bounds.pop("exact", "*")}:*:*:*:*:*:*:*'}
    match.update({{'ee': 'versionEndExcluding', 'ei': 'versionEndIncluding', 'si': 'versionStartIncluding',
                   'se': 'versionStartExcluding'}[k]: v for k, v in bounds.items()})
    cve_data = {'id': cve, 'vulnStatus': status, 'published': '2026-05-13T15:16:00.000', 'lastModified': '2026-05-14T10:00:00.000',
                'descriptions': [{'lang': 'en', 'value': 'Remote code execution in the web GUI.'}, {'lang': 'es', 'value': 'x'}],
                'metrics': {'cvssMetricV31': [{'type': 'Primary', 'cvssData': {'baseScore': score, 'baseSeverity': severity}}]},
                'configurations': [{'nodes': [{'operator': 'OR', 'cpeMatch': [
                    match, {'vulnerable': False, 'criteria': 'cpe:2.3:h:ui:cloud_key_gen2:-:*:*:*:*:*:*:*'}]}]}],
                'references': [{'url': 'https://vendor.example/advisory', 'tags': ['Vendor Advisory']},
                               {'url': 'http://insecure.example/x', 'tags': ['Patch']}, {'url': 'https://blog.example', 'tags': []}]}
    if kev:
        cve_data['cisaExploitAdd'] = kev
    return {'cve': cve_data}


def page(items, total=None):
    return {'vulnerabilities': items, 'totalResults': len(items) if total is None else total}


class VersionTests(TestCase):
    def test_compare(self):
        cases = [('26.1.7', '26.1.8', -1), ('26.1.8', '26.1.8', 0), ('24.7.5_1', '24.7.5', 1), ('v4.1.13', '4.1.13', 0),
                 ('OPNsense 24.7', '24.7.0', 0), ('5.1.15', '5.1.9', 1), ('5.5R10', '5.5R9', 1)]
        for a, b, expected in cases:
            self.assertEqual(vuln.compare(a, b), expected, (a, b))
        for a, b in (('5.5R10P2', '5.5R10'), ('', '1.0'), ('beta', '1.0')):
            self.assertIsNone(vuln.compare(a, b), (a, b))

    def test_ranges(self):
        self.assertTrue(vuln.in_range('26.1.7', {'version': '*', 'ee': '26.1.8'}))
        self.assertFalse(vuln.in_range('26.1.8', {'version': '*', 'ee': '26.1.8'}))
        self.assertTrue(vuln.in_range('5.1.15', {'version': '*', 'ei': '5.1.15'}))
        self.assertFalse(vuln.in_range('4.0', {'version': '*', 'si': '5.0', 'ee': '5.2'}))
        self.assertTrue(vuln.in_range('3.1', {'version': '3.1'}))
        self.assertFalse(vuln.in_range('3.2', {'version': '3.1'}))
        self.assertTrue(vuln.in_range('5.5R10P2', {'version': '*', 'ee': '5.5R11'}))
        self.assertIsNone(vuln.in_range('5.5R10P2', {'version': '*', 'ee': '5.5R10'}))
        self.assertIsNone(vuln.in_range('1.0', {'version': '-'}))

    def test_products(self):
        site = Site.objects.create(client=Client.objects.create(name='A', code='a'), name='S', code='s')
        cases = [(dict(vendor='opnsense'), ['a:opnsense:opnsense']),
                 (dict(vendor='unifi', model='UDM Pro'), ['o:ui:unifi_os', 'o:ui:unifi_dream_machine_pro_firmware']),
                 (dict(vendor='unifi', model='UCG-Ultra'), ['o:ui:unifi_os', 'o:ui:unifi_cloud_gateway_ultra_firmware']),
                 (dict(vendor='unifi', model='Modelo raro'), ['o:ui:unifi_os']),
                 (dict(vendor='hillstone'), []),
                 (dict(vendor='hillstone', vulnerability_product='o:hillstonenet:sc-6000-e3960_firmware'), ['o:hillstonenet:sc-6000-e3960_firmware'])]
        for n, (fields, expected) in enumerate(cases):
            self.assertEqual(vuln.products_for(Device(site=site, name=f'd{n}', **fields)), expected)


class CatalogTests(TestCase):
    def setUp(self):
        site = Site.objects.create(client=Client.objects.create(name='A', code='a'), name='S', code='s')
        Device.objects.create(site=site, name='FW', vendor='opnsense', software_version='26.1.7')
        self.now = timezone.now()

    def test_parse_keeps_only_this_product_and_safe_references(self):
        row = vuln.parse(nvd_item('CVE-2026-44194', 'a:opnsense:opnsense', ee='26.1.8', kev='2026-05-20'), 'a:opnsense:opnsense')
        self.assertEqual((row['severity'], row['score'], row['fixed_version'], str(row['kev_added'])), ('CRITICAL', 9.8, '26.1.8', '2026-05-20'))
        self.assertEqual(row['ranges'], [{'version': '*', 'ee': '26.1.8'}])
        self.assertEqual(row['references'], ['https://vendor.example/advisory'])
        self.assertEqual(row['summary'], 'Remote code execution in the web GUI.')
        self.assertIsNone(vuln.parse(nvd_item('CVE-2026-0001', 'a:other:product', ee='1'), 'a:opnsense:opnsense'))
        self.assertIsNone(vuln.parse(nvd_item('CVE-2026-0002', 'a:opnsense:opnsense', status='Rejected', ee='1'), 'a:opnsense:opnsense'))
        self.assertIsNone(vuln.parse({'cve': {'id': 'nada'}}, 'a:opnsense:opnsense'))
        included = vuln.parse(nvd_item('CVE-2026-0003', 'o:ui:unifi_dream_machine_pro_firmware', ei='5.1.15'), 'o:ui:unifi_dream_machine_pro_firmware')
        self.assertEqual(included['fixed_version'], 'posterior a 5.1.15')

    def test_sync_pages_and_only_sends_the_product(self):
        pages = [page([nvd_item('CVE-2026-0001', 'a:opnsense:opnsense', ee='26.1.8')], total=2),
                 page([nvd_item('CVE-2026-0002', 'a:opnsense:opnsense', severity='MEDIUM', score=5.0, ee='26.1.8')], total=2)]
        with mock.patch.object(vuln, '_fetch', side_effect=pages) as fetch, mock.patch.object(vuln.time, 'sleep'):
            self.assertEqual(vuln.sync(self.now), 1)
        params = [c.args[0] for c in fetch.call_args_list]
        self.assertEqual(params[0], {'virtualMatchString': 'cpe:2.3:a:opnsense:opnsense', 'resultsPerPage': 2000, 'startIndex': 0})
        self.assertEqual(params[1]['startIndex'], 1)
        self.assertEqual(VulnerabilityRecord.objects.count(), 2)
        with mock.patch.object(vuln, '_fetch') as fetch:
            self.assertEqual(vuln.sync(self.now + timedelta(hours=1)), 0)  # aún vigente
        fetch.assert_not_called()

    def test_incomplete_download_is_not_saved_nor_marked_fresh(self):
        pages = [page([nvd_item('CVE-2026-0001', 'a:opnsense:opnsense', ee='26.1.8')], total=2), vuln.CatalogError('NVD respondió HTTP 503.')]
        with mock.patch.object(vuln, '_fetch', side_effect=pages), mock.patch.object(vuln.time, 'sleep'):
            self.assertEqual(vuln.sync(self.now), 0)
        self.assertFalse(VulnerabilityRecord.objects.exists())
        state = WorkerState.objects.get(name=vuln.STATE)
        self.assertIn('503', state.error)
        self.assertEqual(state.details['products'], {})
        self.assertTrue(OperationalIssue.objects.filter(key=vuln.ISSUE_CATALOG, active=True).exists())


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class ExposureTests(TestCase):
    def setUp(self):
        self.now = timezone.now()
        self.company = Client.objects.create(name='Empresa A', code='a', contact_email='it@a.test')
        self.other = Client.objects.create(name='Empresa B', code='b')
        self.site = Site.objects.create(client=self.company, name='Palma', code='palma')
        self.fw = Device.objects.create(site=self.site, name='FW-Palma', vendor='opnsense', software_version='26.1.7')
        other_site = Site.objects.create(client=self.other, name='Inca', code='inca')
        self.other_fw = Device.objects.create(site=other_site, name='FW-Inca', vendor='opnsense', software_version='26.1.7')
        self.critical = VulnerabilityRecord.objects.create(cve_id='CVE-2026-44194', product='a:opnsense:opnsense', severity='CRITICAL',
                                                           score=9.1, ranges=[{'version': '*', 'ee': '26.1.8'}], fixed_version='26.1.8',
                                                           summary='Remote code execution.')
        VulnerabilityRecord.objects.create(cve_id='CVE-2026-0001', product='a:opnsense:opnsense', severity='MEDIUM',
                                           ranges=[{'version': '*', 'ee': '26.1.8'}])
        self.staff = get_user_model().objects.create_user('gestor')
        access = StaffAccess.objects.create(user=self.staff, role='manager')
        access.clients.add(self.company)
        self.staff.user_permissions.add(*Permission.objects.filter(codename__in=['change_incident', 'change_device']))

    def test_affected_versions_open_and_an_update_resolves(self):
        self.assertEqual(vuln.evaluate(self.now), 2)  # solo la crítica, en los dos clientes
        exposure = DeviceExposure.objects.get(device=self.fw)
        self.assertEqual((exposure.client, exposure.version), (self.company, '26.1.7'))
        self.assertTrue(OperationalIssue.objects.filter(key=vuln.ISSUE_REVIEW, active=True).exists())
        self.fw.software_version = '26.1.9'
        self.fw.save()
        vuln.evaluate(self.now + timedelta(hours=1))
        exposure.refresh_from_db()
        self.assertEqual(exposure.resolved_version, '26.1.9')
        self.assertIsNotNone(exposure.resolved_at)

    def test_unknown_version_format_changes_nothing(self):
        vuln.evaluate(self.now)
        self.fw.software_version = 'desconocida'
        self.fw.save()
        vuln.evaluate(self.now)
        self.assertIsNone(DeviceExposure.objects.get(device=self.fw).resolved_at)

    def test_publish_sends_once_and_customer_sees_only_published(self):
        vuln.evaluate(self.now)
        self.company.vulnerability_notices_enabled = True
        self.company.save()
        self.client.force_login(self.staff)
        self.client.post(reverse('vulnerabilities'), {'action': 'publish', 'client': self.company.pk, 'cve': 'CVE-2026-44194',
                                                      'note': 'Actualizamos el martes a las 22:00.'})
        advisory = VulnerabilityAdvisory.objects.get()
        self.assertEqual((advisory.client, advisory.notice_status, advisory.notice_recipient), (self.company, 'queued', 'it@a.test'))
        self.assertEqual(AuditEvent.objects.filter(action='vulnerability.publish').count(), 1)
        # Otro cliente fuera del ámbito del gestor: no se publica.
        self.client.post(reverse('vulnerabilities'), {'action': 'publish', 'client': self.other.pk, 'cve': 'CVE-2026-44194'})
        self.assertEqual(VulnerabilityAdvisory.objects.count(), 1)
        with mock.patch('core.mail_delivery.send_customer_email', return_value='msg-1') as send:
            self.assertEqual(vuln.send_pending(now=self.now), 1)
            self.assertEqual(vuln.send_pending(now=self.now), 0)
        self.assertEqual(send.call_count, 1)
        plain = send.call_args.args[2]
        self.assertIn('gravedad crítica', plain)
        self.assertIn('uno de vuestros firewalls', plain)
        self.assertNotIn('CVE-2026-44194', plain)  # sin datos técnicos en el correo
        self.assertEqual(send.call_args.kwargs['delivery_context'], {'client': self.company, 'kind': 'vulnerability'})
        customer = get_user_model().objects.create_user('cliente-a')
        StaffAccess.objects.create(user=customer, role='customer').clients.add(self.company)
        self.client.force_login(customer)
        home = self.client.get(reverse('customer_home'))
        self.assertContains(home, 'Vulnerabilidades pendientes')
        page_ = self.client.get(reverse('customer_vulnerabilities'))
        self.assertContains(page_, 'CVE-2026-44194')
        self.assertContains(page_, 'Actualizamos el martes')
        self.assertContains(page_, 'FW-Palma')
        self.assertNotContains(page_, 'FW-Inca')
        self.assertNotContains(page_, 'CVE-2026-0001<')
        self.fw.software_version = '26.1.8'
        self.fw.save()
        vuln.evaluate(self.now + timedelta(days=1))
        page_ = self.client.get(reverse('customer_vulnerabilities'))
        self.assertContains(page_, 'Corregida')
        self.assertNotContains(self.client.get(reverse('customer_home')), 'Vulnerabilidades pendientes')

    def test_unpublished_is_invisible_to_the_customer_and_dismiss_needs_reason(self):
        vuln.evaluate(self.now)
        customer = get_user_model().objects.create_user('cliente-a')
        StaffAccess.objects.create(user=customer, role='customer').clients.add(self.company)
        self.client.force_login(customer)
        self.assertNotContains(self.client.get(reverse('customer_home')), 'Vulnerabilidades')
        self.assertNotContains(self.client.get(reverse('customer_vulnerabilities')), 'CVE-')
        self.assertEqual(self.client.get(reverse('vulnerabilities')).status_code, 403)
        self.client.force_login(self.staff)
        self.client.post(reverse('vulnerabilities'), {'action': 'dismiss', 'client': self.company.pk, 'cve': 'CVE-2026-44194'})
        self.assertIsNone(DeviceExposure.objects.get(device=self.fw).dismissed_at)
        self.client.post(reverse('vulnerabilities'), {'action': 'dismiss', 'client': self.company.pk, 'cve': 'CVE-2026-44194',
                                                      'reason': 'Interfaz web no publicada'})
        self.assertIsNotNone(DeviceExposure.objects.get(device=self.fw).dismissed_at)

    def test_soc_page_scope_and_permissions(self):
        vuln.evaluate(self.now)
        self.client.force_login(self.staff)
        page_ = self.client.get(reverse('vulnerabilities'))
        self.assertContains(page_, 'CVE-2026-44194')
        self.assertContains(page_, 'Publicar la pendiente')
        self.assertNotContains(page_, 'Empresa B')
        reader = get_user_model().objects.create_user('lector')
        StaffAccess.objects.create(user=reader, role='reader').clients.add(self.company)
        self.client.force_login(reader)
        response = self.client.post(reverse('vulnerabilities'), {'action': 'publish', 'client': self.company.pk, 'cve': 'CVE-2026-44194'})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(VulnerabilityAdvisory.objects.exists())

    def test_bulk_publish_sends_one_email_per_client(self):
        VulnerabilityRecord.objects.create(cve_id='CVE-2026-44195', product='a:opnsense:opnsense', severity='HIGH',
                                           kev_added=self.now.date(), ranges=[{'version': '*', 'ee': '26.1.8'}])
        vuln.evaluate(self.now)
        self.company.vulnerability_notices_enabled = True
        self.company.save()
        self.client.force_login(self.staff)
        self.client.post(reverse('vulnerabilities'), {'action': 'publish_client', 'client': self.company.pk, 'note': 'Martes'})
        self.assertEqual(VulnerabilityAdvisory.objects.filter(client=self.company, notice_status='queued').count(), 2)
        with mock.patch('core.mail_delivery.send_customer_email', return_value='msg-1') as send:
            self.assertEqual(vuln.send_pending(now=self.now), 1)
        self.assertEqual(send.call_count, 1)
        self.assertIn('Se han publicado 2 vulnerabilidades', send.call_args.args[2])
        self.assertIn('ataques reales', send.call_args.args[2])
        self.assertEqual(set(VulnerabilityAdvisory.objects.values_list('notice_status', flat=True)), {'accepted'})
        self.assertFalse(VulnerabilityAdvisory.objects.filter(client=self.other).exists())

    def test_uncertain_send_is_not_retried(self):
        vuln.evaluate(self.now)
        self.company.vulnerability_notices_enabled = True
        self.company.save()
        vuln.publish(self.company, 'CVE-2026-44194', '', self.staff)
        from .mail_delivery import MailDeliveryError
        with mock.patch('core.mail_delivery.send_customer_email', side_effect=MailDeliveryError('x')) as send:
            vuln.send_pending(now=self.now)
            vuln.send_pending(now=self.now)
        self.assertEqual(send.call_count, 1)
        self.assertEqual(VulnerabilityAdvisory.objects.get().notice_status, 'uncertain')

    def test_product_override_validated(self):
        hill = Device.objects.create(site=self.site, name='HS', vendor='hillstone', software_version='5.5R10')
        self.client.force_login(self.staff)
        self.assertContains(self.client.get(reverse('vulnerabilities')), 'Sin producto conocido en NVD')
        self.client.post(reverse('vulnerabilities'), {'action': 'product', 'device': hill.pk, 'product': 'https://evil/x'})
        hill.refresh_from_db()
        self.assertEqual(hill.vulnerability_product, '')
        self.client.post(reverse('vulnerabilities'), {'action': 'product', 'device': hill.pk,
                                                      'product': 'cpe:2.3:o:hillstonenet:sc-6000-e3960_firmware:5.5:*:*'})
        hill.refresh_from_db()
        self.assertEqual(hill.vulnerability_product, 'o:hillstonenet:sc-6000-e3960_firmware')

    def test_index_counts_only_what_was_published(self):
        DeviceHealth.objects.create(device=self.fw, api_ok=True, checked_at=self.now, protection_checked_at=self.now, last_log_at=self.now,
                                    engines={'Firmware': {'updates_available': False, 'catalogue_checked_at': self.now.isoformat()}})

        def firmware():
            return {f['key']: f for f in security_score.compute(self.company, self.now)['factors']}['firmware']
        self.assertEqual(firmware()['state'], 'ok')
        vuln.evaluate(self.now)
        self.assertEqual(firmware()['state'], 'unknown')  # pendiente de revisar: no se adelanta al cliente
        vuln.publish(self.company, 'CVE-2026-44194', '', self.staff)
        self.assertEqual(firmware()['state'], 'bad')

    def test_preview_and_services_field(self):
        vuln.evaluate(self.now)
        vuln.publish(self.company, 'CVE-2026-44194', '', self.staff)
        self.client.force_login(self.staff)
        self.assertContains(self.client.get(reverse('customer_preview_vulnerabilities', args=[self.company.pk])), 'CVE-2026-44194')
        self.assertContains(self.client.get(reverse('client_detail', args=[self.company.pk])), 'Avisos de vulnerabilidad')

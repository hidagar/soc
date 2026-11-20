"""Q-Feeds, plan A: revisión de destinos salientes, bandeja, menú, listas de la licencia y evolución."""
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import TestCase, override_settings
from django.urls import reverse

from . import threat_intel
from .models import AuditEvent, Incident, SecurityEvidence, StaffAccess, ThreatIntelReview
from .test_threat_intel import C2, OTHER_C2, ThreatIntelTests


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class ThreatIntelReviewTests(TestCase):
    setUp = ThreatIntelTests.setUp
    sync = ThreatIntelTests.sync

    def ready(self, now=None):
        self.sync()
        threat_intel.refresh_matches(now or self.now)

    def operator(self, *perms, all_clients=False):
        user = get_user_model().objects.create_user('analista')
        access = StaffAccess.objects.create(user=user, role='operator', all_clients=all_clients)
        if not all_clients:
            access.clients.add(self.company)
        for codename in ('manage_operations', *perms):
            user.user_permissions.add(Permission.objects.get(codename=codename))
        self.client.force_login(user)
        return user

    def post(self, action, ip=C2, client=None, **extra):
        return self.client.post(reverse('threat_intel_review'), {'client': (client or self.company).pk, 'ip': ip, 'action': action, **extra})

    def queue(self):
        return [(m.client_id, m.ip) for m in threat_intel.pending(
            list(threat_intel.ThreatIntelMatch._base_manager.filter(role='destination')), ThreatIntelReview._base_manager.all())]

    def new_traffic(self, hours):
        SecurityEvidence.objects.create(uid=f'{9000 + hours:064x}', device=self.device, observed_at=self.now + timedelta(hours=hours),
                                        engine='suricata', signature='Firma', source_ip='10.0.0.7', destination_ip=C2,
                                        action='allowed', level=8, client_scope_id=self.company.pk)
        threat_intel.refresh_matches(self.now + timedelta(hours=hours + 1))

    def test_outbound_destinations_wait_for_review_allowed_first(self):
        self.ready()
        self.assertEqual(self.queue(), [(self.company.pk, C2), (self.other.pk, OTHER_C2)])

    def test_dismissing_keeps_the_decision_until_there_is_new_traffic(self):
        self.ready()
        self.operator()
        response = self.post('dismiss', reason='  Servicio   legítimo ')
        self.assertRedirects(response, reverse('threat_intel') + '#salientes', fetch_redirect_response=False)
        review = ThreatIntelReview.objects.get()
        self.assertEqual((review.decision, review.reason), ('dismissed', 'Servicio legítimo'))
        threat_intel.refresh_matches(self.now + timedelta(minutes=15))  # se recalcula: la decisión sigue
        self.assertNotIn((self.company.pk, C2), self.queue())
        self.assertTrue(AuditEvent.objects.filter(action='threat_intel.dismissed').exists())
        self.new_traffic(2)
        self.assertIn((self.company.pk, C2), self.queue())

    def test_opening_an_incident_is_internal_and_returns_when_resolved_with_new_traffic(self):
        self.ready()
        user = self.operator('add_incident')
        response = self.post('incident')
        incident = Incident.objects.get()
        self.assertRedirects(response, reverse('incident_detail', args=[incident.pk]), fetch_redirect_response=False)
        self.assertEqual((incident.client, incident.device, incident.severity, incident.owner), (self.company, self.device, 'high', user))
        self.assertIn('no acredita una infección', incident.description)
        self.assertNotIn((self.company.pk, C2), self.queue())
        # Una segunda petición no duplica la incidencia mientras siga abierta.
        self.post('incident')
        self.assertEqual(Incident.objects.count(), 1)
        Incident.objects.filter(pk=incident.pk).update(status='resolved', resolved_at=self.now + timedelta(hours=1))
        self.new_traffic(3)
        self.assertIn((self.company.pk, C2), self.queue())

    def test_opening_an_incident_needs_its_permission(self):
        self.ready()
        self.operator()
        self.assertEqual(self.post('incident').status_code, 403)
        self.assertFalse(Incident.objects.exists())

    def test_destinations_of_other_clients_cannot_be_reviewed(self):
        self.ready()
        self.operator('add_incident')
        self.post('dismiss', ip=OTHER_C2, client=self.other)
        self.post('incident', ip=OTHER_C2, client=self.other)
        self.assertFalse(ThreatIntelReview._base_manager.exists())
        self.assertFalse(Incident.objects.exists())

    def test_work_queue_and_menu_show_pending_destinations_only_to_operations(self):
        self.ready()
        user = self.operator()
        page = self.client.get(reverse('work_queue'))
        self.assertContains(page, 'Conexiones hacia destinos maliciosos')
        self.assertContains(page, C2)
        self.assertNotContains(page, OTHER_C2)
        self.assertContains(page, 'Marcar sin riesgo')
        self.assertNotContains(page, 'Abrir incidencia')  # sin permiso para abrirla
        user.user_permissions.remove(Permission.objects.get(codename='manage_operations'))
        user = get_user_model().objects.get(pk=user.pk)
        self.client.force_login(user)
        self.assertNotContains(self.client.get(reverse('work_queue')), 'Conexiones hacia destinos maliciosos')

    def test_licence_offer_and_daily_history_are_recorded(self):
        self.ready()
        values = threat_intel.details()
        offered = {item['name']: item for item in values['offered']}
        self.assertEqual(offered['malicious_urls'], {'name': 'malicious_urls', 'type': 'url', 'licensed': False, 'wanted': False})
        self.assertTrue(offered['malware_ip']['wanted'])
        [day] = values['history']
        self.assertEqual((day['outbound'], day['outbound_allowed'], day['pending'], day['clients']), (2, 1, 2, 2))
        self.assertEqual(day['indicators'], 6)
        threat_intel.refresh_matches(self.now + timedelta(minutes=15))
        self.assertEqual(len(threat_intel.details()['history']), 1)  # una fila por día
        self.operator(all_clients=True)
        page = self.client.get(reverse('threat_intel'))
        self.assertContains(page, 'Listas que ofrece tu licencia')
        self.assertContains(page, 'Evolución: qué aporta Q-Feeds')

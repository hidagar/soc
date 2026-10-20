from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase, override_settings
from django.urls import reverse
from .models import AuditEvent, Client, Site, Device, Incident, ConfigurationArchive, StaffAccess
from .security import audit, audit_integrity
from .audit_presentation import present


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class AuditPresentationTests(TestCase):
    def setUp(self):
        self.user=get_user_model().objects.create_user('auditor')
        self.user.groups.add(Group.objects.get(name='SOC Administrador'))
        StaffAccess.objects.create(user=self.user,role='manager',all_clients=True)
        self.company=Client.objects.create(name='Cliente visible',code='audit-visible')
        site=Site.objects.create(client=self.company,name='Sede',code='audit-site')
        self.device=Device.objects.create(site=site,name='Firewall de oficina',vendor='opnsense')
        self.case=Incident.objects.create(client=self.company,device=self.device,title='Revisar ordenador de contabilidad')
        self.client.force_login(self.user)

    def test_known_codes_and_detail_counts_are_explained(self):
        e=audit('incident.automatic',self.case,{'count':12})
        row=present([e])[0]
        self.assertEqual(row['action'],'Incidencia creada automáticamente')
        self.assertIn('12 detecciones relacionadas al crear el caso.',row['details'])
        self.assertIn('contabilidad',row['object'])
        self.assertEqual(row['url'],reverse('incident_detail',args=[self.case.pk]))
        self.assertEqual(row['actor'],'Proceso automático')

    def test_backups_explain_changed_sections_and_keep_hash_technical(self):
        archive=ConfigurationArchive.objects.create(device=self.device,status='saved')
        digest='f'*64
        row=present([audit('firewall.backup_saved',archive,{'sha256':digest,'count':0})])[0]
        self.assertIn('0 secciones con cambios registradas.',row['details'])
        self.assertNotIn(digest,' '.join(row['details']))
        self.assertIn(digest,row['technical'])
        self.assertIn('Firewall de oficina',row['object'])
        self.assertEqual(row['url'],reverse('configuration_archives',args=[self.device.pk]))

    def test_http_status_is_response_not_claim_of_saved_data(self):
        row=present([audit('portal.client_edit',details={'status':200})])[0]
        self.assertEqual(row['action'],'Solicitud: Editar cliente')
        self.assertIn('Página mostrada (HTTP 200).',row['details'])
        row=present([audit('portal.mfa_challenge',details={'status':302})])[0]
        self.assertEqual(row['action'],'Solicitud: Verificar segundo factor')
        self.assertIn('Redirección a otra página (HTTP 302).',row['details'])

    def test_fields_and_status_labels_are_readable(self):
        row=present([audit('network.requirements',details={'fields':['scope','require_ips','review_until'],'status':'pending'})])[0]
        self.assertIn('Estado registrado: Pendiente.',row['details'])
        self.assertIn('Campos modificados: Ámbito del servicio, IPS requerido, Fecha de revisión.',row['details'])

    def test_unknown_actions_and_deleted_objects_have_safe_fallback(self):
        event=audit('future.operation',self.case,{'status':'new-value'})
        self.case.delete()
        row=present([event])[0]
        self.assertEqual(row['action'],'Operación registrada')
        self.assertIn('ficha no disponible',row['object'])
        self.assertFalse(row['url'])
        self.assertIn('new-value',row['technical'])

    def test_presentation_never_rewrites_signed_events(self):
        event=audit('password_login',user=self.user)
        before=list(AuditEvent.objects.values())
        self.assertTrue(audit_integrity())
        present(AuditEvent.objects.all())
        self.client.get(reverse('audit_log'))
        self.assertEqual(list(AuditEvent.objects.values()),before)
        self.assertTrue(audit_integrity())

    def test_untrusted_text_is_escaped_in_template(self):
        self.case.title='<script>alert(1)</script>';self.case.save()
        audit('incident.automatic',self.case,{'count':1,'reason':'<img src=x onerror=alert(1)>'})
        response=self.client.get(reverse('audit_log'))
        self.assertContains(response,'&lt;script&gt;alert(1)&lt;/script&gt;')
        self.assertNotContains(response,'<script>alert(1)</script>')
        self.assertContains(response,'&lt;img')

    def test_non_global_operator_cannot_open_audit(self):
        access=self.user.soc_access;access.all_clients=False;access.save()
        access.clients.add(self.company)
        self.assertEqual(self.client.get(reverse('audit_log')).status_code,403)

    def test_template_has_explanations_and_collapsed_technical_details(self):
        audit('mfa.verified',user=self.user)
        response=self.client.get(reverse('audit_log'))
        self.assertContains(response,'Segundo factor comprobado correctamente.')
        self.assertContains(response,'<details>')
        self.assertContains(response,'Ver datos técnicos')

    def test_object_names_are_batched_for_many_events(self):
        event=audit('incident.automatic',self.case,{'count':1})
        # One projection per model, rather than querying a record for every event.
        with self.assertNumQueries(1):
            rows=present([event]*100)
        self.assertEqual(len(rows),100)

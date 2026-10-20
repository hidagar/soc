import json
from datetime import timedelta
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from .models import Client, Site, Device, FirewallOnboarding, ExportConfiguration
from .onboarding import EquipmentForm, MethodForm
from .onboarding_verification import confirm_onboarding_events
from .protection import snapshot
from .testing_access import workflow_access


@override_settings(SECURE_SSL_REDIRECT=False)
class GrandstreamGccTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user=get_user_model().objects.create_user('gcc-operator')
        workflow_access(cls.user, reader=False)
        cls.user.user_permissions.add(Permission.objects.get(codename='manage_connections'))
        customer=Client.objects.create(name='GCC laboratorio',code='gcc-lab')
        cls.site=Site.objects.create(client=customer,name='Sede',code='gcc-site')

    def setUp(self):
        self.client.force_login(self.user)
        self.device=Device.objects.create(site=self.site,name='GCC6010',vendor='grandstream_gcc')

    def test_model_and_wizard_accept_gcc_without_management_credentials(self):
        form=EquipmentForm({'name':'GCC6011','vendor':'grandstream_gcc'})
        self.assertTrue(form.is_valid(),form.errors)
        device=form.save(commit=False)
        device.site=self.site
        device.full_clean()
        self.assertEqual(device.connection_profile_label,'Grandstream GCC')
        choices=MethodForm(device=device,can_manage=True).fields['method'].choices
        self.assertEqual([value for value,label in choices],['https','manual'])

    def test_guided_direct_destination_and_security_limits(self):
        FirewallOnboarding.objects.create(device=self.device,step=4,method='manual')
        page=self.client.get(reverse('device_onboarding',args=[self.device.pk]))
        self.assertContains(page,'Networking</strong> (icono del globo) y abre <strong>Maintenance → System Diagnostics → Syslog')
        self.assertContains(page,':5514</strong> y deja <strong>Protocol: UDP')
        self.assertContains(page,'Seguridad pendiente de validar')
        guide=self.client.get(reverse('connection_guide'),{'device':self.device.pk})
        self.assertContains(guide,'Grandstream GCC')
        self.assertContains(guide,'Networking</strong> (icono del globo) y abre <strong>Maintenance → System Diagnostics → Syslog')
        self.assertContains(guide,'No necesitas credenciales de gestión para este alta.')

    def test_https_guide_uses_local_relay_destination(self):
        from .secure_logs import prepare
        prepare(self.device)
        page=self.client.get(reverse('secure_log_setup',args=[self.device.pk]))
        self.assertContains(page,'IP LAN del reenviador')
        self.assertContains(page,'IP LAN del reenviador:5515</strong> y deja <strong>Protocol: UDP')
        self.assertContains(page,'Networking</strong> (icono del globo) y abre <strong>Maintenance → System Diagnostics → Syslog')

    def test_real_activity_confirms_receipt_but_keeps_threat_coverage_pending(self):
        now=timezone.now()
        row=FirewallOnboarding.objects.create(device=self.device,step=5,method='manual',verification_started_at=now-timedelta(seconds=10))
        ExportConfiguration.objects.create(device=self.device,source_ip='198.51.100.47',destination='172.20.10.20',status='configured',receiver_ready=True)
        event={'timestamp':now.isoformat(),'location':'198.51.100.47','decoder':{'name':'sshd'},'rule':{'id':'5715'}}
        self.assertEqual(confirm_onboarding_events([json.dumps(event)],now=now),1)
        row.refresh_from_db()
        self.assertIsNotNone(row.verified_at)
        result=snapshot(self.device,now=now)
        self.assertIn('gcc-security-validation',[gap['code'] for gap in result['gaps']])
        self.assertEqual(result['controls'],[])

"""Las listas de opciones de los formularios respetan el ámbito de cliente de cada petición.

Antes se fijaban al importar el formulario: un operador limitado a un cliente podía mover
un firewall, una sede o una incidencia a otro cliente, y veía sus nombres.
"""
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from .forms import DeviceForm, IncidentForm, SiteEditForm, SiteForm
from .models import Client, Device, Incident, Site, StaffAccess
from .scope import customer_scope


@override_settings(SECURE_SSL_REDIRECT=False, SOC_MFA_REQUIRED=False)
class FormScopeTests(TestCase):
    def setUp(self):
        self.own = Client.objects.create(name='Cliente propio', code='propio')
        self.foreign = Client.objects.create(name='CLIENTE AJENO', code='ajeno')
        self.site = Site.objects.create(client=self.own, name='Sede propia', code='s1')
        self.foreign_site = Site.objects.create(client=self.foreign, name='SEDE AJENA', code='s2')
        self.device = Device.objects.create(site=self.site, name='FW-propio', vendor='opnsense')
        self.operator = get_user_model().objects.create_user('operador')
        StaffAccess.objects.create(user=self.operator, role='operator').clients.add(self.own)
        self.operator.groups.add(Group.objects.get(name='SOC Operador'))
        self.client.force_login(self.operator)

    def test_choices_follow_the_scope_of_each_request_not_of_the_first_import(self):
        token = customer_scope.set([self.own.pk])
        try:
            for form, field in ((SiteForm(), 'client'), (SiteEditForm(instance=self.site), 'client'),
                                (DeviceForm(instance=self.device), 'site'), (IncidentForm(), 'client')):
                self.assertNotIn(self.foreign.pk if field == 'client' else self.foreign_site.pk,
                                 [obj.pk for obj in form.fields[field].queryset], type(form).__name__)
        finally:
            customer_scope.reset(token)
        # Sin ámbito (administración global o trabajos), la misma clase ve todos.
        self.assertIn(self.foreign.pk, [c.pk for c in SiteForm().fields['client'].queryset])

    def test_scoped_operator_cannot_move_data_to_another_client(self):
        device_data = {'site': self.foreign_site.pk, 'name': 'FW-propio', 'vendor': 'opnsense',
                       'management_method': 'none', 'log_method': 'syslog', 'active': 'on'}
        page = self.client.post(reverse('device_edit', args=[self.device.pk]), device_data)
        self.assertEqual(page.status_code, 200)
        self.device.refresh_from_db()
        self.assertEqual(self.device.site, self.site)
        self.client.post(reverse('site_edit', args=[self.site.pk]),
                         {'client': self.foreign.pk, 'name': 'Sede propia', 'code': 's1', 'active': 'on'})
        self.site.refresh_from_db()
        self.assertEqual(self.site.client, self.own)
        self.client.post(reverse('incident_new'), {'client': self.foreign.pk, 'title': 'Caso', 'description': 'x',
                                                   'severity': 'low', 'status': 'open',
                                                   'observed_at': timezone.now().strftime('%Y-%m-%dT%H:%M')})
        self.assertFalse(Incident._base_manager.filter(client=self.foreign).exists())
        self.client.post(reverse('site_new'), {'wizard_step': '1', 'client': self.foreign.pk, 'name': 'Nueva', 'code': ''})
        self.assertFalse(Site._base_manager.filter(client=self.foreign).exclude(pk=self.foreign_site.pk).exists())

    def test_edit_pages_do_not_list_other_clients(self):
        for url in (reverse('device_edit', args=[self.device.pk]), reverse('site_edit', args=[self.site.pk]),
                    reverse('incident_new')):
            page = self.client.get(url)
            self.assertEqual(page.status_code, 200, url)
            self.assertNotContains(page, 'CLIENTE AJENO')
            self.assertNotContains(page, 'SEDE AJENA')

    def test_customer_accounts_are_never_incident_owners(self):
        customer = get_user_model().objects.create_user('cliente')
        StaffAccess.objects.create(user=customer, role='customer').clients.add(self.own)
        form = IncidentForm(initial={'client': self.own.pk})
        owners = list(form.fields['owner'].queryset)
        self.assertIn(self.operator, owners)
        self.assertNotIn(customer, owners)


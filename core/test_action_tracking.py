from datetime import datetime,timedelta,time
from django.test import TestCase,override_settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.utils import timezone
from django.urls import reverse
from .models import Client,Site,Device,Incident,IncidentAction,StaffAccess,SecurityEvidence
from .trends import trend_context

@override_settings(SECURE_SSL_REDIRECT=False,SOC_MFA_REQUIRED=False)
class ActionTrackingTests(TestCase):
    def setUp(self):
        self.c=Client.objects.create(name='Visible',code='visible')
        self.other=Client.objects.create(name='Oculto',code='hidden')
        self.s=Site.objects.create(client=self.c,name='Sede',code='sede')
        self.d=Device.objects.create(site=self.s,name='Firewall',vendor='opnsense')
        self.i=Incident.objects.create(client=self.c,site=self.s,device=self.d,title='Malware',description='Evento')
        self.foreign=Incident.objects.create(client=self.other,title='Secreto',description='Evento')
        User=get_user_model()
        self.user=User.objects.create_user('operator')
        self.foreign_user=User.objects.create_user('foreign')
        for u,c in [(self.user,self.c),(self.foreign_user,self.other)]:
            a=StaffAccess.objects.create(user=u,role='operator');a.clients.add(c)
            u.groups.add(Group.objects.get(name='SOC Operador'))
        self.client.force_login(self.user)
    def data(self,**changes):
        data={'title':'Analizar equipo','description':'Ejecutar análisis EDR','owner':self.user.pk,'responsible_party':'client','due_at':timezone.localtime(timezone.now()+timedelta(days=1)).strftime('%Y-%m-%dT%H:%M'),'status':'pending','resolution':''}
        data.update(changes);return data
    def test_creation_and_closure_require_evidence_and_create_history(self):
        response=self.client.post(reverse('action_new',args=[self.i.pk]),self.data())
        self.assertEqual(response.status_code,302)
        a=IncidentAction.objects.get(incident=self.i)
        response=self.client.post(reverse('action_edit',args=[a.pk]),self.data(status='done'))
        self.assertEqual(response.status_code,200)
        a.refresh_from_db();self.assertEqual(a.status,'pending')
        self.client.post(reverse('action_edit',args=[a.pk]),self.data(status='done',resolution='EDR completado, sin persistencia; referencia INC-001'))
        a.refresh_from_db();self.assertEqual(a.status,'done');self.assertIsNotNone(a.completed_at)
        self.assertTrue(self.i.timeline.filter(text__contains='EDR completado').exists())
    def test_foreign_client_owner_and_forged_action_are_denied(self):
        self.assertEqual(self.client.get(reverse('action_new',args=[self.foreign.pk])).status_code,404)
        self.client.post(reverse('action_new',args=[self.i.pk]),self.data(owner=self.foreign_user.pk))
        self.assertFalse(IncidentAction.objects.filter(incident=self.i).exists())
        a=IncidentAction.objects.create(incident=self.foreign,title='Tarea privada')
        self.assertEqual(self.client.post(reverse('action_edit',args=[a.pk]),self.data()).status_code,404)
        response=self.client.get(reverse('action_list'),{'status':'all'})
        self.assertNotContains(response,'Tarea privada')
        self.assertEqual(self.client.get(reverse('client_trends',args=[self.other.pk])).status_code,404)
    def test_reader_can_view_but_not_change(self):
        self.user.groups.clear();self.user.groups.add(Group.objects.get(name='SOC Consulta'))
        access=self.user.soc_access;access.role='reader';access.save()
        self.assertEqual(self.client.get(reverse('action_list')).status_code,200)
        self.assertEqual(self.client.post(reverse('action_new',args=[self.i.pk]),self.data()).status_code,403)
    def test_open_action_requires_owner_and_deadline(self):
        response=self.client.post(reverse('action_new',args=[self.i.pk]),self.data(owner='',due_at=''))
        self.assertContains(response,'Asigna un responsable')
        self.assertContains(response,'Indica una fecha')
        self.assertFalse(IncidentAction.objects.exists())
    def test_overdue_filter_and_edit_preserve_custom_title(self):
        a=IncidentAction.objects.create(incident=self.i,title='Título personalizado',owner=self.user,due_at=timezone.now()-timedelta(hours=1))
        self.assertTrue(a.overdue)
        self.assertContains(self.client.get(reverse('action_list'),{'status':'overdue'}),'Título personalizado')
        response=self.client.get(reverse('action_edit',args=[a.pk]))
        self.assertContains(response,'Título personalizado')
    def test_pending_action_reopens_a_resolved_incident(self):
        self.i.status='resolved';self.i.resolved_at=timezone.now();self.i.save()
        self.client.post(reverse('action_new',args=[self.i.pk]),self.data())
        self.i.refresh_from_db();self.assertEqual(self.i.status,'investigating');self.assertIsNone(self.i.resolved_at)
    def test_incident_cannot_close_while_actions_remain_pending(self):
        from .forms import IncidentForm
        IncidentAction.objects.create(incident=self.i,title='Pendiente',owner=self.user,due_at=timezone.now()+timedelta(days=1))
        data={'client':self.c.pk,'site':self.s.pk,'device':self.d.pk,'title':'Malware','description':'Evento','severity':'high','status':'resolved','owner':self.user.pk,'observed_at':timezone.localtime(self.i.observed_at).strftime('%Y-%m-%dT%H:%M'),'resolved_at':''}
        form=IncidentForm(data=data,instance=self.i)
        self.assertFalse(form.is_valid())
        self.assertIn('Completa o cancela',str(form.errors['status']))
    def test_trends_compare_equivalent_elapsed_periods(self):
        now=timezone.make_aware(datetime(2026,10,6,12))
        start=timezone.make_aware(datetime(2026,10,5))
        for uid,stamp in [('current',start+timedelta(hours=1)),('previous',start-timedelta(days=7)+timedelta(hours=1)),('later_previous',start-timedelta(days=3)),('policy',start+timedelta(hours=2))]:
            SecurityEvidence.objects.create(uid=uid,device=self.d,observed_at=stamp,engine='zenarmor',category='application_policy' if uid=='policy' else 'Malware',signature='Malware',action='blocked')
        context=trend_context(self.c,now)
        totals=context['comparisons'][0]
        self.assertEqual(totals['current'],1);self.assertEqual(totals['previous'],1)
        self.assertEqual(totals['difference'],0)
        self.assertEqual(context['weeks'][-2]['count'],2)
        self.assertTrue(context['weeks'][-1]['provisional'])

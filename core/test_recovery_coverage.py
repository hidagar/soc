import io,json,sqlite3,tarfile,tempfile,hashlib
from pathlib import Path
from unittest.mock import patch
from datetime import timedelta
from cryptography.fernet import Fernet
from django.test import TestCase,SimpleTestCase,override_settings,Client as Browser
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.urls import reverse
from .recovery_components import selected_indices,verify_profile,REQUIRED,export_live_security,SECURITY_KINDS
from .recovery import native_snapshot,test_indexer_restore,validate_tar
from .models import RecoverySettings,BackupRun
from .control_views import RecoveryForm
from .testing_access import workflow_access

class RecoveryCoverageTests(SimpleTestCase):
    def test_index_allowlist_excludes_security_and_live_restore_clones(self):
        result=selected_indices([{'index':n} for n in ('wazuh-alerts-4.x-2026.10.13','.kibana_1','.opensearch_dashboards_1','.opendistro_security','soc-restore-check-dead-other','unrelated')])
        self.assertEqual(len(result),3);self.assertNotIn('.opendistro_security',result)
        with self.assertRaises(ValueError):selected_indices([{'index':'wazuh-alerts-only'}])
    def test_profile_requires_sso_bootstrap_and_live_security_exports(self):
        names={n:'hash' for n in (*REQUIRED,'portal.sqlite3')}
        manifest={'profile':2,'indexer_indices':['.kibana_1','wazuh-alerts-test']}
        self.assertEqual(verify_profile(manifest,names)['coverage']['saved_object_indices'],1)
        self.assertEqual(verify_profile(manifest,{**{n:'hash' for n in REQUIRED},'portal.pgdump':'hash'})['profile'],2)
        for missing in ('portal.sqlite3','config/dashboard/opensearch_dashboards_sso.yml','config/live-security/rolesmapping.json','config/bootstrap/wazuh-install-files.tar'):
            with self.assertRaises(ValueError):verify_profile(manifest,{k:v for k,v in names.items() if k!=missing})
        self.assertEqual(verify_profile({},{}),{}) # Existing encrypted archives remain readable.
    def test_native_snapshot_has_explicit_names_without_global_state(self):
        calls=[]
        def api(path,payload=None,**kwargs):
            calls.append((path,payload,kwargs))
            if path.startswith('/_cat/'):return [{'index':'.kibana_1'},{'index':'wazuh-alerts-test'}]
            return {'snapshot':{'state':'SUCCESS','indices':['wazuh-alerts-test','.kibana_1']}}
        with patch('core.indexer_admin.admin_request',side_effect=api):self.assertTrue(native_snapshot().startswith('soc-'))
        body=calls[-1][1];self.assertFalse(body['include_global_state']);self.assertFalse(body['ignore_unavailable'])
        self.assertEqual(body['indices'],'.kibana_1,wazuh-alerts-test')
    def test_restore_is_exactly_scoped_and_does_not_import_aliases(self):
        calls=[];prefix='soc-restore-check-'+'a'*16+'-'
        def api(path,payload=None,**kwargs):
            calls.append((path,payload,kwargs))
            if path=='/_snapshot/soc_recovery/soc-20261013000000':return {'snapshots':[{'state':'SUCCESS','indices':['.kibana_1','wazuh-alerts-test']}]}
            if path.endswith('/_restore'):return {'accepted':True}
            if path.startswith('/_cluster/'):return {'status':'green','timed_out':False}
            if path.startswith('/_cat/'):return [{'index':prefix+'.kibana_1','docs.count':'72'},{'index':prefix+'wazuh-alerts-test','docs.count':'100'}]
            return {}
        with patch('core.indexer_admin.admin_request',side_effect=api),patch('secrets.token_hex',return_value='a'*16):
            result=test_indexer_restore('soc-20261013000000')
        self.assertEqual(result['restored_saved_object_indices'],1);self.assertEqual(result['restored_docs'],172)
        restore=next(c for c in calls if c[0].endswith('/_restore'))
        self.assertFalse(restore[1]['include_aliases']);self.assertFalse(restore[1]['include_global_state'])
        self.assertEqual(calls[-1][0],'/'+prefix+'*?expand_wildcards=all');self.assertEqual(calls[-1][2]['method'],'DELETE')
    def test_restore_rejects_unexpected_index_without_a_write(self):
        with patch('core.indexer_admin.admin_request',return_value={'snapshots':[{'state':'SUCCESS','indices':['.kibana_1','wazuh-alerts-test','other']}]}) as api:
            with self.assertRaises(ValueError):test_indexer_restore('soc-20261013000000')
        self.assertEqual(api.call_count,1)
    def test_security_exports_are_private_and_only_paths_are_returned(self):
        with tempfile.TemporaryDirectory() as directory:
            files=export_live_security(directory,lambda path:{'private-hash':'PRIVATE'})
            self.assertEqual(len(files),len(SECURITY_KINDS));self.assertNotIn('PRIVATE',str(files))
            self.assertTrue(all(p.is_file() for p in files.values()))
            import os
            if os.name!='nt':self.assertTrue(all(p.stat().st_mode & 0o077==0 for p in files.values()))
    def test_nested_firewall_configuration_is_decrypted_and_xml_validated(self):
        from . import recovery
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);key=root/'key';key.write_bytes(Fernet.generate_key())
            db=root/'source.sqlite3'
            with sqlite3.connect(db) as c:c.execute('CREATE TABLE django_migrations (id INTEGER)')
            c.close()
            members={'portal.sqlite3':db.read_bytes(),'config/soc-portal/portal.env':b'private','firewalls/encrypted/1.fernet':Fernet(key.read_bytes()).encrypt(b'<opnsense><nat/></opnsense>')}
            archive=root/'archive.tar.gz'
            with tarfile.open(archive,'w:gz') as t:
                manifest={'files':{k:hashlib.sha256(v).hexdigest() for k,v in members.items()}}
                for name,body in [*members.items(),('manifest.json',json.dumps(manifest).encode())]:
                    entry=tarfile.TarInfo(name);entry.size=len(body);t.addfile(entry,io.BytesIO(body))
            target=root/'verify';target.mkdir()
            with patch.object(recovery,'KEY',key):self.assertEqual(validate_tar(archive,target)['firewall_xml_checked'],1)
    def test_vm_forms_do_not_require_sftp_or_invent_backup_dates(self):
        values={'transport':'vm','retention_days':30,'evidence_days':90,'operational_email':'noc@example.test'}
        form=RecoveryForm(values);self.assertTrue(form.is_valid(),form.errors)
        self.assertIsNone(form.cleaned_data['vm_last_backup_at']);self.assertNotIn('hostname',form.fields)
        form=RecoveryForm({**values,'vm_last_backup_at':(timezone.now()+timedelta(days=1)).isoformat()});self.assertFalse(form.is_valid())
        form=RecoveryForm({**values,'vm_last_restore_at':timezone.now().isoformat()});self.assertFalse(form.is_valid())
    def test_old_integrity_timestamps_are_not_shown_as_native_restore(self):
        run=BackupRun(restore_tested_at=timezone.now(),details={'database_integrity':'ok'})
        self.assertIsNone(run.native_restore_checked_at)
        run.details={'native_restore':'ok'};self.assertEqual(run.native_restore_checked_at,run.restore_tested_at)

@override_settings(SOC_MFA_REQUIRED=False,SECURE_SSL_REDIRECT=False)
class RecoveryVMViewsTests(TestCase):
    def setUp(self):
        self.user=get_user_model().objects.create_user(username='recovery-manager');workflow_access(self.user,reader=False)
        self.user.user_permissions.add(Permission.objects.get(codename='manage_recovery'))
        self.client.force_login(self.user)
    def test_operator_declaration_does_not_verify_a_transfer_or_restore(self):
        with patch('core.control_views.mfa_fresh',return_value=True):
            response=self.client.post(reverse('recovery'),{'action':'save','transport':'vm','vm_platform':'VM backup','vm_storage':'External repository','retention_days':30,'evidence_days':90,'operational_email':'noc@example.test'})
        self.assertEqual(response.status_code,302)
        cfg=RecoverySettings.objects.get(pk=1);self.assertEqual(cfg.transport,'vm')
        self.assertFalse(cfg.enabled);self.assertFalse(cfg.verified);self.assertIsNone(cfg.vm_backup['vm_last_backup_at'])
        self.assertFalse(BackupRun.objects.exists())
        self.assertContains(self.client.get(reverse('recovery')),'no consulta el hipervisor')
    def test_vm_settings_require_csrf_and_fresh_mfa(self):
        browser=Browser(enforce_csrf_checks=True);browser.force_login(self.user)
        self.assertEqual(browser.post(reverse('recovery'),{'action':'save','transport':'vm'}).status_code,403)
        with patch('core.control_views.mfa_fresh',return_value=False):
            response=self.client.post(reverse('recovery'),{'action':'save','transport':'vm'})
        self.assertEqual(response.status_code,302);self.assertIn('/security/mfa/',response.url)


class RestoreTestScopeTests(SimpleTestCase):
    """La prueba de restauración no duplica el histórico cada día ni llena el disco del indexador."""
    def test_sample_and_inventory_ignore_daily_rotation(self):
        from .recovery import restore_inventory,restore_sample
        monday=['.kibana_1','soc-customer-7-events','wazuh-alerts-4.x-2026.10.12','wazuh-alerts-4.x-2026.10.13']
        tuesday=['.kibana_1','soc-customer-7-events','wazuh-alerts-4.x-2026.10.13','wazuh-alerts-4.x-2026.10.14']
        self.assertEqual(restore_sample(tuesday),['.kibana_1','soc-customer-7-events','wazuh-alerts-4.x-2026.10.14'])
        self.assertEqual(restore_inventory(monday),restore_inventory(tuesday),'la rotación diaria no repite la prueba')
        self.assertNotEqual(restore_inventory(monday),restore_inventory(monday+['soc-customer-8-events']),'un cliente nuevo sí')
    def test_restore_is_postponed_when_it_would_fill_the_indexer_disk(self):
        calls=[]
        def api(path,payload=None,**kwargs):
            calls.append(path)
            if path=='/_snapshot/soc_recovery/soc-20261013000000':return {'snapshots':[{'state':'SUCCESS','indices':['.kibana_1','wazuh-alerts-test']}]}
            if path.startswith('/_cat/indices/'):return [{'index':'wazuh-alerts-test','pri.store.size':'40000'}]
            if path.startswith('/_cat/allocation'):return [{'disk.total':'100000','disk.used':'50000'}]
            raise AssertionError(path)
        with patch('core.indexer_admin.admin_request',side_effect=api):
            result=test_indexer_restore('soc-20261013000000')
        self.assertEqual(result['native_restore'],'pospuesta')
        self.assertFalse(any(p.endswith('/_restore') for p in calls),'no restaura nada')


class JobInterruptionTests(TestCase):
    def test_sigterm_is_not_swallowed_by_connector_error_handling_and_is_recorded(self):
        from . import background_jobs
        from .interruption import JobInterrupted
        from .models import WorkerState
        def connector():
            try:
                raise JobInterrupted('parada')
            except Exception:  # lo que hacen los conectores con sus errores
                return 'siguió trabajando'
        with patch.object(background_jobs,'execute',side_effect=lambda name:connector()):
            with self.assertRaises(JobInterrupted):background_jobs.run_job('transport')
        state=WorkerState.objects.get(name='job:transport')
        self.assertEqual((state.details['running'],state.details['error_type']),(False,'JobInterrupted'))
        self.assertFalse(issubclass(JobInterrupted,(Exception,OSError)))

import hashlib
import importlib.util
import json
import tempfile
import time
import threading
import uuid
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.db import connection,connections,transaction
from django.db.models import F
from django.db.models.query import QuerySet
from django.test import TestCase,SimpleTestCase,TransactionTestCase,override_settings
from django.urls import reverse
from django.utils import timezone
from .models import Client,Site,Device,SecureLogReceipt,StaffAccess,WorkerState
from .security import decrypt,encrypt
from .secure_logs import prepare
from .log_delivery import deliver_due,recover_interrupted,retry_reviewed,cleanup
from .background_jobs import run_job,dispatch,reconcile_sources

@override_settings(SECURE_SSL_REDIRECT=False,SOC_MFA_REQUIRED=False)
class DurableInboxTests(TestCase):
    def setUp(self):
        self.owner=Client.objects.create(name='Owner',code='owner')
        self.device=Device.objects.create(name='Firewall',vendor='opnsense',site=Site.objects.create(client=self.owner,name='Office',code='office'))
        self.channel=prepare(self.device);self.channel.receiver_ready=True;self.channel.save()
        self.auth='Bearer '+decrypt(self.channel.encrypted_token)
    def submit(self,lines=None,batch=None):
        response=self.client.post(reverse('secure_log_ingest',args=[self.channel.pk]),
            json.dumps({'batch_id':batch or str(uuid.uuid4()),'messages':lines or ['one','two']}),
            content_type='application/json',secure=True,HTTP_AUTHORIZATION=self.auth)
        # These tests exercise the retained legacy UDP recovery contract.
        SecureLogReceipt.objects.update(transport_version=1)
        return response
    def sender(self):
        mock=patch('core.log_delivery.socket.socket');sock=mock.start();self.addCleanup(mock.stop)
        sender=sock.return_value.__enter__.return_value
        sender.sendto.side_effect=lambda data,dest:len(data)
        return sender
    def test_ack_is_after_encrypted_storage_without_network(self):
        sender=self.sender();response=self.submit();self.assertEqual(response.status_code,202)
        row=SecureLogReceipt.objects.get();reply=response.json()
        self.assertEqual(json.loads(decrypt(row.encrypted_payload)),['one','two'])
        self.assertTrue(reply['persisted']);self.assertFalse(reply['wazuh_verified'])
        self.assertEqual(reply['digest'],row.digest);self.assertEqual(reply['batch_id'],str(row.batch_id))
        self.assertEqual(row.status,'queued');sender.sendto.assert_not_called()
    def test_duplicate_after_forwarding_never_replays_and_has_same_receipt(self):
        sender=self.sender();batch=str(uuid.uuid4());self.submit(batch=batch)
        self.assertEqual(deliver_due(),1)
        self.assertTrue(self.submit(batch=batch).json()['duplicate']);self.assertEqual(deliver_due(),0)
        self.assertEqual(sender.sendto.call_count,2)
        row=SecureLogReceipt.objects.get();self.assertEqual(row.status,'forwarded');self.assertEqual(row.forwarded_count,2)
        sender.bind.assert_called_once_with((self.channel.source_identity,0))
    def test_local_failure_retries_only_the_unsent_suffix(self):
        sender=self.sender();self.submit()
        sender.sendto.side_effect=[3,OSError('private error must not persist')]
        now=timezone.now();self.assertEqual(deliver_due(now=now),0)
        row=SecureLogReceipt.objects.get();self.assertEqual(row.status,'retry');self.assertEqual(row.forwarded_count,1)
        self.assertNotIn('private error',row.error)
        self.assertEqual(deliver_due(now=now),0)
        sender.sendto.side_effect=lambda data,dest:len(data)
        self.assertEqual(deliver_due(now=now+timedelta(minutes=1)),1)
        self.assertEqual(sender.sendto.call_args.args[0],b'two')
    def test_crash_after_send_quarantines_and_requires_review(self):
        sender=self.sender();self.submit();original=QuerySet.update
        def interrupted(qs,**values):
            if qs.model is SecureLogReceipt and values.get('forwarded_count')==1:raise RuntimeError('crash after UDP')
            return original(qs,**values)
        with patch.object(QuerySet,'update',interrupted),self.assertRaises(RuntimeError):deliver_due()
        row=SecureLogReceipt.objects.get();self.assertEqual(row.inflight_index,0)
        recover_interrupted(timezone.now()+timedelta(minutes=6));row.refresh_from_db()
        self.assertEqual(row.status,'uncertain');self.assertEqual(deliver_due(),0)
        self.assertEqual(sender.sendto.call_count,1)
        self.assertTrue(retry_reviewed(self.channel,row.pk));self.assertEqual(deliver_due(),1)
    def test_exhausted_retries_are_not_discarded_or_looped(self):
        self.submit();row=SecureLogReceipt.objects.get();row.attempts=7;row.save()
        sender=self.sender();sender.bind.side_effect=OSError('unavailable')
        deliver_due();row.refresh_from_db();self.assertEqual(row.status,'failed')
        cleanup(timezone.now()+timedelta(days=100));self.assertTrue(SecureLogReceipt.objects.filter(pk=row.pk).exists())
        self.assertTrue(row.encrypted_payload);self.assertEqual(deliver_due(),0)
    def test_revoked_and_reassigned_channels_never_forward_saved_logs(self):
        self.submit();sender=self.sender();self.channel.enabled=False;self.channel.save()
        self.assertEqual(deliver_due(),0);sender.sendto.assert_not_called()
        self.channel.enabled=True;self.channel.save()
        other=Client.objects.create(name='Other',code='other');self.device.site.client=other;self.device.site.save()
        self.assertEqual(deliver_due(),0);sender.sendto.assert_not_called()
    def test_failed_channel_does_not_block_a_different_channel(self):
        self.submit();SecureLogReceipt.objects.update(status='uncertain')
        other=Device.objects.create(name='Other firewall',vendor='opnsense',site=self.device.site)
        channel=prepare(other);channel.receiver_ready=True;channel.save()
        self.channel=channel;self.auth='Bearer '+decrypt(channel.encrypted_token);self.submit()
        self.sender();self.assertEqual(deliver_due(limit=1),1)
    def test_payload_tampering_is_not_sent(self):
        self.submit();SecureLogReceipt.objects.update(encrypted_payload=encrypt('["modified"]'))
        sender=self.sender();self.assertEqual(deliver_due(),0);sender.sendto.assert_not_called()
        self.assertEqual(SecureLogReceipt.objects.get().status,'failed')
    def test_retention_keeps_pending_payload_and_old_dedup_tombstones(self):
        self.submit();row=SecureLogReceipt.objects.get();now=timezone.now()+timedelta(days=100)
        cleanup(now);row.refresh_from_db();self.assertTrue(row.encrypted_payload)
        row.status='forwarded';row.forwarded_at=timezone.now();row.save();cleanup(now)
        row.refresh_from_db();self.assertEqual(row.encrypted_payload,'')
        response=self.submit(batch=str(row.batch_id));self.assertTrue(response.json()['duplicate'])
        self.assertEqual(SecureLogReceipt.objects.count(),1)
    def test_legacy_receipt_is_retained_for_review_not_replayed(self):
        lines=['one'];batch=uuid.uuid4();digest=hashlib.sha256(json.dumps(lines,separators=(',',':')).encode()).hexdigest()
        row=SecureLogReceipt.objects.create(channel=self.channel,batch_id=batch,digest=digest,bytes_count=3,messages_count=1)
        self.assertTrue(self.submit(lines,batch=str(batch)).json()['persisted']);row.refresh_from_db()
        self.assertEqual(row.status,'uncertain');self.assertEqual(deliver_due(),0)
    def test_capacity_rejects_new_batch_but_preserves_pending_and_duplicate(self):
        batch=str(uuid.uuid4());self.submit(batch=batch)
        SecureLogReceipt.objects.update(bytes_count=64*1024*1024,received_at=timezone.now()-timedelta(minutes=2))
        self.assertEqual(self.submit().status_code,503)
        self.assertTrue(self.submit(batch=batch).json()['duplicate'])
        self.assertEqual(SecureLogReceipt.objects.count(),1)
    def test_review_requires_mfa_confirmation_and_scoped_device(self):
        user=get_user_model().objects.create_user('manager')
        StaffAccess.objects.create(user=user,role='manager',all_clients=True)
        user.user_permissions.add(Permission.objects.get(codename='manage_connections'))
        self.client.force_login(user);self.submit();row=SecureLogReceipt.objects.get();row.status='uncertain';row.save()
        url=reverse('secure_log_setup',args=[self.device.pk]);data={'action':'retry','receipt':row.pk,'confirm_replay':'yes'}
        self.assertEqual(self.client.post(url,data).status_code,302);row.refresh_from_db();self.assertEqual(row.status,'uncertain')
        session=self.client.session;session.update({'soc_mfa_user':user.pk,'soc_mfa_at':time.time()});session.save()
        self.client.post(url,{'action':'retry','receipt':row.pk});row.refresh_from_db();self.assertEqual(row.status,'uncertain')
        self.client.post(url,data);row.refresh_from_db();self.assertEqual(row.status,'queued')
        response=self.client.get(url);self.assertContains(response,'Estado de la entrega');self.assertNotContains(response,row.encrypted_payload)
        access=user.soc_access;access.all_clients=False;access.save()
        self.assertEqual(self.client.post(url,data).status_code,404)

class IndependentJobTests(TestCase):
    def test_local_reader_counts_invalid_json_and_resumes_an_oversized_line(self):
        from .operations import read_receipts
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'alerts.json'
            path.write_bytes(b'not json\n'+b'x'*(1024*1024+10)+b'\n{}\n')
            with patch('core.operations.ingest_events',return_value=0) as ingest:
                read_receipts(path,limit=2)
                state=WorkerState.objects.get(pk='receipts')
                self.assertEqual(state.details['invalid_json_total'],1)
                self.assertEqual(state.details['oversized_lines_total'],1)
                self.assertTrue(state.details['skipping_oversized'])
                read_receipts(path)
                state.refresh_from_db();self.assertFalse(state.details['skipping_oversized'])
                self.assertEqual(state.details['remaining_bytes'],0)
                self.assertEqual(ingest.call_args.args[0],[{}])
                self.assertEqual(state.details['oversized_lines_total'],1)
    def test_delivery_drains_multiple_batches_within_the_budget(self):
        # Independent transport can drain more than one batch/minute per source.
        owner=Client.objects.create(name='Owner',code='owner')
        device=Device.objects.create(name='Firewall',site=Site.objects.create(client=owner,name='Office',code='office'))
        channel=prepare(device);channel.receiver_ready=True;channel.save()
        content='["one"]';digest=hashlib.sha256(content.encode()).hexdigest()
        for _ in range(3):SecureLogReceipt.objects.create(channel=channel,batch_id=uuid.uuid4(),digest=digest,
            bytes_count=7,messages_count=1,status='queued',encrypted_payload=encrypt(content))
        with patch('core.log_delivery.socket.socket') as sock:
            sock.return_value.__enter__.return_value.sendto.return_value=3
            self.assertEqual(deliver_due(limit=2),2)
            self.assertEqual(SecureLogReceipt.objects.filter(status='queued').count(),1)
            self.assertEqual(deliver_due(max_seconds=0),0)
    def test_failed_job_preserves_metrics_and_other_job_can_succeed(self):
        with patch('core.background_jobs.execute',side_effect=RuntimeError('private response')):
            with self.assertRaises(RuntimeError):run_job('inventory')
        bad=WorkerState.objects.get(pk='job:inventory')
        self.assertEqual(bad.details['consecutive_failures'],1);self.assertIsNone(bad.last_success_at)
        self.assertNotIn('private response',bad.error)
        with patch('core.background_jobs.execute',return_value=4):run_job('receipts')
        good=WorkerState.objects.get(pk='job:receipts');self.assertIsNotNone(good.last_success_at)
        self.assertEqual(good.details['processed'],4)
    def test_dispatch_respects_retry_time_and_no_notify_including_invitations(self):
        WorkerState.objects.create(name='job:transport',details={'next_retry_at':(timezone.now()+timedelta(hours=1)).isoformat()})
        with patch('core.background_jobs.subprocess.run') as run:dispatch(no_notify=True)
        units=[c.args[0][-1] for c in run.call_args_list]
        self.assertNotIn('soc-job@transport.service',units)
        self.assertNotIn('soc-job@notifications.service',units);self.assertNotIn('soc-job@invitations.service',units)
        self.assertIn('soc-job@receipts.service',units)
    def test_unknown_job_is_rejected_without_creating_state(self):
        with self.assertRaises(ValueError):run_job('untrusted; command')
        self.assertFalse(WorkerState.objects.exists())
    def test_source_failure_does_not_block_other_cursor_or_reset_global_backlog(self):
        owner=Client.objects.create(name='Owner',code='owner');site=Site.objects.create(client=owner,name='Office',code='office')
        first=Device.objects.create(site=site,name='One');second=Device.objects.create(site=site,name='Two')
        start=(timezone.now()-timedelta(days=8)).isoformat();end=(timezone.now()-timedelta(days=5)).isoformat()
        WorkerState.objects.create(name='security-reconciliation',details={'start':start,'end':end,'sources':['8.8.8.8','9.9.9.9']})
        calls=[]
        def reconcile(**kwargs):
            name=kwargs.get('state_name','security-reconciliation');state=WorkerState.objects.get(pk=name)
            calls.append((name,dict(state.details),kwargs.get('selected_sources')))
            state.last_run_at=timezone.now();state.error='failed' if name.endswith(':'+str(first.pk)) else '';state.save();return 0
        with patch('core.operations.source_map',return_value=({'8.8.8.8':first,'9.9.9.9':second},{})),patch('core.operations.reconcile_security',side_effect=reconcile):
            with self.assertRaises(RuntimeError):reconcile_sources()
        self.assertEqual(len(calls),3)
        self.assertEqual(calls[0][1]['completed_until'],start);self.assertEqual(calls[1][1]['completed_until'],start)
        self.assertEqual(calls[0][2],['8.8.8.8']);self.assertEqual(calls[1][2],['9.9.9.9'])

class RelayAcknowledgementTests(SimpleTestCase):
    def setUp(self):
        path=Path(__file__).resolve().parent.parent/'deploy/relay/soc_log_relay.py'
        spec=importlib.util.spec_from_file_location('soc_relay',path);self.relay=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.relay)
    def test_old_or_mismatched_ack_never_deletes_a_local_batch(self):
        lines=['a','á'];batch=str(uuid.uuid4());digest=hashlib.sha256(json.dumps(lines,ensure_ascii=False,separators=(',',':')).encode()).hexdigest()
        ack={'accepted':2,'persisted':True,'batch_id':batch,'digest':digest}
        self.assertTrue(self.relay.durable_ack(202,ack,batch,lines))
        self.assertFalse(self.relay.durable_ack(202,{'accepted':2},batch,lines))
        for key,value in [('digest','wrong'),('batch_id',str(uuid.uuid4())),('persisted',False),('accepted',1)]:
            self.assertFalse(self.relay.durable_ack(202,{**ack,key:value},batch,lines))
    def test_local_counters_and_queue_age_survive_restart_without_payload_disclosure(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'spool.sqlite3'
            with self.relay.database(path) as db:
                db.execute('CREATE TABLE counters (name TEXT PRIMARY KEY,value INTEGER NOT NULL)')
                db.execute('CREATE TABLE spool (id TEXT,content TEXT,created REAL)')
                db.execute('CREATE TABLE batches (id TEXT,content TEXT,created REAL)')
                db.execute('INSERT INTO spool VALUES (?,?,?)',('id','private event',time.time()-3*86400))
                self.relay.counter(db,'overflow_dropped',2)
            result=self.relay.spool_status(path)
            self.assertEqual(result['overflow_dropped'],2);self.assertEqual(result['pending_messages'],1)
            self.assertGreater(result['oldest_pending_seconds'],2*86400);self.assertNotIn('private event',str(result))

class FileDatabaseConcurrencyTests(TransactionTestCase):
    def test_local_reader_reserves_writer_before_reading_ownership(self):
        from .operations import read_receipts
        if connection.vendor!='sqlite' or 'memory' in str(connection.settings_dict['NAME']):
            self.skipTest('Requires an isolated file SQLite database; run the concurrency gate.')
        WorkerState.objects.create(name='receipts');WorkerState.objects.create(name='load-check')
        entered=threading.Event();errors=[]
        def writer():
            try:
                if not entered.wait(3):raise RuntimeError('Reader did not enter')
                with transaction.atomic():WorkerState.objects.filter(pk='load-check').update(offset=F('offset')+1)
            except Exception as exc:errors.append(type(exc).__name__)
            finally:connections.close_all()
        def ingest(events):
            WorkerState.objects.get(pk='load-check')
            entered.set();time.sleep(.2)
            WorkerState.objects.filter(pk='load-check').update(offset=F('offset')+1)
            return 0
        thread=threading.Thread(target=writer);thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                path=Path(directory)/'alerts.json';path.write_bytes(b'{}\n')
                with patch('core.operations.ingest_events',side_effect=ingest):read_receipts(path)
        finally:thread.join(timeout=5)
        self.assertFalse(thread.is_alive());self.assertEqual(errors,[])
        self.assertEqual(WorkerState.objects.get(pk='load-check').offset,2)

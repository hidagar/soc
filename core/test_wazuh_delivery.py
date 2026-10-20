import hashlib,json,tempfile,uuid
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch
from django.test import TestCase,override_settings
from django.utils import timezone
from django.urls import reverse
from .models import Client,Site,Device,SecureLogReceipt,SecureLogMessage,SecurityEvidence,DeviceFeed,Incident,WorkerState
from .security import encrypt,decrypt
from .secure_logs import prepare
from .wazuh_delivery import (prepare_messages,reframe,hostname,identify,canonical,_record_ack,
    send_due,read_native_receipts,publish_due,finish_batches,prune_logs)

@override_settings(SECURE_SSL_REDIRECT=False,SOC_MFA_REQUIRED=False)
class AcknowledgedDeliveryTests(TestCase):
    def setUp(self):
        unix=patch('core.wazuh_delivery.socket.AF_UNIX',1,create=True);unix.start();self.addCleanup(unix.stop)
        self.owner=Client.objects.create(name='A',code='a')
        self.device=Device.objects.create(name='Firewall',vendor='opnsense',site=Site.objects.create(client=self.owner,name='Office',code='office'))
        self.channel=prepare(self.device);self.channel.receiver_ready=True;self.channel.save()
        self.lines=['{"timestamp":"2026-10-20T12:00:00Z","event_type":"alert"}']
        payload=json.dumps(self.lines,ensure_ascii=False,separators=(',',':'))
        self.receipt=SecureLogReceipt.objects.create(channel=self.channel,batch_id=uuid.uuid4(),
            digest=hashlib.sha256(payload.encode()).hexdigest(),messages_count=1,bytes_count=len(payload),
            encrypted_payload=encrypt(payload),transport_version=2,status='queued')
        prepare_messages(self.receipt);self.message=self.receipt.delivery_messages.get()
    def native(self,level=8):
        return {'id':'native-runtime-id','timestamp':timezone.now().isoformat(),'location':self.channel.source_identity,
            'predecoder':{'hostname':hostname(self.receipt,self.message.uid)},
            'full_log':reframe(self.lines[0],self.receipt,self.message.uid),'decoder':{'name':'json'},
            'rule':{'id':'86601','level':level,'description':'Native laboratory alert','groups':['ids','suricata']},
            'data':{'event_type':'alert','src_ip':'203.0.113.9','dest_ip':'10.0.0.20','dest_port':443,
                'alert':{'action':'allowed','category':'Malware','signature':'Laboratory fixture'}}}
    def test_new_http_receipt_uses_acknowledged_transport(self):
        response=self.client.post(reverse('secure_log_ingest',args=[self.channel.pk]),json.dumps({'batch_id':str(uuid.uuid4()),'messages':['ordinary activity']}),
            content_type='application/json',secure=True,HTTP_AUTHORIZATION='Bearer '+decrypt(self.channel.encrypted_token))
        self.assertEqual(response.status_code,202);self.assertFalse(response.json()['wazuh_processed'])
        self.assertEqual(SecureLogReceipt.objects.order_by('-pk').first().transport_version,2)
    def test_frame_and_identity_survive_recreation_and_timestamp_delay(self):
        original=reframe(self.lines[0],self.receipt,self.message.uid)
        prepare_messages(self.receipt);self.assertEqual(self.receipt.delivery_messages.count(),1)
        self.assertEqual(original,reframe(self.lines[0],self.receipt,self.message.uid))
        self.assertIn('soc-json:',original)
        event=canonical(self.native(),self.message)
        self.assertEqual(event['id'],'soc-relay-'+self.message.uid)
        self.assertEqual(event['timestamp'],self.receipt.received_at.isoformat())
    def test_program_and_body_preserved_for_rfc3164_and_iso(self):
        for line,suffix in [('Oct 20 12:00:00 original CEF:0|vendor|log','CEF:0|vendor|log'),
            ('2026-10-20T12:00:00Z original zenarmor: daemon=zenarmor, data={}','zenarmor: daemon=zenarmor, data={}')]:
            self.assertTrue(reframe(line,self.receipt,self.message.uid).endswith(suffix))
    def test_wrong_source_frame_or_hostname_cannot_confirm_another_message(self):
        source=self.native();self.assertEqual(identify(source).pk,self.message.pk)
        for key,value in [('location','127.80.0.9'),('full_log','different')]:
            self.assertIsNone(identify({**source,key:value}))
        self.assertIsNone(identify({**source,'predecoder':{'hostname':'sr.invalid'}}))
    def test_unix_send_never_marks_message_processed_or_batch_complete(self):
        with patch('core.wazuh_delivery.socket.socket') as sock:
            sock.return_value.__enter__.return_value.send.side_effect=lambda data:len(data)
            self.assertEqual(send_due(),1)
        self.message.refresh_from_db();self.assertEqual(self.message.status,'awaiting');self.assertIsNone(self.message.processed_at)
        self.assertEqual(finish_batches(),0)
        self.receipt.refresh_from_db();self.assertNotEqual(self.receipt.status,'confirmed')
    def test_socket_error_and_crash_retry_preserve_message_id(self):
        with patch('core.wazuh_delivery.socket.socket',side_effect=OSError):self.assertEqual(send_due(),0)
        self.message.refresh_from_db();self.assertEqual(self.message.attempts,1);self.assertIsNone(self.message.processed_at)
        uid=self.message.uid
        with patch('core.wazuh_delivery.socket.socket') as sock:
            sock.return_value.__enter__.return_value.send.side_effect=lambda data:len(data)
            self.assertEqual(send_due(now=timezone.now()+timedelta(minutes=1)),1)
        self.assertEqual(self.receipt.delivery_messages.get().pk,uid)
    def test_no_alert_has_native_receipt_without_fake_security_evidence(self):
        source=self.native();source.pop('rule');source['decoder']={}
        self.assertTrue(_record_ack(source,timezone.now()));self.assertEqual(finish_batches(),1)
        self.receipt.refresh_from_db();self.assertEqual(self.receipt.status,'confirmed')
        self.assertFalse(SecurityEvidence.objects.exists());self.assertFalse(Incident.objects.exists())
        self.message.refresh_from_db();self.assertEqual(self.message.encrypted_event,'')
    def test_first_native_result_is_frozen_when_duplicate_changes_classification(self):
        _record_ack(self.native(),timezone.now());first=SecureLogMessage.objects.get().encrypted_event
        _record_ack(self.native(level=12),timezone.now())
        self.message.refresh_from_db();self.assertEqual(self.message.encrypted_event,first)
        self.assertEqual(self.message.rule_level,8)
    def test_archive_cursor_and_fsync_before_confirmation_survive_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'archives.json';path.write_text(json.dumps(self.native())+'\n',encoding='utf-8')
            seen=[]
            def fsync(fd):seen.append(SecureLogMessage.objects.get().processed_at)
            with patch('core.wazuh_delivery.os.fsync',side_effect=fsync):
                self.assertEqual(read_native_receipts([path]),1)
                self.assertEqual(read_native_receipts([path]),0)
            self.assertEqual(seen,[None]);self.message.refresh_from_db();self.assertIsNotNone(self.message.processed_at)
    def test_partial_archive_never_advances_past_the_incomplete_record(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'archives.json';line=json.dumps(self.native())
            path.write_text(line[:30],encoding='utf-8')
            self.assertEqual(read_native_receipts([path]),0);self.assertEqual(WorkerState.objects.filter(name__startswith='https-archive:').get().offset,0)
            path.write_text(line+'\n',encoding='utf-8')
            with patch('core.wazuh_delivery.os.fsync'):self.assertEqual(read_native_receipts([path]),1)
    def publish(self,create_status=True,stored=None):
        source=canonical(self.native(),self.message) if stored is None else stored
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'etc').mkdir();(root/'etc/soc-delivery.json').write_text('{"pipeline":"native-pipeline"}')
            with patch('core.wazuh_delivery.ENGINE_ROOT',root),patch('core.wazuh_delivery.native_bulk',return_value=[create_status]) as bulk,patch(
                'core.indexer_admin.admin_request',return_value={'docs':[{'found':True,'_id':'soc-relay-'+self.message.uid,'_source':source}]}):
                return publish_due(),bulk
    def test_real_native_alert_is_published_and_evidence_projected_once(self):
        _record_ack(self.native(),timezone.now())
        self.assertEqual(self.publish()[0],1);self.assertEqual(self.publish()[0],0)
        self.assertEqual(SecurityEvidence.objects.count(),1);self.assertEqual(Incident.objects.count(),1)
        self.assertEqual(DeviceFeed.objects.get().event_count,1)
        self.assertEqual(SecurityEvidence.objects.get().wazuh_id,'soc-relay-'+self.message.uid)
        self.assertEqual(finish_batches(),1)
    def test_create_conflict_after_crash_is_verified_without_duplicate_evidence(self):
        _record_ack(self.native(),timezone.now());self.publish()
        SecureLogMessage.objects.filter(pk=self.message.pk).update(indexed_at=None)
        self.assertEqual(self.publish()[0],1)
        self.assertEqual(SecurityEvidence.objects.count(),1);self.assertEqual(DeviceFeed.objects.get().event_count,1)
    def test_indexer_partial_failure_keeps_native_event_and_batch_pending(self):
        _record_ack(self.native(),timezone.now())
        self.assertEqual(self.publish(create_status=False)[0],0)
        self.message.refresh_from_db();self.assertIsNone(self.message.indexed_at);self.assertTrue(self.message.encrypted_event)
        self.assertEqual(finish_batches(),0)
    def test_indexed_body_mismatch_is_not_acknowledged_or_projected(self):
        _record_ack(self.native(),timezone.now());wrong=canonical(self.native(),self.message);wrong['data']['alert']['action']='blocked'
        self.assertEqual(self.publish(stored=wrong)[0],0)
        self.assertFalse(SecurityEvidence.objects.exists());self.message.refresh_from_db();self.assertIsNone(self.message.indexed_at)
    def test_reassignment_preserves_pending_payload_without_publishing_to_new_owner(self):
        _record_ack(self.native(),timezone.now())
        other=Client.objects.create(name='B',code='b');self.device.site.client=other;self.device.site.save()
        result,bulk=self.publish();self.assertEqual(result,0);bulk.assert_not_called()
        self.receipt.refresh_from_db();self.assertEqual(self.receipt.status,'failed');self.assertTrue(self.receipt.encrypted_payload)
    def test_forged_archive_is_not_a_processing_receipt(self):
        bad=self.native();bad['full_log']+=' altered'
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'archives.json';path.write_text(json.dumps(bad)+'\n',encoding='utf-8')
            with patch('core.wazuh_delivery.os.fsync'):self.assertEqual(read_native_receipts([path]),0)
        self.message.refresh_from_db();self.assertIsNone(self.message.processed_at)
    def test_publish_failure_backs_off_without_losing_native_result(self):
        _record_ack(self.native(),timezone.now())
        self.publish(create_status=False)
        result,bulk=self.publish();self.assertEqual(result,0);bulk.assert_not_called()
        self.message.refresh_from_db();self.assertTrue(self.message.error);self.assertTrue(self.message.encrypted_event)
    def test_no_alert_reassigned_batch_is_held_for_scope_review(self):
        _record_ack(self.native(level=0),timezone.now())
        other=Client.objects.create(name='B',code='b');self.device.site.client=other;self.device.site.save()
        self.assertEqual(finish_batches(),0)
        self.receipt.refresh_from_db();self.assertEqual(self.receipt.status,'failed')
    def test_database_failure_during_preparation_is_not_reported_as_corruption(self):
        from django.db import OperationalError
        with patch('core.wazuh_delivery.prepare_messages',side_effect=OperationalError('busy')):
            with self.assertRaises(OperationalError):send_due()
        self.receipt.refresh_from_db();self.assertEqual(self.receipt.status,'queued')
    def test_private_pipeline_accepts_precise_time_and_does_not_drop_errors(self):
        from .wazuh_delivery import provision_pipeline
        original={'processors':[{'date_index_name':{'field':'timestamp'}}],'on_failure':[{'drop':{}}]}
        with patch('core.indexer_admin.admin_request',side_effect=[{'native-wazuh-alerts-pipeline':original},{}]) as request:
            self.assertEqual(provision_pipeline(),'soc-https-wazuh-v1')
        copied=request.call_args.args[1]
        self.assertNotIn('on_failure',copied)
        self.assertEqual(copied['processors'][0]['date_index_name']['date_formats'],['ISO8601'])
        self.assertIn('on_failure',original)
    def test_reused_archive_inode_cannot_skip_a_new_generation_at_the_same_size(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'archives.json'
            original=self.native();original['full_log']+=' altered'
            # Pad the valid line to the same physical length as the invalid one.
            bad=json.dumps(original)+'\n';good=json.dumps(self.native())+' '*8+'\n'
            self.assertEqual(len(bad),len(good))
            path.write_text(bad,encoding='utf-8')
            with patch('core.wazuh_delivery.os.fsync'):self.assertEqual(read_native_receipts([path]),0)
            path.write_text(good,encoding='utf-8')
            with patch('core.wazuh_delivery.os.fsync'):self.assertEqual(read_native_receipts([path]),1)

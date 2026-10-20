"""Opt-in real native/indexer gate: isolated database, engine and unique index.

Never run against production Django data. Requires Linux root/mTLS and the
prepared /var/lib/soc-wazuh-https-lab tree. Scratch indexes are deleted by exact
generated names, without wildcards. No test events enter production indexes.
"""
import json,os,socket,subprocess,time,uuid
from pathlib import Path
from unittest import skipUnless
from unittest.mock import patch
from django.test import TransactionTestCase,override_settings
from django.urls import reverse
from django.utils import timezone
from .models import Client,Site,Device,SecureLogMessage,SecureLogReceipt,SecurityEvidence,DeviceFeed
from .secure_logs import prepare
from .security import decrypt
from . import wazuh_delivery as delivery
from .indexer_admin import admin_request

@skipUnless(os.environ.get('SOC_NATIVE_ENGINE_GATE')=='1','Explicit isolated Linux gate only')
@override_settings(SECURE_SSL_REDIRECT=False,SOC_MFA_REQUIRED=False)
class NativePipelineGate(TransactionTestCase):
    def test_native_delivery_restarts_replay_index_failure_and_load(self):
        rootfs=Path('/var/lib/soc-wazuh-https-lab');root=rootfs/'var/ossec'
        prefix='soc-delivery-lab-'+uuid.uuid4().hex+'-';indexes=set();processes=[]
        pipeline=delivery.provision_pipeline('soc-https-lab-'+uuid.uuid4().hex)
        template=admin_request('/_template/wazuh')['wazuh']
        template={**template,'index_patterns':[prefix+'*']}
        admin_request('/_template/'+prefix+'template',template,method='PUT')
        manifest=root/'etc/soc-delivery.json';config=json.loads(manifest.read_text());config['pipeline']=pipeline;manifest.write_text(json.dumps(config))
        owner=Client.objects.create(name='Isolated laboratory',code='isolated')
        device=Device.objects.create(name='Isolated fixtures',vendor='opnsense',site=Site.objects.create(client=owner,name='Lab',code='lab'))
        channel=prepare(device);channel.receiver_ready=True;channel.save()
        fixtures=[
            'Oct 20 12:00:00 lab CEF:0|Ubiquiti|UniFi Network|1|test|Threat Detected and Blocked|5|UNIFIcategory=Security act=blocked src=203.0.113.9 dst=10.0.0.20 dpt=443 UNIFIipsSignature=Lab sample UNIFIrisk=medium',
            json.dumps({'timestamp':'2026-10-20T12:00:00+0000','event_type':'alert','src_ip':'203.0.113.9','dest_ip':'10.0.0.20','dest_port':443,'alert':{'signature':'Laboratory sample','category':'Malware','action':'allowed','severity':2}}),
            'Oct 20 12:00:00 lab zenarmor: daemon=zenarmor, index=alerts, data='+json.dumps({'ip_src_saddr':'10.0.0.20','ip_dst_saddr':'203.0.113.9','ip_dst_port':443,'security_tags':['Malware'],'is_blocked':1}),
            'Oct 20 12:00:00 lab HillstoneNetworks#Threat@FLOW: FROM 203.0.113.9:61009(ethernet0/0) to 10.20.0.8:8082(-), threat name:IP-Reputation, threat type:Attack, threat subtype:Risk IP, App/Protocol:, action:Log-Only, defender:PTF, severity:High, reason:hit ip-reputation category Bot, hit-count:1(in the last 60 seconds)'
        ]
        lines=fixtures+[f'ordinary laboratory activity {n}' for n in range(256)]
        def submit(batch):
            return self.client.post(reverse('secure_log_ingest',args=[channel.pk]),json.dumps(batch),content_type='application/json',secure=True,HTTP_AUTHORIZATION='Bearer '+decrypt(channel.encrypted_token))
        started=time.monotonic()
        for offset in range(0,len(lines),32):
            batch={'batch_id':str(uuid.uuid4()),'messages':lines[offset:offset+32]}
            self.assertEqual(submit(batch).status_code,202)
            # Lost HTTP ACK and retry cannot create a second durable batch.
            self.assertEqual(submit(batch).status_code,202)
        self.assertEqual(SecureLogReceipt.objects.count(),9)
        def start_engine():
            console=(root/'gate-console.log').open('ab')
            db=subprocess.Popen(['/usr/bin/chroot',str(rootfs),'/var/ossec/bin/wazuh-db','-f'],stdout=console,stderr=console,env={**os.environ,'LD_LIBRARY_PATH':'/var/ossec/lib'})
            engine=subprocess.Popen(['/var/ossec/bin/wazuh-analysisd','-f','-D',str(root),'-c','etc/ossec.conf'],stdout=console,stderr=console,env={**os.environ,'TZ':'UTC'})
            processes.extend([engine,db]);console.close();deadline=time.monotonic()+20
            while time.monotonic()<deadline:
                self.assertIsNone(engine.poll());self.assertIsNone(db.poll())
                try:
                    with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as probe:probe.connect(str(root/'queue/sockets/queue'))
                    return
                except (ConnectionRefusedError,FileNotFoundError):time.sleep(.1)
            self.fail('Private native engine did not start')
        def stop_engine():
            for process in processes:
                if process.poll() is None:
                    process.terminate()
                    try:process.wait(timeout=8)
                    except subprocess.TimeoutExpired:process.kill();process.wait()
            processes.clear()
        try:
            with patch.object(delivery,'ENGINE_ROOT',root),patch.object(delivery,'SOCKET',root/'queue/sockets/queue'),patch.object(delivery,'ARCHIVES',root/'logs/archives'),patch.object(delivery,'INDEX_PREFIX',prefix):
                self.assertEqual(delivery.send_due(limit=1024),0) # native engine offline
                self.assertEqual(SecureLogMessage.objects.count(),260)
                self.assertFalse(SecureLogMessage.objects.exclude(processed_at=None).exists())
                start_engine();SecureLogMessage.objects.update(next_attempt_at=None)
                self.assertEqual(delivery.send_due(limit=1024),260)
                deadline=time.monotonic()+30
                while time.monotonic()<deadline:
                    delivery.read_native_receipts()
                    if SecureLogMessage.objects.filter(processed_at=None).count()==0:break
                    time.sleep(.2)
                self.assertEqual(SecureLogMessage.objects.filter(processed_at=None).count(),0)
                self.assertEqual(SecureLogMessage.objects.filter(rule_level__gte=3).count(),4)
                self.assertEqual(delivery.publish_due.__name__,'publish_due')
                with patch.object(delivery,'native_bulk',side_effect=OSError('Isolated outage')):
                    with self.assertRaises(OSError):delivery.publish_due()
                self.assertFalse(SecurityEvidence.objects.exists())
                SecureLogMessage.objects.update(next_attempt_at=None)
                indexes.add(prefix+timezone.now().strftime('%Y.%m.%d'))
                self.assertEqual(delivery.publish_due(),4)
                self.assertEqual(SecurityEvidence.objects.count(),4)
                counts=list(DeviceFeed.objects.filter(device=device).order_by('pk').values_list('pk','event_count'))
                stop_engine();start_engine()
                # Replayed native frame and lost SQL acknowledgement after index create.
                first=SecureLogMessage.objects.filter(rule_level__gte=3).first()
                frame=delivery.reframe(fixtures[first.position],first.receipt,first.uid)
                with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as sender:
                    sender.connect(str(root/'queue/sockets/queue'));sender.send(f'1:{channel.source_identity}:{frame}'.encode())
                SecureLogMessage.objects.filter(rule_level__gte=3).update(indexed_at=None,next_attempt_at=None)
                self.assertEqual(delivery.publish_due(),4)
                self.assertEqual(SecurityEvidence.objects.count(),4)
                self.assertEqual(list(DeviceFeed.objects.filter(device=device).order_by('pk').values_list('pk','event_count')),counts)
                self.assertEqual(delivery.finish_batches(),9)
                for index in indexes:
                    self.assertEqual(admin_request('/'+index+'/_count')['count'],4)
                print('NATIVE_GATE_RESULT',json.dumps({'messages':260,'native_alerts':4,'batches':9,'evidence':4,'seconds':round(time.monotonic()-started,2),'restarts':1,'production_indexes_written':False}))
        finally:
            stop_engine()
            for index in indexes:
                assert index.startswith(prefix) and '*' not in index
                try:admin_request('/'+index,method='DELETE')
                except Exception as exc:
                    if getattr(exc,'code',None)!=404:print('SCRATCH_CLEANUP_REQUIRED',index)
            admin_request('/_ingest/pipeline/'+pipeline,method='DELETE')
            admin_request('/_template/'+prefix+'template',method='DELETE')

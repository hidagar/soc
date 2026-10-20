import gzip,sys,tempfile,types
from datetime import timedelta
from pathlib import Path
from unittest.mock import MagicMock,patch
from django.test import TestCase
from django.utils import timezone
from .asn import lookup,values,update_database
from .models import WorkerState

class AsnTests(TestCase):
    def reader(self,age=0,row=None):
        reader=MagicMock()
        reader.metadata.return_value.build_epoch=int((timezone.now()-timedelta(days=age)).timestamp())
        reader.metadata.return_value.database_type='DBIP-ASN-Lite'
        reader.get.return_value=row or {'autonomous_system_number':15169,'autonomous_system_organization':'Google LLC'}
        opener=MagicMock();opener.return_value.__enter__.return_value=reader
        return reader,types.SimpleNamespace(open_database=opener)
    def test_public_ipv4_ipv6_local_reader_and_private_not_looked_up(self):
        reader,module=self.reader()
        with patch.dict(sys.modules,{'maxminddb':module}),patch('urllib.request.urlopen',side_effect=AssertionError('No lookup network allowed')):
            self.assertEqual(lookup('8.8.8.8')['label'],'AS15169')
            self.assertEqual(lookup('2001:4860:4860::8888')['organization'],'Google LLC')
            for ip in ('10.0.0.1','127.0.0.1','fe80::1','not-an-ip'):
                self.assertIn(lookup(ip)['status'],('private','invalid'))
        self.assertEqual(reader.get.call_count,2)
    def test_wrong_schema_unavailable_stale_and_future_are_explicit(self):
        self.assertIsNone(values({'autonomous_system_number':True}))
        self.assertIsNone(values({'autonomous_system_number':'15169'}))
        self.assertIsNone(values({'autonomous_system_number':0}))
        self.assertIsNone(values({'country':{'iso_code':'US'}}))
        _,module=self.reader(age=63)
        with patch.dict(sys.modules,{'maxminddb':module}):self.assertTrue(lookup('8.8.8.8')['stale'])
        _,module=self.reader(age=-3)
        with patch.dict(sys.modules,{'maxminddb':module}):self.assertEqual(lookup('8.8.8.8')['status'],'unavailable')
        module.open_database.side_effect=OSError('missing')
        with patch.dict(sys.modules,{'maxminddb':module}):self.assertEqual(lookup('8.8.8.8')['status'],'unavailable')
    def test_atomic_download_uses_public_bulk_url_and_is_daily_throttled(self):
        reader,module=self.reader()
        response=MagicMock();response.__enter__.return_value.read.return_value=gzip.compress(b'test-mmdb')
        with tempfile.TemporaryDirectory() as directory,patch.dict('os.environ',{'SOC_ASN_DATABASE':str(Path(directory)/'asn.mmdb')}),patch.dict(sys.modules,{'maxminddb':module}),patch('urllib.request.urlopen',return_value=response) as download:
            self.assertTrue(update_database())
            self.assertEqual((Path(directory)/'asn.mmdb').read_bytes(),b'test-mmdb')
            self.assertIn('/free/dbip-asn-lite-',download.call_args.args[0].full_url)
            self.assertNotIn('8.8.8.8',download.call_args.args[0].full_url)
            self.assertFalse(update_database());download.assert_called_once()
            self.assertEqual(len(list(Path(directory).iterdir())),1)
        self.assertEqual(WorkerState.objects.get(name='asn-database').error,'')
    def test_download_failure_or_wrong_dataset_preserves_previous_file(self):
        _,module=self.reader(age=63)
        response=MagicMock();response.__enter__.return_value.read.return_value=gzip.compress(b'invalid-new')
        with tempfile.TemporaryDirectory() as directory,patch.dict('os.environ',{'SOC_ASN_DATABASE':str(Path(directory)/'asn.mmdb')}),patch.dict(sys.modules,{'maxminddb':module}),patch('urllib.request.urlopen',return_value=response):
            path=Path(directory)/'asn.mmdb';path.write_bytes(b'previous-good')
            self.assertFalse(update_database())
            self.assertEqual(path.read_bytes(),b'previous-good')
            self.assertEqual(len(list(Path(directory).iterdir())),1)
        self.assertTrue(WorkerState.objects.get(name='asn-database').error)
    def test_invalid_gzip_and_size_limit_preserve_previous_file(self):
        _,module=self.reader(age=63)
        response=MagicMock();response.__enter__.return_value.read.return_value=b'not-gzip'
        with tempfile.TemporaryDirectory() as directory,patch.dict('os.environ',{'SOC_ASN_DATABASE':str(Path(directory)/'asn.mmdb')}),patch.dict(sys.modules,{'maxminddb':module}),patch('urllib.request.urlopen',return_value=response):
            path=Path(directory)/'asn.mmdb';path.write_bytes(b'previous-good')
            self.assertFalse(update_database());self.assertEqual(path.read_bytes(),b'previous-good')
            WorkerState.objects.filter(name='asn-database').update(last_run_at=None)
            with patch('core.asn.MAX_COMPRESSED',1):self.assertFalse(update_database())
            self.assertEqual(path.read_bytes(),b'previous-good')

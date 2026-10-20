import json
from unittest.mock import patch
from django.test import SimpleTestCase
from .exposure_ssh import read_legacy,SCRIPT

class ExposureSshTests(SimpleTestCase):
    def data(self):return {'status':'ok','filter':[],'nat':[],'aliases':[],'interfaces':[]}
    def test_reader_is_fixed_readonly_root_and_preserves_pinning(self):
        with patch('core.exposure_ssh.run_command',return_value=(0,json.dumps(self.data()),'')) as run:
            data,aliases=read_legacy(object())
            self.assertEqual(aliases,{})
            self.assertEqual(run.call_args.args[1],'/usr/local/bin/php -f /dev/stdin')
            self.assertEqual(run.call_args.kwargs['stdin_data'],SCRIPT.encode())
        for forbidden in ('file_put_contents','serializeToConfig','->save(', 'exec(', 'system(', 'shell_exec'):
            self.assertNotIn(forbidden,SCRIPT)
    def test_nonroot_requires_existing_noninteractive_sudo(self):
        with patch('core.exposure_ssh.run_command',side_effect=[(1,'{"status":"error","reason":"permissions"}',''),(1,'','')]) as run:
            with self.assertRaises(ValueError):read_legacy(object())
            self.assertEqual(run.call_count,2)
        with patch('core.exposure_ssh.run_command',side_effect=[(1,'{"status":"error","reason":"permissions"}',''),(0,json.dumps(self.data()),'')]) as run:
            read_legacy(object());self.assertEqual(run.call_args.args[1],'sudo -n /usr/local/bin/php -f /dev/stdin')
    def test_failure_partial_and_oversized_outputs_rejected(self):
        for output in ('invalid',json.dumps({'status':'error'}),json.dumps({**self.data(),'nat':[{}]*201}),json.dumps({**self.data(),'filter':'bad'})):
            with patch('core.exposure_ssh.run_command',return_value=(0,output,'')):
                with self.assertRaises(ValueError):read_legacy(object())

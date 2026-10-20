#!/usr/bin/env python3
"""Create a private native analysisd tree, never copy production keys or state."""
import argparse,hashlib,json,os,pwd,grp,re,shutil,subprocess,socket
from pathlib import Path
from xml.etree import ElementTree as ET

def prepare(root,pipeline=''):
    rootfs=Path(root).resolve();root=rootfs/'var/ossec'
    if (root/'queue/sockets/queue').exists():
        try:
            with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as probe:probe.connect(str(root/'queue/sockets/queue'))
        except (ConnectionRefusedError,FileNotFoundError):pass
        else:raise RuntimeError('Stop the isolated engine before replacing its profile.')
    root.mkdir(parents=True,exist_ok=True);os.chmod(root,0o750)
    uid=pwd.getpwnam('wazuh').pw_uid;gid=grp.getgrnam('wazuh').gr_gid
    os.chmod(rootfs,0o750);os.chown(rootfs,0,gid)
    os.chown(root,0,gid)
    # wazuh-db has no -D option. Supply a tiny private root filesystem so its
    # compiled /var/ossec path points to this tree, never the main manager DB.
    executable=Path('/var/ossec/bin/wazuh-db')
    libraries=subprocess.run(['ldd',str(executable)],env={**os.environ,'LD_LIBRARY_PATH':'/var/ossec/lib'},capture_output=True,text=True,check=True).stdout
    for source in [executable,*[Path(p) for p in re.findall(r'(/[^\s()]+)',libraries)]]:
        destination=rootfs/str(source).lstrip('/');destination.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(source,destination);os.chmod(destination,0o755)
    (rootfs/'etc').mkdir(exist_ok=True)
    for name in ('passwd','group'):
        records=Path('/etc',name).read_text().splitlines()
        (rootfs/'etc'/name).write_text('\n'.join(r for r in records if r.split(':')[0] in ('root','wazuh','nobody','nogroup'))+'\n')
    (rootfs/'etc/nsswitch.conf').write_text('passwd: files\ngroup: files\nhosts: files\n')
    (rootfs/'dev').mkdir(exist_ok=True)
    if not (rootfs/'dev/null').exists():os.mknod(rootfs/'dev/null',0o20666,os.makedev(1,3))
    for name in ('ruleset','etc/decoders','etc/rules','etc/lists'):
        source=Path('/var/ossec')/name;dest=root/name
        if source.exists():shutil.copytree(source,dest,dirs_exist_ok=True)
    for name in ('internal_options.conf','local_internal_options.conf'):
        source=Path('/var/ossec/etc')/name
        if source.exists():shutil.copy2(source,root/'etc'/name)
    shutil.copy2(Path(__file__).with_name('soc_https_json_decoder.xml'),root/'etc/decoders/soc_https_json_decoder.xml')
    (root/'etc/shared').mkdir(parents=True,exist_ok=True)
    (root/'etc/shared/ar.conf').write_text('')
    (root/'etc/client.keys').write_text('')
    # Limit this instance's threads and disable testing/network-facing services.
    with (root/'etc/local_internal_options.conf').open('a') as stream:
        stream.write('\nanalysisd.event_threads=1\nanalysisd.rule_matching_threads=1\nanalysisd.min_rotate_interval=600\n')
    for directory in ('ruleset','etc'):
        for path in [root/directory,*((root/directory).rglob('*'))]:
            os.chown(path,0,gid);os.chmod(path,0o750 if path.is_dir() else 0o640)
    for name in ('backup/db','queue/sockets','queue/fts','queue/alerts','queue/diff','queue/db','queue/ossec','logs/alerts','logs/archives','logs/firewall','logs/fts','var/run','var/db','var/multigroups','stats'):
        directory=root/name;directory.mkdir(parents=True,exist_ok=True)
        os.chown(directory,uid,gid);os.chmod(directory,0o750)
    config=ET.Element('ossec_config');glob=ET.SubElement(config,'global')
    for key,value in (('jsonout_output','yes'),('alerts_log','yes'),('logall','no'),('logall_json','yes'),('email_notification','no'),('rotate_interval','10m'),('max_output_size','64M')):
        ET.SubElement(glob,key).text=value
    alert=ET.SubElement(config,'alerts');ET.SubElement(alert,'log_alert_level').text='3'
    rules=ET.SubElement(config,'ruleset')
    for name in ('ruleset/decoders','etc/decoders'):ET.SubElement(rules,'decoder_dir').text=name
    # Preserve production's rule order, excludes and CDB list declarations.
    production=ET.fromstring('<root>'+Path('/var/ossec/etc/ossec.conf').read_text()+'</root>')
    original=production.find('.//ruleset')
    for child in list(original) if original is not None else []:
        if child.tag in ('rule_dir','rule_exclude','rule_include','list'):
            if child.text and (child.text.startswith('/') or '..' in Path(child.text).parts):raise ValueError('Unexpected absolute ruleset path')
            rules.append(ET.fromstring(ET.tostring(child)))
    test=ET.SubElement(config,'rule_test');ET.SubElement(test,'enabled').text='no'
    ET.indent(config);(root/'etc/ossec.conf').write_text(ET.tostring(config,encoding='unicode'))
    manifest={'binary_sha256':hashlib.sha256(Path('/var/ossec/bin/wazuh-analysisd').read_bytes()).hexdigest(),
        'db_sha256':hashlib.sha256(executable.read_bytes()).hexdigest(),
        'pipeline':pipeline,'profile_files':{}}
    for directory in ('ruleset','etc/decoders','etc/rules','etc/lists'):
        for path in sorted((root/directory).rglob('*')):
            if path.is_file():manifest['profile_files'][str(path.relative_to(root))]=hashlib.sha256(path.read_bytes()).hexdigest()
    (root/'etc/soc-delivery.json').write_text(json.dumps(manifest))
    for name in ('etc/ossec.conf','etc/internal_options.conf','etc/local_internal_options.conf','etc/soc-delivery.json'):
        path=root/name
        if path.exists():os.chown(path,0,gid);os.chmod(path,0o640)
    subprocess.run(['/var/ossec/bin/wazuh-analysisd','-t','-D',str(root),'-c','etc/ossec.conf'],check=True,timeout=30)
    return manifest

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('root');parser.add_argument('--pipeline',default='')
    args=parser.parse_args();manifest=prepare(args.root,args.pipeline)
    print('Native HTTPS engine profile verified:',len(manifest['profile_files']),'files; no production credentials or queues copied.')

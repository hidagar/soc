"""Isolated WireGuard peers; the portal queues changes for a privileged worker."""
import base64
import ipaddress
import os
import subprocess
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,PublicFormat,NoEncryption
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from .models import VpnPeer,WorkerState
from .security import encrypt,decrypt,audit

SERVER='10.255.251.1'
NETWORK=ipaddress.ip_network('10.255.251.0/24')
PUBLIC_KEY=Path('/usr/local/share/soc-portal/wg-soc.pub')

def create_peer(site):
    with transaction.atomic():
        # Serialize address allocation on SQLite, including concurrent requests.
        WorkerState.reserve('vpn-allocation')
        existing=VpnPeer.objects.filter(site=site).first()
        if existing: return existing
        used=set(VpnPeer._base_manager.values_list('address',flat=True))
        address=next((str(v) for v in NETWORK.hosts() if str(v)!=SERVER and str(v) not in used),None)
        if not address: raise ValueError('No quedan direcciones VPN disponibles.')
        private=X25519PrivateKey.generate()
        secret=base64.b64encode(private.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption())).decode()
        public=base64.b64encode(private.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()
        psk=base64.b64encode(os.urandom(32)).decode()
        peer=VpnPeer.objects.create(site=site,address=address,public_key=public,
            encrypted_private_key=encrypt(secret),encrypted_preshared_key=encrypt(psk))
        audit('vpn.prepared',peer)
        return peer

def client_config(peer):
    public=PUBLIC_KEY.read_text().strip()
    if len(base64.b64decode(public,validate=True))!=32: raise ValueError('Clave de servidor no válida.')
    # Only the collector address crosses the tunnel. No customer LAN routes or default route.
    return '\n'.join(['[Interface]','PrivateKey = '+decrypt(peer.encrypted_private_key),
        'Address = '+peer.address+'/32','', '[Peer]','PublicKey = '+public,
        'PresharedKey = '+decrypt(peer.encrypted_preshared_key),
        'Endpoint = soc.ibred.es:51820','AllowedIPs = '+SERVER+'/32','PersistentKeepalive = 25',''])

def active_peers():
    return VpnPeer.objects.filter(enabled=True,site__active=True,site__client__active=True).order_by('pk')

def synchronize():
    peers=list(active_peers())
    server_key=Path('/etc/wireguard/wg-soc.key').read_text().strip()
    if len(base64.b64decode(server_key,validate=True))!=32: raise ValueError('Clave de servidor no válida.')
    lines=['[Interface]','PrivateKey = '+server_key,'ListenPort = 51820']
    for p in peers:
        if ipaddress.ip_address(p.address) not in NETWORK or p.address==SERVER: raise ValueError('Dirección no válida.')
        lines+=['','[Peer]','PublicKey = '+p.public_key,'PresharedKey = '+decrypt(p.encrypted_preshared_key),'AllowedIPs = '+p.address+'/32']
    secret_path=Path('/etc/wireguard/.soc-runtime.conf')
    fd=os.open(secret_path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
    with os.fdopen(fd,'w') as stream: stream.write('\n'.join(lines)+'\n')
    try:
        subprocess.run(['wg','syncconf','wg-soc',str(secret_path)],check=True,capture_output=True,timeout=15)
    finally: secret_path.unlink(missing_ok=True)
    for p in peers:
        subprocess.run(['ip','route','replace',p.address+'/32','dev','wg-soc'],check=True,capture_output=True,timeout=5)
    for p in VpnPeer.objects.exclude(pk__in=[p.pk for p in peers]):
        subprocess.run(['ip','route','del',p.address+'/32','dev','wg-soc'],capture_output=True,timeout=5)
    # Validate rules before replacing only our own nft table. Never change existing perimeter rules.
    rules='''table inet soc_wg {
      chain input { type filter hook input priority -10; policy accept;
        iifname "wg-soc" ip daddr 10.255.251.1 udp dport 5514 accept
        iifname "wg-soc" ip daddr 10.255.251.1 icmp type echo-request accept
        iifname "wg-soc" drop
      }
      chain forward { type filter hook forward priority -10; policy accept;
        iifname "wg-soc" drop
        oifname "wg-soc" drop
      }
    }'''
    exists=subprocess.run(['nft','list','table','inet','soc_wg'],capture_output=True,timeout=5).returncode==0
    script=('delete table inet soc_wg\n' if exists else '')+rules
    subprocess.run(['nft','--check','-f','-'],input=script,text=True,check=True,capture_output=True,timeout=5)
    subprocess.run(['nft','-f','-'],input=script,text=True,check=True,capture_output=True,timeout=5)
    result=subprocess.run(['wg','show','wg-soc','latest-handshakes'],check=True,capture_output=True,text=True,timeout=5)
    times={line.split()[0]:int(line.split()[1]) for line in result.stdout.splitlines()}
    transfers=subprocess.run(['wg','show','wg-soc','transfer'],check=True,capture_output=True,text=True,timeout=5)
    totals={line.split()[0]:(int(line.split()[1]),int(line.split()[2])) for line in transfers.stdout.splitlines()}
    from datetime import datetime,timezone as utc
    for p in peers:
        stamp=times.get(p.public_key,0)
        p.handshake_at=datetime.fromtimestamp(stamp,utc.utc) if stamp else None
        p.status='connected' if stamp and 0<=(timezone.now()-p.handshake_at).total_seconds()<180 else 'waiting'
        p.refresh_from_db(fields=['transport'])
        rx,tx=totals.get(p.public_key,(0,0))
        p.transport=transfer_sample(p.transport,rx,tx,timezone.now())
        p.save(update_fields=['handshake_at','status','transport'])
    VpnPeer.objects.filter(enabled=False).update(status='prepared',handshake_at=None)
    VpnPeer.objects.filter(Q(site__active=False)|Q(site__client__active=False)).update(status='paused',handshake_at=None)
    state,_=WorkerState.objects.get_or_create(name='vpn')
    state.last_success_at=timezone.now(); state.error=''; state.save()

def record_log_transport(device,source,stamp,now):
    if not device.active or device.integration=='paused':return
    if not 0<=(now-stamp).total_seconds()<=600:return
    peer=VpnPeer.objects.filter(site_id=device.site_id,address=source,enabled=True,site__active=True,site__client__active=True).first()
    if not peer:return
    from django.utils.dateparse import parse_datetime
    try:old=parse_datetime(peer.transport.get('log_at',''))
    except (ValueError,TypeError):old=None
    if old and old>=stamp:return
    peer.transport={**peer.transport,'log_at':stamp.isoformat(),'log_device_id':device.pk,'log_recorded_at':now.isoformat()}
    peer.save(update_fields=['transport'])

def transfer_sample(previous,rx,tx,now):
    """Recent deltas, not lifetime counters presented as current traffic."""
    from django.utils.dateparse import parse_datetime
    result={**previous,'received_bytes':rx,'sent_bytes':tx,'sampled_at':now.isoformat(),
        'received_delta':None,'sent_delta':None,'delta_since':None}
    try:
        old=parse_datetime(previous.get('sampled_at',''))
        before_rx=previous.get('received_bytes');before_tx=previous.get('sent_bytes')
        valid=all(isinstance(v,int) and not isinstance(v,bool) and v>=0 for v in (rx,tx,before_rx,before_tx))
        if valid and (rx<before_rx or tx<before_tx):
            for key in ('log_at','log_device_id','log_recorded_at'):result.pop(key,None)
            result['counters_reset_at']=now.isoformat()
        elif valid and old and 0<(now-old).total_seconds()<=180:
            result.update(received_delta=rx-before_rx,sent_delta=tx-before_tx,delta_since=old.isoformat())
    except (ValueError,TypeError):pass
    return result


def transport_snapshot(peer,now=None):
    from django.utils.dateparse import parse_datetime
    now=now or timezone.now()
    try:
        log_at=parse_datetime(peer.transport.get('log_at',''))
        sampled=parse_datetime(peer.transport.get('sampled_at',''))
        current=bool(peer.enabled and peer.site.active and peer.site.client.active and sampled and 0<=(now-sampled).total_seconds()<=180)
        handshake=bool(current and peer.handshake_at and 0<=(now-peer.handshake_at).total_seconds()<=180)
        from .models import Device
        owned=Device.objects.filter(pk=peer.transport.get('log_device_id'),site_id=peer.site_id,active=True).exclude(integration='paused').exists()
        logs=bool(handshake and owned and log_at and 0<=(now-log_at).total_seconds()<=600 and peer.transport.get('received_bytes',0)>0)
    except (ValueError,TypeError):current=handshake=logs=False;log_at=None
    rx=peer.transport.get('received_delta');tx=peer.transport.get('sent_delta')
    deltas=bool(current and all(isinstance(v,int) and not isinstance(v,bool) and v>=0 for v in (rx,tx)) and peer.transport.get('delta_since'))
    steps=[{'label':'Peer habilitado','ok':bool(peer.enabled and peer.site.active and peer.site.client.active)},
        {'label':'Muestra reciente del servicio','ok':current}, {'label':'Handshake reciente','ok':handshake},
        {'label':'Logs recientes atribuidos a un equipo de esta sede','ok':logs}]
    return {'peer':peer,'handshake_current':handshake,'logs_current':logs,'log_at':log_at,'current':current,
        'steps':steps,'delta_current':deltas,'received_delta':rx if deltas else None,'sent_delta':tx if deltas else None}

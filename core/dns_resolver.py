"""DNS del SOC para las sedes por la VPN de sedes: bloqueo de dominios para equipos sin listas DNS propias.

Pensado para Grandstream GCC (sin listas por URL ni escritura por API), sirve para cualquier sede con la VPN:
- la sede se conecta por WireGuard a la VPN de sedes y su firewall reenvía el DNS a 10.255.251.1;
- un Unbound del SOC, que escucha solo en esa dirección, responde con la lista de dominios de Q-Feeds de su
  cliente (sin sus excepciones). Cada cliente tiene su zona RPZ y solo la aplican las direcciones VPN de sus
  sedes (etiquetas de Unbound); cualquier otra dirección recibe REFUSED;
- el trabajo protegido `operate_soc dns` (cada 15 minutos, root) escribe las zonas y la configuración propia,
  comprueba la configuración con `unbound-checkconf` y recarga Unbound solo si algo cambió. Si la comprobación
  falla, restaura lo anterior. Comandos fijos: nunca un ejecutor genérico (invariante 8);
- el freno de emergencia, detener o despublicar la lista o desactivar los dominios de Q-Feeds dejan la zona del
  cliente vacía: sus consultas se resuelven con normalidad. Solo desactivar «DNS del SOC» retira el acceso de sus
  sedes, así que antes hay que devolver el DNS del firewall de la sede a su valor anterior;
- medición: Unbound anota cada consulta bloqueada (`rpz-log`); el trabajo cuenta las de cada cliente en el
  diario de systemd con un cursor propio, que solo avanza si la lectura terminó (invariante 5). No se guardan
  dominios ni consultas: solo el número por día. Unbound no registra las consultas resueltas.

Sin `deploy/configurar_dns_soc.sh` (Unbound instalado y la configuración base del SOC) el trabajo no hace nada.
"""
import hashlib
import os
import subprocess
from datetime import timedelta
from pathlib import Path

from django.db import transaction
from django.utils import timezone

from .models import BlocklistFeed, VpnPeer, WorkerState

ADDRESS = '10.255.251.1'
CONF_DIR = Path(os.environ.get('SOC_DNS_CONF_DIR', '/etc/unbound/unbound.conf.d'))
ZONE_DIR = Path(os.environ.get('SOC_DNS_ZONE_DIR', '/var/lib/unbound/soc'))
BASE = 'soc-base.conf'  # la escribe deploy/configurar_dns_soc.sh: interfaz, controles de acceso y registro
OWN = 'soc-qfeeds.conf'
STATE = 'dns-resolver'
HISTORY_DAYS = 35
TTL = 300


def zone_name(feed):
    return f'soc-c{feed.client_id}'


def served():
    """[(lista del cliente, direcciones VPN de sus sedes, aplica la lista)] con el DNS del SOC activado.

    Solo desactivar «DNS del SOC» retira el acceso de sus sedes: desactivar los dominios de Q-Feeds, detener la
    lista o despublicarla deja la zona vacía y las sedes siguen resolviendo (si no, se quedarían sin DNS).
    """
    from .qfeeds_distribution import publishing
    result = []
    for feed in BlocklistFeed._base_manager.filter(dns_resolver=True).select_related('client'):
        peers = sorted(VpnPeer._base_manager.filter(site__client_id=feed.client_id, enabled=True, site__active=True,
                                                    site__client__active=True).values_list('address', flat=True))
        if peers:
            result.append((feed, peers, publishing(feed) and feed.qfeeds_dns))
    return result


def dns_peers():
    """Direcciones VPN que pueden consultar el DNS del SOC (reglas nft de la VPN de sedes)."""
    return sorted({address for _, peers, _ in served() for address in peers})


def zone_text(name, domains):
    """Zona RPZ: cada dominio de la lista responde NXDOMAIN (`CNAME .`). Nombres relativos al origen de la zona."""
    lines = [f'$ORIGIN {name}.', f'$TTL {TTL}', f'@ IN SOA localhost. soc.localhost. 1 3600 600 86400 {TTL}', '@ IN NS localhost.']
    lines += [f'{domain} CNAME .' for domain in domains]
    return '\n'.join(lines) + '\n'


def conf_text(entries):
    """Configuración propia del SOC para Unbound: etiqueta por cliente, acceso de sus sedes y su zona RPZ."""
    if not entries:
        return '# DNS del SOC: ningún cliente activado. Lo genera operate_soc dns; no editar a mano.\n'
    tags = ' '.join(name for name, _, _ in entries)
    lines = ['# DNS del SOC. Lo genera operate_soc dns; no editar a mano.', 'server:', f'    define-tag: "{tags}"']
    for name, peers, _ in entries:
        for address in peers:
            lines += [f'    access-control: {address}/32 allow', f'    access-control-tag: {address}/32 "{name}"']
    for name, _, path in entries:
        lines += ['', 'rpz:', f'    name: {name}', f'    zonefile: {path}', f'    tags: "{name}"', '    rpz-log: yes',
                  f'    rpz-log-name: "{name}"']
    return '\n'.join(lines) + '\n'


def desired():
    """(configuración, {archivo de zona: contenido}) a partir de las listas actuales."""
    from .qfeeds_distribution import servable_dns
    entries, zones = [], {}
    for feed, peers, live in served():
        name = zone_name(feed)
        path = ZONE_DIR / f'{name}.rpz'
        # Detenida o despublicada: zona vacía, las consultas de sus sedes se resuelven con normalidad.
        zones[path] = zone_text(name, servable_dns(feed) if live else [])
        entries.append((name, peers, path))
    return conf_text(entries), zones


def _digest(conf, zones):
    data = conf + ''.join(f'{path}\n{text}' for path, text in sorted(zones.items(), key=lambda item: str(item[0])))
    return hashlib.sha256(data.encode()).hexdigest()


def _run(args, timeout=60, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=timeout, **kwargs)


def _write(path, text):
    tmp = path.with_name(path.name + '.tmp')
    tmp.write_text(text)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def apply(conf, zones):
    """Escribe zonas y configuración, las comprueba y recarga Unbound. Si la comprobación falla, restaura."""
    ZONE_DIR.mkdir(parents=True, exist_ok=True)
    own = CONF_DIR / OWN
    previous = {path: path.read_text() for path in [own, *ZONE_DIR.glob('soc-c*.rpz')] if path.exists()}
    try:
        for path, text in zones.items():
            _write(path, text)
        _write(own, conf)
        _run(['unbound-checkconf'])
    except (OSError, subprocess.SubprocessError):
        for path in [own, *zones]:
            if path in previous:
                _write(path, previous[path])
            else:
                path.unlink(missing_ok=True)
        raise
    for path in ZONE_DIR.glob('soc-c*.rpz'):
        if path not in zones:
            path.unlink(missing_ok=True)  # cliente desactivado: su zona ya no está en la configuración
    _run(['unbound-control', 'reload'])


def count_blocked(lines, names):
    """Consultas bloqueadas por zona en líneas del diario de Unbound (`rpz: applied [soc-cN] …`).

    `_rpz_other` cuenta líneas de RPZ que no encajan con ese formato: si hay bloqueos que no se reconocen,
    el formato del diario no es el esperado y la página del cliente lo avisa (no se inventa un cero).
    """
    counts = {name: 0 for name in names}
    other = 0
    for line in lines:
        if 'rpz:' not in line:
            continue
        if 'rpz: applied' in line and any(f'[{name}]' in line for name in names):
            counts[next(name for name in names if f'[{name}]' in line)] += 1
        elif 'soc-c' in line:
            other += 1
    counts['_rpz_other'] = other
    return counts


def unbound_health(zones):
    """(Unbound responde, zonas RPZ cargadas o None si no se pueden listar) con comandos fijos de unbound-control."""
    try:
        _run(['unbound-control', 'status'], timeout=15)
    except (OSError, subprocess.SubprocessError):
        return False, None
    try:
        output = _run(['unbound-control', 'list_auth_zones'], timeout=15).stdout
    except (OSError, subprocess.SubprocessError):
        return True, None
    loaded = sorted({line.split()[0].rstrip('.') for line in output.splitlines() if line.strip().startswith('soc-c')})
    return True, loaded


def read_journal(cursor):
    """(líneas, cursor nuevo) del diario de Unbound desde el cursor. Excepción si la lectura no termina."""
    args = ['journalctl', '-u', 'unbound', '-o', 'cat', '--no-pager', '-q', '--show-cursor']
    args += ['--after-cursor', cursor] if cursor else ['--since', '-15min']
    output = _run(args, timeout=120).stdout.splitlines()
    new = cursor
    if output and output[-1].startswith('-- cursor: '):
        new = output.pop()[len('-- cursor: '):].strip()
    return output, new


def record(counts, now):
    day = timezone.localtime(now).date().isoformat()
    cutoff = (timezone.localtime(now).date() - timedelta(days=HISTORY_DAYS)).isoformat()
    for client_id, blocked in counts.items():
        name = f'{STATE}:{client_id}'
        state = WorkerState.objects.filter(name=name).first()
        details = dict(state.details) if state else {}
        history = {d: v for d, v in (details.get('history') or {}).items() if d >= cutoff}
        history[day] = history.get(day, 0) + blocked
        details.update(history=history, checked_at=now.isoformat(), since=details.get('since') or now.isoformat(),
                       total_queries=details.get('total_queries', 0) + blocked)
        if blocked:
            details['last_block_at'] = now.isoformat()
        with transaction.atomic():
            WorkerState.reserve(name)
            WorkerState.objects.filter(name=name).update(details=details)


def synchronize(now=None):
    """Trabajo protegido: genera y aplica la configuración y cuenta lo bloqueado. Sin Unbound del SOC, nada."""
    now = now or timezone.now()
    state = WorkerState.objects.filter(name=STATE).first()
    details = dict(state.details) if state else {}
    if not (CONF_DIR / BASE).exists():
        details.update(configured=False, checked_at=now.isoformat())
    else:
        conf, zones = desired()
        digest = _digest(conf, zones)
        details.update(configured=True, checked_at=now.isoformat(), error='')
        try:
            if digest != details.get('digest') or not (CONF_DIR / OWN).exists():
                apply(conf, zones)
                details.update(digest=digest, applied_at=now.isoformat(), clients=len(zones))
        except (OSError, subprocess.SubprocessError):
            details['error'] = 'Unbound no aceptó la configuración del SOC; se mantiene la anterior. Revisar `unbound-checkconf`.'
        details['zone_domains'] = {path.stem: text.count(' CNAME .') for path, text in zones.items()}
        details['unbound_ok'], details['loaded_zones'] = unbound_health(zones)
        names = {zone_name(feed): feed.client_id for feed, _, _ in served()}
        try:
            lines, cursor = read_journal(details.get('cursor'))
        except (OSError, subprocess.SubprocessError):
            details['journal_error'] = 'No se pudo leer el diario de Unbound; el recuento se reanudará desde el mismo punto.'
        else:
            counts = count_blocked(lines, names)
            other = counts.pop('_rpz_other')
            record({names[name]: n for name, n in counts.items()}, now)
            details.update(cursor=cursor, journal_error='')
            if other:
                details['format_warning'] = (f'{other} línea(s) de bloqueo del SOC en el diario de Unbound con un formato que no se '
                                             'reconoce: el recuento puede quedarse corto. Revisar el formato de rpz-log.')
                details['format_warning_at'] = now.isoformat()
    with transaction.atomic():
        WorkerState.reserve(STATE)
        WorkerState.objects.filter(name=STATE).update(details=details)
    return details


def status():
    state = WorkerState.objects.filter(name=STATE).first()
    return dict(state.details) if state else {}


def client_status(feed):
    """Estado para la lista del cliente: sedes con VPN, si consultan y lo bloqueado en 7 días."""
    from django.utils.dateparse import parse_datetime
    peers = list(VpnPeer._base_manager.filter(site__client_id=feed.client_id, site__active=True).select_related('site')
                 .order_by('site__name'))
    state = WorkerState.objects.filter(name=f'{STATE}:{feed.client_id}').first()
    history = (state.details.get('history') or {}) if state else {}
    today = timezone.localdate()
    week = sum(v for d, v in history.items() if d >= (today - timedelta(days=6)).isoformat())
    general = status()
    name = zone_name(feed)
    loaded = general.get('loaded_zones')
    connected = [p for p in peers if p.enabled and p.status == 'connected']
    last_block = parse_datetime(state.details.get('last_block_at') or '') if state else None
    # Lista de comprobación del piloto: True correcto, False fallo, None aún sin dato.
    checks = [
        ('DNS del SOC instalado en la VM', bool(general.get('configured')),
         '' if general.get('configured') else 'sudo deploy/configurar_dns_soc.sh --instalar'),
        ('Unbound responde', general.get('unbound_ok') if general.get('configured') else None,
         'Revisar «systemctl status unbound» en la VM.' if general.get('unbound_ok') is False else ''),
        ('Lista de dominios cargada en Unbound', (name in loaded) if isinstance(loaded, list) and general.get('configured') else None,
         f"{general.get('zone_domains', {}).get(name, 0)} dominios" if isinstance(loaded, list) and name in loaded else
         'Se carga en la siguiente pasada del trabajo soc-dns (15 minutos).'),
        ('Sede conectada a la VPN', bool(connected) if peers else False,
         ', '.join(p.site.name for p in connected) if connected else 'Conectar la VPN de sedes desde el firewall.'),
        ('Bloqueo visto desde una sede', True if last_block else None,
         timezone.localtime(last_block).strftime('%d/%m/%Y %H:%M') if last_block else
         'Probar desde un PC de la sede un dominio de la lista (nslookup): debe dar «Non-existent domain».'),
    ]
    return {'peers': peers, 'configured': bool(general.get('configured')), 'error': general.get('error', ''),
            'applied_at': parse_datetime(general.get('applied_at') or ''), 'week': week if state else None,
            'address': ADDRESS, 'checks': checks, 'format_warning': general.get('format_warning', ''),
            'journal_error': general.get('journal_error', '')}


def blocked_between(client_id, first_day, last_day):
    """Consultas bloqueadas por el DNS del SOC para un cliente entre dos días (None si no hay medida)."""
    state = WorkerState.objects.filter(name=f'{STATE}:{client_id}').first()
    if not state or not state.details.get('checked_at'):
        return None
    return sum(v for d, v in (state.details.get('history') or {}).items() if first_day.isoformat() <= d <= last_day.isoformat())

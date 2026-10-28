"""Comprobación de solo lectura del bloqueo del SOC en consolas UniFi.

Se ejecuta en el servidor del SOC, que tiene la clave cifrada de cada consola:

    sudo bash -c 'eval "$(python3 /srv/soc-portal/deploy/envfile.py --shell /etc/soc-portal/portal.env)"; cd /srv/soc-portal && runuser -u socportal -- /opt/soc-portal-venv/bin/python manage.py unifi_bloqueo_comprobar --equipo NOMBRE'

(sin --equipo revisa todos los equipos UniFi). Carga el entorno como deploy/update.sh.

Solo hace consultas GET. Muestra nombres, recuentos y estados; nunca IPs, claves ni respuestas
crudas de UniFi, para que la salida se pueda compartir.
"""
from django.core.management.base import BaseCommand, CommandError

from core import unifi_blocklist as ub
from core.models import BlocklistFeed, Device, UnifiBlocklistBinding
from core.unifi_cloud import UnifiCloudError, decrypt_api_key


def _list_ref(side):
    flt = (side or {}).get('trafficFilter') or {}
    ip = flt.get('ipAddressFilter') or {}
    return ip.get('trafficMatchingListId') if ip.get('type') == 'TRAFFIC_MATCHING_LIST' else None


class Command(BaseCommand):
    help = 'Comprueba (solo lectura) listas y políticas «SOC…» de las consolas UniFi vinculadas.'

    def add_arguments(self, parser):
        parser.add_argument('--equipo', help='Nombre o número del equipo UniFi (por defecto, todos los vinculados).')

    def handle(self, *args, **options):
        devices = Device._base_manager.filter(vendor=Device.Vendor.UNIFI).select_related('site__client')
        wanted = options.get('equipo')
        if wanted:
            devices = devices.filter(pk=int(wanted)) if wanted.isdigit() else devices.filter(name__iexact=wanted)
        devices = list(devices.order_by('site__client__name', 'name'))
        if not devices:
            raise CommandError('No hay equipos UniFi con ese nombre.')
        for device in devices:
            self.check_device(device)

    def line(self, text='', level=0):
        self.stdout.write('  ' * level + text)

    def check_device(self, device):
        client = device.site.client
        self.line()
        self.line(f'=== {device.name} · {client.name} · {device.site.name} (equipo {device.pk}) ===')
        feed = BlocklistFeed._base_manager.filter(client=client).first()
        if not feed:
            self.line('Lista del SOC: no configurada para este cliente.', 1)
        else:
            state = 'detenida (freno)' if feed.stopped else 'publicada' if feed.enabled else 'desactivada'
            self.line(f'Lista del SOC: {state} · {len(feed.entries)} entradas de entrada · '
                      f'salida C2 {"activa" if feed.outbound_enabled else "no"} ({len(feed.outbound_entries)}).', 1)
        connection = getattr(device, 'unifi_cloud', None)
        if connection is None or not connection.remote_host_id:
            self.line('Consola UniFi: NO vinculada. Vincúlala en «Conexión UniFi» de la ficha del equipo.', 1)
            return
        self.line(f'Consola UniFi: vinculada · comprobación {"correcta" if connection.last_ok else "con error o pendiente"}.', 1)
        bindings = list(UnifiBlocklistBinding._base_manager.filter(device=device))
        if not bindings:
            self.line('Panel: sin lista vinculada todavía (pendiente de «Crear lista y política»).', 1)
        for b in bindings:
            synced = b.synced_at.strftime('%d/%m/%Y %H:%M') if b.synced_at else 'nunca'
            self.line(f'Panel · {b.get_direction_display()}: lista «{b.list_name}» · {b.pushed_count} IPs escritas · '
                      f'última sincronización {synced} · políticas guardadas {len(b.policies)} · '
                      f'{"ACTIVADAS" if b.policies_enabled else "desactivadas"}'
                      f'{" · ERROR: " + b.error if b.error else ""}', 1)
        try:
            key = decrypt_api_key(connection.encrypted_api_key)
            host = connection.remote_host_id
            site = ub.default_site(key, host)
            self.line('Sitio principal: encontrado.', 1)
        except UnifiCloudError as exc:
            self.line(f'No se pudo consultar la consola: {exc}', 1)
            return
        self.check_zones(key, host, site)
        lists = self.check_lists(key, host, site)
        self.check_policies(key, host, site, lists, bindings)

    def check_zones(self, key, host, site):
        try:
            rows = [z for z in ub.call(key, host, f'/v1/sites/{site}/firewall/zones').get('data') or [] if isinstance(z, dict)]
            self.zone_ids = {str(z.get('name', '')).lower(): z.get('id') for z in rows}
            self.zone_labels = {z.get('id'): str(z.get('name', '')) for z in rows}
        except UnifiCloudError as exc:
            self.zone_ids, self.zone_labels = {}, {}
            self.line(f'Zonas: no se pudieron leer ({exc}).', 1)
            return
        needed = {name.lower() for flows in ub.FLOWS.values() for pair in flows for name in pair}
        missing = sorted(needed - set(self.zone_ids))
        self.line(f'Zonas: {len(self.zone_ids)} · necesarias para el bloqueo: '
                  f'{"todas presentes" if not missing else "FALTAN " + ", ".join(missing)}.', 1)

    def check_lists(self, key, host, site):
        try:
            rows = ub.call(key, host, f'/v1/sites/{site}/traffic-matching-lists').get('data') or []
        except UnifiCloudError as exc:
            self.line(f'Listas: no se pudieron leer ({exc}).', 1)
            return {}
        own = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            name = str(row.get('name') or '')
            if name.upper().startswith(ub.PREFIX) and row.get('type') == 'IPV4_ADDRESSES':
                own[row.get('id')] = name
                items = row.get('items') or []
                placeholder = ub.decode(items) == [ub.PLACEHOLDER]
                self.line(f'Lista «{name}»: {0 if placeholder else len(items)} entradas'
                          f'{" (solo la dirección de prueba)" if placeholder else ""} · formato '
                          f'{ub.item_format(items) or "desconocido"}.', 1)
        self.line(f'Listas en la consola: {len(rows)} en total, {len(own)} del SOC («SOC…», IPv4).', 1)
        return own

    def check_policies(self, key, host, site, lists, bindings):
        try:
            rows = ub.policies(key, host, site)
        except UnifiCloudError as exc:
            self.line(f'Políticas: no se pudieron leer ({exc}).', 1)
            return
        names = getattr(self, 'zone_labels', {})
        saved = {p['id'] for b in bindings for p in b.policies}
        soc = [p for p in rows if str(p.get('name', '')).startswith(ub.PREFIX) or p.get('id') in saved
               or _list_ref(p.get('source')) in lists or _list_ref(p.get('destination')) in lists]
        self.line(f'Políticas: {len(rows)} en total, {len(soc)} del SOC o que usan su lista.', 1)
        for p in sorted(soc, key=lambda r: (r.get('index') is None, r.get('index') or 0)):
            src, dst = p.get('source') or {}, p.get('destination') or {}
            pair = (src.get('zoneId'), dst.get('zoneId'))
            action = (p.get('action') or {}).get('type', '?')
            index = p.get('index')
            # Políticas del operador que permiten el mismo flujo de zonas y se evalúan antes.
            before = [r for r in rows if r is not p and isinstance(index, int) and isinstance(r.get('index'), int)
                      and r['index'] < index and r.get('enabled') and (r.get('action') or {}).get('type') == 'ALLOW'
                      and ((r.get('source') or {}).get('zoneId'), (r.get('destination') or {}).get('zoneId')) == pair]
            used = lists.get(_list_ref(src)) or lists.get(_list_ref(dst)) or 'ninguna lista del SOC'
            self.line(f'«{p.get("name")}»: {"ACTIVADA" if p.get("enabled") else "desactivada"} · acción {action} · '
                      f'{names.get(pair[0], "?")} → {names.get(pair[1], "?")} · lista: {used} · '
                      f'orden {index if index is not None else "no informado"}'
                      f'{" · creada por el panel" if p.get("id") in saved else ""}', 2)
            if before:
                self.line(f'AVISO: {len(before)} política(s) ALLOW del mismo flujo se evalúan antes; '
                          'revisa el orden en UniFi antes de activar.', 3)
        missing = saved - {p.get('id') for p in rows}
        if missing:
            self.line(f'AVISO: {len(missing)} política(s) guardadas en el panel ya no existen en UniFi.', 1)

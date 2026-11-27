"""Capacidades por fabricante: cada función del SOC es común y se aplica con un adaptador por fabricante.

Modos:
- `auto`: el SOC lo aplica por API, con el control de cambios cuando escribe en el equipo.
- `guided`: el SOC prepara lo necesario (URL, lista, guía) y alguien lo configura en el equipo; después se comprueba.
- `partial`: funciona con un límite que se indica en la nota.
- `pending`: falta comprobar si el fabricante lo permite (documentación y un equipo real). Hasta entonces, nada
  se presume: no se ofrece como disponible.
- `unavailable`: el fabricante no lo permite.

Nada aquí se deduce de una casilla: la tabla describe lo que el código sabe hacer con cada fabricante y lo que
se ha comprobado. Cambiarla exige cambiar también el adaptador y su documentación (docs/integrations.md).
"""
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from django.views.decorators.http import require_GET

MODES = {'auto': 'Automático', 'guided': 'Guiado', 'partial': 'Parcial', 'pending': 'Por comprobar',
         'unavailable': 'No disponible'}
FEATURES = (
    ('logs', 'Recepción de registros y detecciones'),
    ('blocklist', 'Lista de bloqueo de entrada'),
    ('blocklist_out', 'Lista de salida (C2)'),
    ('preventive', 'Lista preventiva de Q-Feeds'),
    ('dns', 'Bloqueo de dominios por DNS'),
    ('measure', 'Medición de lo bloqueado'),
    ('policy', 'Cambios de política del firewall'),
)
VENDORS = (('opnsense', 'OPNsense'), ('unifi', 'UniFi'), ('hillstone', 'Hillstone'), ('grandstream_gcc', 'Grandstream GCC'))
_URL_GUIDE = 'tabla o lista de IPs por URL con la dirección de la lista del cliente.'
MATRIX = {
    'opnsense': {
        'logs': ('auto', 'Destino Syslog creado y verificado por API o SSH.'),
        'blocklist': ('auto', 'Alias por URL y regla con el control de cambios (API). Sin API: ' + _URL_GUIDE),
        'blocklist_out': ('auto', 'Igual que la de entrada, con regla de salida.'),
        'preventive': ('auto', 'Alias por URL y reglas propias de entrada y salida (API). Sin API: ' + _URL_GUIDE),
        'dns': ('auto', 'Lista de bloqueo propia en Unbound con el control de cambios (OPNsense 25.7 o posterior y API). '
                        'En versiones anteriores o sin API: URL de dominios añadida a mano en Unbound.'),
        'measure': ('auto', 'Contadores de cada regla del SOC y entradas cargadas, cada hora. DNS: consultas que bloqueó la '
                            'lista del SOC según las estadísticas de Unbound (25.7, con la recogida local activada).'),
        'policy': ('auto', 'Reglas con punto de restauración, confirmación y reversión.'),
    },
    'unifi': {
        'logs': ('auto', 'Activity Logging gestionado y verificado por la API de Site Manager.'),
        'blocklist': ('auto', 'El SOC escribe la lista IPv4 y crea sus políticas desactivadas (máximo 4.000 IPv4).'),
        'blocklist_out': ('auto', 'Igual que la de entrada, con política de salida.'),
        'preventive': ('partial', 'Lista y políticas propias, solo de entrada y con las 4.000 primeras IPv4.'),
        'dns': ('partial', 'Política de bloqueo por dominios del SOC (UniFi Network 10.1 o posterior, también 11), creada desactivada, '
                           'con los 1.000 dominios más recientes. Bloquea la conexión, no la consulta DNS, y no se mide.'),
        'measure': ('partial', 'Sin contadores por política: indicio a partir de las detecciones de IPs de la lista.'),
        'policy': ('guided', 'Guía preparada; la política se aplica desde la consola UniFi.'),
    },
    'hillstone': {
        'logs': ('guided', 'Syslog configurado con la guía y comprobado al recibir registros.'),
        'blocklist': ('guided', 'Lista negra del filtrado perimetral (Perimeter Traffic Filtering) importada de una fuente '
                                'externa por HTTPS con la URL del SOC (StoneOS 5.5R9 o posterior; puede requerir la licencia '
                                'de reputación IP). La descarga desde el equipo se comprueba en el SOC.'),
        'blocklist_out': ('guided', 'Lista dinámica externa (External Dynamic List) en el destino de una política de bloqueo '
                                    '(StoneOS 5.5R12 o posterior). La descarga desde el equipo se comprueba en el SOC.'),
        'preventive': ('guided', 'Como la lista de entrada (filtrado perimetral) o la de salida (lista dinámica externa), '
                                 'con la URL de la lista preventiva.'),
        'dns': ('pending', 'La API REST de StoneOS 5.5R10 gestiona la lista de bloqueo del módulo antibotnet, que podría '
                           'servir para dominios; falta su guía REST (se descarga desde el propio equipo) y la licencia.'),
        'measure': ('pending', 'StoneOS cuenta los aciertos de cada política; falta la guía REST para leerlos desde el SOC.'),
        'policy': ('guided', 'Guía preparada; se aplica desde la consola del equipo.'),
    },
    'grandstream_gcc': {
        'logs': ('guided', 'Syslog configurado con la guía y comprobado al recibir registros.'),
        'blocklist': ('unavailable', 'El cortafuegos del GCC no descarga listas de IPs por URL y la API de GDMS (GWN) no '
                                     'gestiona sus reglas ni sus grupos de direcciones. El GCC aplica sus propios módulos '
                                     '(IPS, antibotnet, filtrado DNS por categorías); el SOC lo cubre con detección y avisos.'),
        'blocklist_out': ('unavailable', 'Igual que la de entrada.'),
        'preventive': ('unavailable', 'Igual que la de entrada.'),
        'dns': ('guided', 'DNS del SOC por la VPN de sedes: el GCC se conecta por WireGuard y reenvía su DNS a 10.255.251.1, '
                          'que bloquea los dominios de la lista del cliente y cuenta lo bloqueado. Requiere activar «DNS del SOC».'),
        'measure': ('unavailable', 'Sin contadores por API; la API de GDMS solo exporta el registro de accesos web.'),
        'policy': ('guided', 'Guía preparada; se aplica desde la consola del equipo.'),
    },
}
UNKNOWN = ('pending', 'Fabricante sin adaptador: comprobar qué admite antes de ofrecerlo.')
# Pasos del modo guiado. Los nombres de menú van como los muestra el fabricante; se validan en un equipo real.
_FETCH = 'Al guardar, el firewall descarga la lista; en esta página aparece la descarga desde la IP del equipo.'
GUIDES = {
    ('opnsense', 'blocklist'): ['Firewall › Aliases: crear un alias de tipo «URL Table (IPs)» con la URL de la lista de entrada '
                                'y actualización cada hora.',
                                'Firewall › Rules › WAN: regla «Block» con origen ese alias, registrada, por encima de las que permiten tráfico.', _FETCH],
    ('opnsense', 'blocklist_out'): ['Firewall › Aliases: alias «URL Table (IPs)» con la URL de la lista de salida.',
                                    'Firewall › Rules › WAN: regla «Block» de salida con destino ese alias.', _FETCH],
    ('opnsense', 'preventive'): ['Firewall › Aliases: alias «URL Table (IPs)» con la URL de la lista preventiva (comprobar el máximo '
                                 'de entradas de tablas en Firewall › Settings › Advanced).',
                                 'Firewall › Rules › WAN: regla «Block» con origen ese alias.', _FETCH],
    ('opnsense', 'dns'): ['Services › Unbound DNS › Blocklist: añadir la URL de dominios como lista propia y aplicar.', _FETCH],
    ('grandstream_gcc', 'dns'): ['En el SOC: «VPN de sedes», preparar la VPN de la sede y descargar su configuración WireGuard; '
                                 'en la lista de bloqueo del cliente, activar «DNS del SOC».',
                                 'En el GCC: VPN › WireGuard, cliente con la configuración descargada (solo enruta 10.255.251.1).',
                                 'En la WAN (o en la VPN, «VPN Static DNS»): servidor DNS preferido 10.255.251.1. Los equipos siguen '
                                 'usando el GCC como DNS; el GCC reenvía al SOC.',
                                 'Servidor alternativo: dejar uno público solo si se prefiere disponibilidad a bloqueo (si el SOC no '
                                 'responde, se resuelve sin la lista).',
                                 'Comprobar en esta página que la sede aparece «Conectada» y que un dominio de la lista no resuelve.'],
    ('hillstone', 'blocklist'): ['Perimeter Traffic Filtering: activar la lista negra definida por el usuario e importar sus miembros '
                                 'desde una fuente externa por HTTPS con la URL de la lista de entrada.',
                                 'Formato: una IP o red por línea. Si StoneOS no acepta el certificado del SOC, importar su CA.', _FETCH],
    ('hillstone', 'blocklist_out'): ['Crear una External Dynamic List con la URL de la lista de salida.',
                                     'Política de bloqueo de la zona interna a la externa con esa lista como destino, por encima de las de permiso.', _FETCH],
    ('hillstone', 'preventive'): ['Entrada: importar la URL de la lista preventiva en la lista negra del Perimeter Traffic Filtering.',
                                  'Salida (opcional): External Dynamic List con la misma URL en el destino de una política de bloqueo.', _FETCH],
}


def capability(vendor, feature):
    """(modo, nota) de una función para un fabricante."""
    return MATRIX.get(vendor, {}).get(feature, UNKNOWN)


def _unifi_linked(device):
    from django.core.exceptions import ObjectDoesNotExist
    try:
        return bool(device.unifi_cloud.remote_host_id)
    except ObjectDoesNotExist:
        return False


def for_device(device, feature):
    """Modo efectivo en un equipo concreto: lo automático de OPNsense necesita su API conectada."""
    mode, note = capability(device.vendor, feature)
    if device.vendor == 'opnsense' and mode == 'auto' and feature not in ('logs',) and device.management_method != 'api':
        return 'guided', 'Sin API conectada: se configura a mano con la URL o la guía del SOC.'
    if device.vendor == 'unifi' and mode in ('auto', 'partial') and feature not in ('logs', 'policy') and \
            not _unifi_linked(device):
        return 'guided', 'Sin la consola UniFi vinculada: vincúlala en la ficha del equipo para que el SOC gestione la lista.'
    return mode, note


def device_rows(devices, feature):
    """Modo de una función en cada equipo, para mostrarlo junto a la función (lista del cliente)."""
    rows = []
    for device in devices:
        mode, note = for_device(device, feature)
        steps = GUIDES.get((device.vendor, feature), []) if mode == 'guided' else []
        rows.append({'device': device, 'mode': mode, 'label': MODES[mode], 'note': note, 'steps': steps})
    return rows


@login_required
@require_GET
def overview(request):
    """Tabla de capacidades por fabricante para el equipo del SOC."""
    rows = []
    for code, label in FEATURES:
        cells = []
        for vendor, _ in VENDORS:
            mode, note = capability(vendor, code)
            cells.append({'mode': mode, 'label': MODES[mode], 'note': note})
        rows.append({'feature': label, 'cells': cells})
    return render(request, 'vendor_capabilities.html', {'rows': rows, 'vendors': VENDORS, 'modes': MODES})

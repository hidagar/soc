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
        'dns': ('pending', 'La API oficial no ofrece listas de dominios propias por URL. Alternativa por comprobar: '
                           'que los equipos usen como DNS un resolvedor que sí las admita.'),
        'measure': ('partial', 'Sin contadores por política: indicio a partir de las detecciones de IPs de la lista.'),
        'policy': ('guided', 'Guía preparada; la política se aplica desde la consola UniFi.'),
    },
    'hillstone': {
        'logs': ('guided', 'Syslog configurado con la guía y comprobado al recibir registros.'),
        'blocklist': ('pending', 'Hoy solo hay lectura por REST (StoneOS). Comprobar si admite listas de IPs por URL o '
                                 'escritura de libretas de direcciones antes de ofrecerlo.'),
        'blocklist_out': ('pending', 'Igual que la de entrada.'),
        'preventive': ('pending', 'Igual que la de entrada.'),
        'dns': ('pending', 'Comprobar si StoneOS admite listas de dominios propias.'),
        'measure': ('pending', 'Comprobar contadores de política por REST.'),
        'policy': ('guided', 'Guía preparada; se aplica desde la consola del equipo.'),
    },
    'grandstream_gcc': {
        'logs': ('guided', 'Syslog configurado con la guía y comprobado al recibir registros.'),
        'blocklist': ('pending', 'GDMS no documenta escritura de configuración. Comprobar si el GCC admite listas de IPs '
                                 'por URL o importación.'),
        'blocklist_out': ('pending', 'Igual que la de entrada.'),
        'preventive': ('pending', 'Igual que la de entrada.'),
        'dns': ('pending', 'Comprobar si el GCC admite listas de dominios propias.'),
        'measure': ('pending', 'Sin contadores conocidos por API.'),
        'policy': ('guided', 'Guía preparada; se aplica desde la consola del equipo.'),
    },
}
UNKNOWN = ('pending', 'Fabricante sin adaptador: comprobar qué admite antes de ofrecerlo.')


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
        rows.append({'device': device, 'mode': mode, 'label': MODES[mode], 'note': note})
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

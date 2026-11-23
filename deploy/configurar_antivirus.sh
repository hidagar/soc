#!/usr/bin/env bash
# Antivirus de los adjuntos de las solicitudes: ClamAV en la propia VM.
#
#   sudo deploy/configurar_antivirus.sh            instala, arranca y prueba ClamAV
#   sudo deploy/configurar_antivirus.sh --ver      estado de los servicios, del socket y de las firmas
#   sudo deploy/configurar_antivirus.sh --probar   prueba con el archivo de prueba EICAR (inofensivo)
#   (añade --yes para no pedir confirmación)
#
# Instala clamav-daemon y clamav-freshclam (paquetes de la distribución), espera a la primera descarga de
# firmas, arranca el demonio y comprueba que detecta EICAR por el mismo socket que usa el portal
# (/run/clamav/clamd.ctl, o SOC_PORTAL_CLAMD_SOCKET). El trabajo «Antivirus de adjuntos» del portal empieza a
# analizar en el minuto siguiente, también los adjuntos que ya había.
#
# Requisitos: unos 1,5 GB de memoria libre para clamd y salida a Internet para las firmas
# (database.clamav.net). No cambia nada del portal ni de Nginx.
set -euo pipefail

SOCKET=${SOC_PORTAL_CLAMD_SOCKET:-/run/clamav/clamd.ctl}
DB=${SOC_CLAMAV_DB:-/var/lib/clamav}
MIN_MEMORY_MB=1500

die() { echo "ERROR: $*" >&2; exit 1; }
confirm() {
  [[ "${ASSUME_YES:-0}" == 1 ]] && return 0
  read -r -p "$1 [escribe 'si' para continuar]: " answer
  [[ "$answer" == si ]] || die "Cancelado."
}

# Envía bytes a clamd con INSTREAM (o VERSION) y muestra la respuesta. Sin dependencias: Python estándar.
clamd() {
  python3 - "$SOCKET" "$1" <<'PY'
import socket, struct, sys
path, mode = sys.argv[1], sys.argv[2]
conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
conn.settimeout(30)
conn.connect(path)
if mode == 'version':
    conn.sendall(b'zVERSION\0')
else:
    # Archivo de prueba EICAR, en dos partes para que este script no sea él mismo una «muestra».
    data = (r'X5O!P%@AP[4\PZX54(P^)7CC)7}$' + 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*').encode()
    conn.sendall(b'zINSTREAM\0' + struct.pack('!L', len(data)) + data + struct.pack('!L', 0))
reply = b''
while not reply.endswith(b'\0'):
    block = conn.recv(4096)
    if not block:
        break
    reply += block
print(reply.rstrip(b'\0\n').decode('utf-8', 'replace'))
PY
}

show() {
  for unit in clamav-freshclam clamav-daemon; do
    printf '%-18s %s\n' "$unit:" "$(systemctl is-active "$unit" 2>/dev/null || true)"
  done
  if [[ -S "$SOCKET" ]]; then
    echo "Socket: $SOCKET"
    echo "Versión y firmas: $(clamd version 2>/dev/null || echo 'sin respuesta')"
  else
    echo "Socket: $SOCKET no existe (ClamAV no está arrancado o no está instalado)."
  fi
}

probe() {
  [[ -S "$SOCKET" ]] || die "No existe $SOCKET: ClamAV no está arrancado."
  local reply
  reply=$(clamd eicar) || die "ClamAV no responde en $SOCKET."
  if [[ "$reply" == *FOUND ]]; then
    echo "Prueba correcta: ClamAV detecta el archivo de prueba EICAR ($reply)."
  else
    die "ClamAV respondió «$reply» en lugar de detectar EICAR."
  fi
}

ASSUME_YES=0
for arg in "$@"; do [[ "$arg" == --yes ]] && ASSUME_YES=1; done
case "${1:-}" in
  --ver) show; exit 0 ;;
  --probar) probe; exit 0 ;;
  --yes|"") ;;
  *) die "Opción desconocida: $1" ;;
esac
[[ $EUID -eq 0 ]] || die "Ejecutar con sudo."

available=$(awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo)
echo "Memoria disponible: ${available} MB (ClamAV necesita unos ${MIN_MEMORY_MB} MB)."
if (( available < MIN_MEMORY_MB )); then
  echo "AVISO: con poca memoria, clamd puede no arrancar o el sistema puede quedarse sin memoria."
fi
confirm "Se instalarán clamav-daemon y clamav-freshclam y se arrancarán. ¿Continuar?"

DEBIAN_FRONTEND=noninteractive apt-get install -y clamav-daemon clamav-freshclam
systemctl enable --now clamav-freshclam

echo "Esperando la primera descarga de firmas (puede tardar varios minutos)…"
for _ in $(seq 1 180); do
  ls "$DB"/main.c[lv]d "$DB"/daily.c[lv]d >/dev/null 2>&1 && break
  sleep 5
done
ls "$DB"/main.c[lv]d "$DB"/daily.c[lv]d >/dev/null 2>&1 \
  || die "No han llegado las firmas a $DB. Revisar «journalctl -u clamav-freshclam» (salida a database.clamav.net)."

systemctl enable clamav-daemon
systemctl restart clamav-daemon
echo "Esperando a que ClamAV cargue las firmas…"
for _ in $(seq 1 60); do
  [[ -S "$SOCKET" ]] && clamd version >/dev/null 2>&1 && break
  sleep 5
done
[[ -S "$SOCKET" ]] || die "clamd no ha creado $SOCKET. Revisar «journalctl -u clamav-daemon» (memoria)."

probe
show
echo "Hecho. El trabajo «Antivirus de adjuntos» del portal analizará los adjuntos en el próximo minuto."

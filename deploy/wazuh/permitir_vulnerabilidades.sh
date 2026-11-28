#!/usr/bin/env bash
# Vulnerabilidades de los equipos: permite al usuario de solo lectura del SOC leer el índice de vulnerabilidades
# de Wazuh (wazuh-states-vulnerabilities-*), y nada más.
#
#   sudo deploy/wazuh/permitir_vulnerabilidades.sh --aplicar   crea el rol de lectura y lo asigna al usuario del SOC
#   sudo deploy/wazuh/permitir_vulnerabilidades.sh --ver       muestra el permiso, el índice y la configuración del gestor
#   (añade --yes para no pedir confirmación)
#
# Usa el certificado de administración del indexador (como los scripts de seguridad de Wazuh) en esta VM. Del archivo
# del usuario de lectura (SOC_INDEXER_READER_FILE) solo se lee el nombre, nunca la contraseña. El rol creado,
# `soc_vulnerabilities_reader`, solo permite leer ese índice; no cambia los permisos que ya tuviera el usuario.
set -euo pipefail

CERTS=${SOC_INDEXER_CERTS:-/etc/wazuh-indexer/certs}
READER=${SOC_INDEXER_READER_FILE:-/etc/soc-portal/indexer-reader.json}
URL=https://127.0.0.1:9200
ROLE=soc_vulnerabilities_reader
OSSEC_CONF=${SOC_WAZUH_DIR:-/var/ossec}/etc/ossec.conf

die() { echo "ERROR: $*" >&2; exit 1; }
confirm() {
  [[ "${ASSUME_YES:-0}" == 1 ]] && return 0
  read -r -p "$1 [escribe 'si' para continuar]: " answer
  [[ "$answer" == si ]] || die "Cancelado."
}
api() { curl -sS --fail-with-body --cert "$CERTS/admin.pem" --key "$CERTS/admin-key.pem" --cacert "$CERTS/root-ca.pem" "$@"; }

reader_name() {
  [[ -r "$READER" ]] || die "No se puede leer $READER."
  python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["username"])' "$READER"
}

show() {
  [[ -r "$CERTS/admin.pem" ]] || die "No se encuentra el certificado de administración en $CERTS."
  echo "Usuario de lectura del SOC: $(reader_name)"
  if api "$URL/_plugins/_security/api/rolesmapping/$ROLE" 2>/dev/null | grep -q "\"$(reader_name)\""; then
    echo "Permiso de lectura de vulnerabilidades: concedido ($ROLE)."
  else
    echo "Permiso de lectura de vulnerabilidades: NO concedido."
  fi
  echo "Filas en el índice de vulnerabilidades: $(api "$URL/wazuh-states-vulnerabilities-*/_count" 2>/dev/null | python3 -I -c 'import json,sys; print(json.load(sys.stdin).get("count","?"))' 2>/dev/null || echo 'índice no disponible')"
  if [[ -r "$OSSEC_CONF" ]] && grep -A2 '<vulnerability-detection>' "$OSSEC_CONF" | grep -q '<enabled>yes</enabled>'; then
    echo "Detección de vulnerabilidades en el gestor: activa."
  else
    echo "Detección de vulnerabilidades en el gestor: no se ve activa en $OSSEC_CONF (sección <vulnerability-detection>)."
  fi
}

apply() {
  [[ -r "$CERTS/admin.pem" ]] || die "No se encuentra el certificado de administración en $CERTS."
  local user
  user=$(reader_name)
  [[ "$user" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || die "Nombre de usuario de lectura no válido."
  confirm "Se creará el rol $ROLE (solo lectura de wazuh-states-vulnerabilities-*) y se asignará a «$user». ¿Continuar?"
  api -X PUT "$URL/_plugins/_security/api/roles/$ROLE" -H 'Content-Type: application/json' \
    -d '{"index_permissions":[{"index_patterns":["wazuh-states-vulnerabilities-*"],"allowed_actions":["read"]}]}' >/dev/null
  api -X PUT "$URL/_plugins/_security/api/rolesmapping/$ROLE" -H 'Content-Type: application/json' \
    -d "{\"users\":[\"$user\"]}" >/dev/null
  echo "Hecho. El trabajo «Vulnerabilidades de los equipos» leerá el índice en su próxima pasada (cada hora)."
  show
}

ASSUME_YES=0
for arg in "$@"; do [[ "$arg" == --yes ]] && ASSUME_YES=1; done
case "${1:-}" in
  --ver) [[ $EUID -eq 0 ]] || die "Ejecutar con sudo."; show ;;
  --aplicar) [[ $EUID -eq 0 ]] || die "Ejecutar con sudo."; apply ;;
  *) die "Uso: $0 --aplicar | --ver [--yes]" ;;
esac

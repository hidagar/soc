#!/usr/bin/env bash
# Motor CrowdSec del SOC sin compartir señales con la comunidad (decisión del 28/11/2026).
#
#   sudo deploy/configurar_crowdsec_privado.sh --aplicar   deja de enviar señales y datos a CrowdSec y reinicia el motor
#   sudo deploy/configurar_crowdsec_privado.sh --ver       muestra qué está aplicado
#   (añade --yes para no pedir confirmación)
#
# Según la documentación oficial (configuración del Security Engine):
# - `api.server.online_client.sharing: false` deja de enviar al Central API las señales del motor (IPs que
#   detecta atacando a la VM). Se escribe en /etc/crowdsec/config.yaml.local, el archivo previsto para ajustes
#   locales, sin tocar config.yaml. La lista comunitaria se sigue recibiendo, en su versión reducida («Lite»),
#   y también las listas suscritas en la consola.
# - `cscli console disable --all` deja de enviar a la consola decisiones manuales, escenarios propios o
#   modificados y el contexto de las alertas.
set -euo pipefail

LOCAL=/etc/crowdsec/config.yaml.local
MARK='# soc-ib-red: sin compartir señales'

die() { echo "ERROR: $*" >&2; exit 1; }
confirm() {
  [[ "${ASSUME_YES:-0}" == 1 ]] && return 0
  read -r -p "$1 [escribe 'si' para continuar]: " answer
  [[ "$answer" == si ]] || die "Cancelado."
}

sharing() { cscli config show --key Config.API.Server.OnlineClient.Sharing 2>/dev/null || echo "desconocido"; }

show() {
  command -v cscli >/dev/null || die "No se encuentra cscli: ¿está instalado CrowdSec en esta VM?"
  echo "Compartir señales con el Central API (sharing): $(sharing)"
  if [[ -f "$LOCAL" ]] && grep -q "$MARK" "$LOCAL"; then echo "Ajuste local del SOC: aplicado ($LOCAL)."; else echo "Ajuste local del SOC: NO aplicado."; fi
  echo "Opciones de la consola:"
  cscli console status 2>/dev/null || echo "  (sin inscripción en la consola o no disponible)"
}

apply() {
  command -v cscli >/dev/null || die "No se encuentra cscli: ¿está instalado CrowdSec en esta VM?"
  if [[ -f "$LOCAL" ]] && ! grep -q "$MARK" "$LOCAL"; then
    die "$LOCAL ya existe con otros ajustes. Añade a mano dentro de api.server.online_client la línea «sharing: false» y vuelve a ejecutar --ver."
  fi
  confirm "El motor dejará de compartir señales con CrowdSec (la lista comunitaria pasa a la versión reducida) y se reiniciará. ¿Continuar?"
  if [[ ! -f "$LOCAL" ]]; then
    printf '%s\napi:\n  server:\n    online_client:\n      sharing: false\n' "$MARK" > "$LOCAL"
    chmod 0644 "$LOCAL"
  fi
  if ! crowdsec -t >/dev/null 2>&1; then
    crowdsec -t || true
    rm -f "$LOCAL"
    die "CrowdSec no acepta la configuración; se ha retirado el ajuste local."
  fi
  cscli console disable --all >/dev/null 2>&1 || echo "AVISO: no se pudieron desactivar las opciones de la consola (¿sin inscripción?)."
  systemctl restart crowdsec
  echo "Hecho. Compartir señales: $(sharing)."
  echo "Comprueba en unas horas que sigue llegando la lista comunitaria: sudo cscli decisions list --origin CAPI | head"
}

ASSUME_YES=0
for arg in "$@"; do [[ "$arg" == --yes ]] && ASSUME_YES=1; done
case "${1:-}" in
  --ver) show ;;
  --aplicar) [[ $EUID -eq 0 ]] || die "Ejecutar con sudo."; apply ;;
  *) die "Uso: $0 --aplicar | --ver [--yes]" ;;
esac

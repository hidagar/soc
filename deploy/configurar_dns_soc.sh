#!/usr/bin/env bash
# DNS del SOC para las sedes conectadas por la VPN de sedes (bloqueo de dominios para equipos sin listas DNS
# propias, como Grandstream GCC). Ver docs/integrations.md («DNS del SOC por la VPN de sedes»).
#
#   sudo deploy/configurar_dns_soc.sh --instalar   instala Unbound, su configuración base y el trabajo soc-dns
#   sudo deploy/configurar_dns_soc.sh --ver        muestra qué está aplicado
#   (añade --yes para no pedir confirmación)
#
# Unbound escucha SOLO en 10.255.251.1 (la VPN de sedes) y rechaza cualquier origen que el SOC no haya
# autorizado (las sedes de clientes con «DNS del SOC» activado). No registra las consultas resueltas; solo las
# bloqueadas (rpz-log), que el SOC cuenta sin guardarlas. Las reglas nft de la VPN las mantiene soc-vpn.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
CONF_DIR=/etc/unbound/unbound.conf.d
BASE=$CONF_DIR/soc-base.conf
ZONES=/var/lib/unbound/soc
ADDRESS=10.255.251.1

die() { echo "ERROR: $*" >&2; exit 1; }
confirm() {
  [[ "${ASSUME_YES:-0}" == 1 ]] && return 0
  read -r -p "$1 [escribe 'si' para continuar]: " answer
  [[ "$answer" == si ]] || die "Cancelado."
}

show() {
  if command -v unbound >/dev/null; then echo "Unbound: instalado ($(unbound -V 2>/dev/null | head -1))."; else echo "Unbound: NO instalado."; fi
  if [[ -f "$BASE" ]]; then echo "Configuración base del SOC: $BASE."; else echo "Configuración base del SOC: NO existe."; fi
  if systemctl is-active --quiet unbound 2>/dev/null; then echo "Servicio unbound: activo."; else echo "Servicio unbound: parado."; fi
  if systemctl is-active --quiet soc-dns.timer 2>/dev/null; then echo "Trabajo soc-dns: activo."; else echo "Trabajo soc-dns: no activo."; fi
  if command -v ss >/dev/null && ss -lnu | grep -q "$ADDRESS:53 "; then echo "Escucha en $ADDRESS:53: sí."; else echo "Escucha en $ADDRESS:53: no."; fi
  local zones
  zones=$(find "$ZONES" -name 'soc-c*.rpz' 2>/dev/null | wc -l)
  echo "Zonas de clientes: $zones."
}

install_all() {
  ip -4 addr show dev wg-soc 2>/dev/null | grep -q "inet $ADDRESS/" || die "La VPN de sedes (wg-soc, $ADDRESS) no está activa en esta VM."
  if ss -lnu 2>/dev/null | grep -q "$ADDRESS:53 " && ! systemctl is-active --quiet unbound; then
    die "Otro servicio ya escucha en $ADDRESS:53."
  fi
  confirm "Se instalará Unbound escuchando solo en $ADDRESS (VPN de sedes) y el trabajo soc-dns cada 15 minutos. ¿Continuar?"
  if ! command -v unbound >/dev/null; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y unbound
  fi
  install -d -m 0755 "$CONF_DIR"
  install -d -m 0755 -o unbound -g unbound "$ZONES" 2>/dev/null || install -d -m 0755 "$ZONES"
  local tmp
  tmp=$(mktemp)
  cat > "$tmp" <<CONF
# DNS del SOC (deploy/configurar_dns_soc.sh). Las sedes autorizadas y sus zonas están en soc-qfeeds.conf.
server:
    interface: $ADDRESS
    ip-freebind: yes
    access-control: 0.0.0.0/0 refuse
    access-control: ::/0 refuse
    hide-identity: yes
    hide-version: yes
    qname-minimisation: yes
    log-queries: no
    log-replies: no
    use-syslog: yes
    verbosity: 1
CONF
  [[ -f "$BASE" ]] && cp -p "$BASE" "$BASE.bak.$(date +%Y%m%d-%H%M%S)"
  install -m 0644 "$tmp" "$BASE"
  rm -f "$tmp"
  [[ -f "$CONF_DIR/soc-qfeeds.conf" ]] || echo '# DNS del SOC: ningún cliente activado todavía.' > "$CONF_DIR/soc-qfeeds.conf"
  if ! unbound-checkconf >/dev/null; then
    unbound-checkconf || true
    rm -f "$BASE"
    die "Unbound no acepta la configuración; se ha retirado la base del SOC."
  fi
  systemctl enable --now unbound
  systemctl restart unbound
  install -m 0644 "$HERE/systemd/soc-dns.service" /etc/systemd/system/soc-dns.service
  install -m 0644 "$HERE/systemd/soc-dns.timer" /etc/systemd/system/soc-dns.timer
  systemctl daemon-reload
  systemctl enable --now soc-dns.timer
  systemctl start soc-dns.service || true
  if command -v dig >/dev/null; then
    echo "Prueba desde la propia VM (debe responder REFUSED: la VM no es una sede autorizada):"
    dig +short +time=3 +tries=1 @"$ADDRESS" example.com || true
  fi
  echo
  echo "Hecho. Activa «DNS del SOC» en la lista de bloqueo del cliente y configura su firewall con la guía del portal."
}

ASSUME_YES=0
for arg in "$@"; do [[ "$arg" == --yes ]] && ASSUME_YES=1; done
case "${1:-}" in
  --ver) show ;;
  --instalar) [[ $EUID -eq 0 ]] || die "Ejecutar con sudo."; install_all ;;
  *) die "Uso: $0 --instalar | --ver [--yes]" ;;
esac

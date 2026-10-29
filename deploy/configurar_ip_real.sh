#!/usr/bin/env bash
# IP real de los visitantes cuando el portal se publica a través de otro proxy (p. ej. el Nginx público).
#
#   sudo deploy/configurar_ip_real.sh 172.20.10.112 [OTRA_IP ...]   confiar en X-Forwarded-For solo de esos proxys
#   sudo deploy/configurar_ip_real.sh --quitar                       volver a la configuración anterior
#   sudo deploy/configurar_ip_real.sh --ver                          mostrar la configuración actual
#
# Escribe /etc/nginx/conf.d/soc-real-ip.conf, comprueba con `nginx -t` y recarga Nginx. Si la
# comprobación falla, restaura el archivo anterior y no recarga. No toca el portal ni portal.env:
# el Nginx local ya pasa a Django la IP corregida en X-Real-IP.
#
# El proxy público debe enviar `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`.
# La cabecera se ignora si llega desde cualquier otra IP, así que no se puede falsear desde internet.
set -euo pipefail

CONF=/etc/nginx/conf.d/soc-real-ip.conf
die() { echo "ERROR: $*" >&2; exit 1; }

[[ $# -ge 1 ]] || die "Indica la IP del proxy público, --quitar o --ver."
if [[ "$1" == --ver ]]; then
  [[ -f "$CONF" ]] && cat "$CONF" || echo "Sin configurar: Nginx usa la IP de conexión."
  exit 0
fi
[[ $EUID -eq 0 ]] || die "Ejecútalo con sudo."
command -v nginx >/dev/null || die "Nginx no está instalado."

BACKUP=$(mktemp)
trap 'rm -f "$BACKUP"' EXIT
had_conf=0
if [[ -f "$CONF" ]]; then cp -p "$CONF" "$BACKUP"; had_conf=1; fi

restore() {
  if [[ $had_conf == 1 ]]; then cp -p "$BACKUP" "$CONF"; else rm -f "$CONF"; fi
}

if [[ "$1" == --quitar ]]; then
  rm -f "$CONF"
else
  proxies=()
  for value in "$@"; do
    # Solo direcciones IP o redes privadas concretas: nunca 0.0.0.0/0 ni direcciones públicas.
    checked=$(python3 -I -c '
import ipaddress, sys
net = ipaddress.ip_network(sys.argv[1], strict=False)
if not net.is_private or net.prefixlen < (24 if net.version == 4 else 64):
    raise SystemExit(1)
print(net if net.num_addresses > 1 else net.network_address)
' "$value") || die "«$value» no es una IP o red privada válida (como mucho /24): el proxy debe estar en la red interna."
    proxies+=("$checked")
  done
  {
    echo "# Generado por deploy/configurar_ip_real.sh. IP real del visitante:"
    echo "# X-Forwarded-For solo se acepta de estos proxys; de cualquier otra IP se ignora."
    for proxy in "${proxies[@]}"; do echo "set_real_ip_from $proxy;"; done
    echo "real_ip_header X-Forwarded-For;"
    echo "real_ip_recursive on;"
  } > "$CONF"
  chmod 0644 "$CONF"
fi

if ! nginx -t 2>/dev/null; then
  restore
  nginx -t || true
  die "Nginx no acepta la configuración; se ha restaurado la anterior y no se ha recargado."
fi
systemctl reload nginx
if [[ -f "$CONF" ]]; then
  echo "Configurado y Nginx recargado. Proxys de confianza: $(grep -c '^set_real_ip_from' "$CONF")."
  echo "Comprueba en unos minutos que aparecen IP públicas: sudo tail -n 20 /var/log/nginx/access.log"
else
  echo "Configuración de IP real retirada y Nginx recargado."
fi

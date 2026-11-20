#!/usr/bin/env bash
# Acceso al Wazuh del SOC (/wazuh/) también desde el bloque de Nginx del portal por IP.
#
#   sudo deploy/configurar_wazuh_nginx.sh          aplica el cambio
#   sudo deploy/configurar_wazuh_nginx.sh --ver    muestra qué está aplicado (sin secretos)
#   (añade --yes para no pedir confirmación)
#
# Las rutas de Wazuh (comprobación con el portal, /wazuh, /wazuh/ y la vuelta al login) estaban solo en el
# bloque del nombre público. Este script:
# 1. Las saca tal cual, con su secreto interno y sin mostrarlo, a /etc/nginx/snippets/soc-wazuh.conf (0600).
# 2. Las sustituye en su bloque original por un `include` de ese archivo.
# 3. Añade el mismo `include` al bloque del portal por IP (sites-available/soc-portal), que no las tenía.
# Guarda copia de los archivos que toca, comprueba `nginx -t` y, si falla, lo restaura todo sin recargar.
# Si el archivo común ya existe, solo añade el `include` donde falte.
set -euo pipefail

NGINX=${SOC_NGINX_DIR:-/etc/nginx}
SNIPPET=$NGINX/snippets/soc-wazuh.conf
IP_SITE=$NGINX/sites-available/soc-portal
BACKUPS=${SOC_BACKUP_DIR:-/var/backups/soc-nginx}
INCLUDE="    include $SNIPPET;"

die() { echo "ERROR: $*" >&2; exit 1; }
confirm() {
  [[ "${ASSUME_YES:-0}" == 1 ]] && return 0
  read -r -p "$1 [escribe 'si' para continuar]: " answer
  [[ "$answer" == si ]] || die "Cancelado."
}

# Archivos de sitio activos (sigue los enlaces de sites-enabled) y conf.d, sin el archivo común.
site_files() {
  local f
  for f in "$NGINX"/sites-enabled/* "$NGINX"/conf.d/*.conf; do
    [[ -e "$f" ]] || continue
    readlink -f "$f"
  done | sort -u | grep -vxF "$(readlink -f "$SNIPPET" 2>/dev/null || echo "$SNIPPET")" || true
}

show() {
  local f
  if [[ -f "$SNIPPET" ]]; then
    echo "Archivo común: $SNIPPET ($(stat -c %a "$SNIPPET"))."
    grep -qi 'X-SOC-Wazuh-Key' "$SNIPPET" && echo "  Contiene el secreto interno (no se muestra)." \
      || echo "  AVISO: no contiene la cabecera X-SOC-Wazuh-Key."
  else
    echo "Archivo común: no existe."
  fi
  while read -r f; do
    [[ -n "$f" ]] || continue
    if grep -qF "include $SNIPPET;" "$f"; then echo "$f: incluye las rutas de Wazuh."
    elif grep -q 'location /wazuh/' "$f"; then echo "$f: tiene las rutas de Wazuh escritas dentro."
    else echo "$f: SIN rutas de Wazuh."; fi
  done < <(site_files)
}

case "${1:-}" in
  --ver) show; exit 0 ;;
  --yes|"") ;;
  *) die "Opción desconocida: $1" ;;
esac
[[ " $* " == *" --yes "* ]] && ASSUME_YES=1
command -v nginx >/dev/null || die "Nginx no está instalado."
[[ -f "$IP_SITE" ]] || die "No existe $IP_SITE."

SOURCE=""
if [[ ! -f "$SNIPPET" ]]; then
  mapfile -t sites < <(site_files)
  mapfile -t found < <(grep -l 'location /wazuh/' "${sites[@]}" 2>/dev/null || true)
  [[ ${#found[@]} -eq 1 ]] || die "Se esperaba un único sitio con 'location /wazuh/' y hay ${#found[@]}. Revisar a mano."
  SOURCE=${found[0]}
  [[ "$SOURCE" != "$(readlink -f "$IP_SITE")" ]] \
    || die "Las rutas de Wazuh ya están en $IP_SITE: si el bloque por IP está en el mismo archivo, revisar a mano."
fi
if [[ -z "$SOURCE" ]] && grep -qF "include $SNIPPET;" "$IP_SITE"; then
  echo "Ya está aplicado."; show; exit 0
fi

echo "Se van a modificar:"
[[ -n "$SOURCE" ]] && echo "  - $SOURCE: sus rutas de Wazuh pasan a $SNIPPET"
grep -qF "include $SNIPPET;" "$IP_SITE" || echo "  - $IP_SITE: se añaden las rutas de Wazuh"
confirm "¿Continuar?"

stamp=$(date +%Y%m%d-%H%M%S)
backup=$BACKUPS/$stamp
umask 077
mkdir -p "$backup"
touched=()
save() { cp -p "$1" "$backup/$(echo "$1" | tr / _)"; touched+=("$1"); }
restore() {
  local f
  for f in "${touched[@]}"; do cp -p "$backup/$(echo "$f" | tr / _)" "$f"; done
  [[ -n "$SOURCE" ]] && rm -f "$SNIPPET"
}

if [[ -n "$SOURCE" ]]; then
  save "$SOURCE"
  tmp=$(mktemp "$backup/snippet.XXXXXX")
  # Desde la comprobación interna hasta el cierre de la vuelta al login, sin cambiar nada.
  awk '/location = \/_soc_wazuh_auth/ {on=1}
       on {print}
       on && /location @soc_wazuh_login/ {last=1}
       on && last && /^[[:space:]]*}[[:space:]]*$/ {exit}' "$SOURCE" > "$tmp"
  for needed in 'location = /_soc_wazuh_auth' 'location /wazuh/' 'auth_request /_soc_wazuh_auth;' \
                'location @soc_wazuh_login' 'X-SOC-Wazuh-Key'; do
    grep -qiF "$needed" "$tmp" || { rm -f "$tmp"; die "No se encontró '$needed' en las rutas de Wazuh de $SOURCE. Revisar a mano."; }
  done
  start=$(grep -n 'location = /_soc_wazuh_auth' "$SOURCE" | head -1 | cut -d: -f1)
  lines=$(wc -l < "$tmp")
  [[ $(sed -n "${start},$((start + lines - 1))p" "$SOURCE" | cmp -s - "$tmp"; echo $?) == 0 ]] \
    || { rm -f "$tmp"; die "Las rutas de Wazuh de $SOURCE no son contiguas. Revisar a mano."; }
  mkdir -p "$(dirname "$SNIPPET")"
  { echo "# Rutas del Wazuh del SOC: comprobación con el portal y proxy al Wazuh Dashboard local."
    echo "# Contiene el secreto interno X-SOC-Wazuh-Key: no copiar fuera del servidor. Plantilla: deploy/nginx/soc-wazuh.conf.example"
    sed 's/^    //' "$tmp"; } > "$SNIPPET"
  chmod 600 "$SNIPPET"
  rm -f "$tmp"
  sed -i "${start},$((start + lines - 1))d" "$SOURCE"
  sed -i "$((start - 1))a\\$INCLUDE" "$SOURCE"
fi

if ! grep -qF "include $SNIPPET;" "$IP_SITE"; then
  save "$IP_SITE"
  # Antes de la primera «location»: /wazuh/ gana a «location /» por ser un prefijo más largo.
  first=$(grep -n '^[[:space:]]*location' "$IP_SITE" | head -1 | cut -d: -f1)
  [[ -n "$first" ]] || { restore; die "No se encontró ninguna 'location' en $IP_SITE."; }
  sed -i "${first}i\\$INCLUDE" "$IP_SITE"
fi

if ! nginx -t 2>/dev/null; then
  nginx -t || true
  restore
  die "Nginx no acepta la configuración; se ha restaurado la anterior. Copia en $backup."
fi
systemctl reload nginx
echo "Hecho. Copia de lo anterior en $backup (contiene el secreto: solo root)."
show

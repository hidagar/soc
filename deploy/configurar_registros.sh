#!/usr/bin/env bash
# Registros sin secretos de URL y gunicorn configurado desde el código (instalaciones anteriores a esta versión).
#
#   sudo deploy/configurar_registros.sh            aplica los dos cambios
#   sudo deploy/configurar_registros.sh --ver      muestra qué está aplicado
#   sudo deploy/configurar_registros.sh --quitar   vuelve a la configuración anterior
#   (añade --yes para no pedir confirmación)
#
# 1. Nginx: instala /etc/nginx/conf.d/soc-log-redaction.conf (formato «soc_redacted», que oculta los
#    tokens de los enlaces de informes, las listas de bloqueo y las invitaciones) y lo usa en el servidor
#    del portal. Comprueba `nginx -t` y, si falla, restaura lo anterior sin recargar.
# 2. Portal: arranca gunicorn con deploy/gunicorn.conf.py (sin registro de accesos, que guardaba esas
#    URL completas en el diario). Es un archivo de systemd adicional; la unidad no se modifica. Reinicia
#    el portal y comprueba que responde; si no, deshace el cambio.
#
# No borra los registros antiguos: siguen conteniendo esas URL hasta que roten (véase docs/security.md).
set -euo pipefail

APP=${SOC_APP:-/srv/soc-portal}
NGINX=${SOC_NGINX_DIR:-/etc/nginx}
UNITS=${SOC_SYSTEMD_DIR:-/etc/systemd/system}
SITE=$NGINX/sites-available/soc-portal
SNIPPET=$NGINX/conf.d/soc-log-redaction.conf
DROPIN=$UNITS/soc-portal.service.d/gunicorn.conf
LOG_LINE='    access_log /var/log/nginx/access.log soc_redacted;'

die() { echo "ERROR: $*" >&2; exit 1; }
confirm() {
  [[ "${ASSUME_YES:-0}" == 1 ]] && return 0
  read -r -p "$1 [escribe 'si' para continuar]: " answer
  [[ "$answer" == si ]] || die "Cancelado."
}

portal_ok() {
  # Igual que deploy/update.sh: el login responde 200 a través de gunicorn.
  local host status
  host=$(/opt/soc-portal-venv/bin/python -I "$APP/deploy/envfile.py" --get SOC_PORTAL_ALLOWED_HOSTS /etc/soc-portal/portal.env 2>/dev/null \
         | cut -d, -f1 | tr -d '[:space:]' || true)
  for _ in $(seq 1 15); do
    status=$(curl -s -o /dev/null -w '%{http_code}' -H "Host: ${host:-127.0.0.1}" -H 'X-Forwarded-Proto: https' \
      http://127.0.0.1:8000/login/ || true)
    [[ "$status" == 200 ]] && return 0
    sleep 2
  done
  return 1
}

show() {
  [[ -f "$SNIPPET" ]] && echo "Nginx: formato soc_redacted instalado." || echo "Nginx: formato soc_redacted NO instalado."
  grep -q 'soc_redacted;' "$SITE" 2>/dev/null && echo "Nginx: el portal registra con soc_redacted." \
    || echo "Nginx: el portal registra con el formato por defecto (URL completas)."
  [[ -f "$DROPIN" ]] && echo "Portal: gunicorn usa $APP/deploy/gunicorn.conf.py." \
    || echo "Portal: gunicorn usa las opciones de la unidad (con registro de accesos)."
}

reload_nginx() {
  if ! nginx -t 2>/dev/null; then
    nginx -t || true
    return 1
  fi
  systemctl reload nginx
}

restart_portal() {
  systemctl daemon-reload
  systemctl restart soc-portal
  portal_ok
}

MODE=apply
for arg in "$@"; do
  case "$arg" in
    --ver) MODE=show ;;
    --quitar) MODE=remove ;;
    --yes) ASSUME_YES=1 ;;
    *) die "Opción desconocida: $arg" ;;
  esac
done
if [[ "$MODE" == show ]]; then show; exit 0; fi
[[ $EUID -eq 0 || -n "${SOC_NGINX_DIR:-}" ]] || die "Ejecútalo con sudo."
[[ -f "$SITE" ]] || die "No se encuentra $SITE (servidor Nginx del portal)."

BACKUP=$(mktemp -d)
trap 'rm -rf "$BACKUP"' EXIT
cp -p "$SITE" "$BACKUP/site"
[[ -f "$SNIPPET" ]] && cp -p "$SNIPPET" "$BACKUP/snippet"
[[ -f "$DROPIN" ]] && cp -p "$DROPIN" "$BACKUP/dropin"

restore_nginx() {
  cp -p "$BACKUP/site" "$SITE"
  if [[ -f "$BACKUP/snippet" ]]; then cp -p "$BACKUP/snippet" "$SNIPPET"; else rm -f "$SNIPPET"; fi
}

if [[ "$MODE" == remove ]]; then
  confirm "Se volverá al registro con URL completas y se reiniciará el portal. ¿Continuar?"
  sed -i '/access_log .* soc_redacted;/d' "$SITE"
  rm -f "$SNIPPET"
  reload_nginx || { restore_nginx; die "Nginx no acepta la configuración; se ha restaurado la anterior."; }
  rm -f "$DROPIN"
  rmdir "$(dirname "$DROPIN")" 2>/dev/null || true
  restart_portal || die "El portal no responde tras el cambio. Revisa: journalctl -u soc-portal -n 80"
  echo "Configuración anterior restaurada."
  exit 0
fi

[[ -f "$APP/deploy/gunicorn.conf.py" && -f "$APP/deploy/nginx/soc-log-redaction.conf" ]] \
  || die "Falta deploy/gunicorn.conf.py o deploy/nginx/ en $APP: despliega primero esta versión con update.sh."
grep -q 'server_name' "$SITE" || die "No se encuentra server_name en $SITE."
confirm "Se recargará Nginx y se reiniciará el portal (unos segundos sin servicio). ¿Continuar?"

# 1. Nginx. Cada paso comprueba su resultado: dentro de `función || …` bash no aplica `set -e`.
apply_nginx() {
  install -m 0644 "$APP/deploy/nginx/soc-log-redaction.conf" "$SNIPPET" || return 1
  if ! grep -q 'soc_redacted;' "$SITE"; then
    # Tras el primer server_name: el servidor del portal que crea install.sh.
    sed -i "0,/^[[:space:]]*server_name .*;/s||&\n$LOG_LINE|" "$SITE" || return 1
    grep -q 'soc_redacted;' "$SITE" || return 1
  fi
  reload_nginx
}
apply_nginx || { restore_nginx; die "Nginx no acepta la configuración; se ha restaurado la anterior y no se ha recargado."; }
echo "Nginx: el registro de accesos oculta los secretos de URL."

# 2. Portal
install -d -m 0755 "$(dirname "$DROPIN")"
cat > "$DROPIN" <<EOF
# Generado por deploy/configurar_registros.sh: opciones de gunicorn en el código desplegado.
[Service]
ExecStart=
ExecStart=/opt/soc-portal-venv/bin/gunicorn -c $APP/deploy/gunicorn.conf.py socportal.wsgi:application
EOF
chmod 0644 "$DROPIN"
if ! restart_portal; then
  if [[ -f "$BACKUP/dropin" ]]; then cp -p "$BACKUP/dropin" "$DROPIN"; else rm -f "$DROPIN"; rmdir "$(dirname "$DROPIN")" 2>/dev/null || true; fi
  restart_portal || true
  die "El portal no respondía con la configuración nueva; se ha vuelto a la anterior. Revisa: journalctl -u soc-portal -n 80"
fi
echo "Portal: gunicorn arranca con $APP/deploy/gunicorn.conf.py (sin registro de accesos)."
show

#!/usr/bin/env bash
# Actualiza una instalación existente del portal desde el checkout Git.
#
#   sudo deploy/update.sh                   despliega el commit actual del checkout
#   sudo deploy/update.sh --rollback DIR    restaura código y base de una copia previa
#
# Sigue docs/deployment.md: copia consistente, escritores parados, código del
# commit (no del árbol de trabajo), migración, estáticos y comprobación. No
# instala unidades systemd ni toca Wazuh, el motor HTTPS privado ni secretos.
set -Eeuo pipefail

APP=/srv/soc-portal
VENV=/opt/soc-portal-venv
ENV_FILE=/etc/soc-portal/portal.env
DB="$APP/data/portal.sqlite3"
BACKUPS=/var/backups/soc-portal
LOG=/var/log/soc-portal-deploy.log
CODE_ITEMS=(manage.py requirements.txt core socportal templates static deploy)
# Servicios que el script nunca detiene: portal (se gestiona aparte) y motor privado 3B.
KEEP_RUNNING='^(soc-portal|soc-wazuh-https|soc-wazuh-https-db)\.service$'

log() { printf '%s %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG" >&2; }
die() { log "ERROR: $*"; exit 1; }

confirm() {
  [[ "${ASSUME_YES:-0}" == 1 ]] && return 0
  read -r -p "$1 [escribe 'si' para continuar]: " answer
  [[ "$answer" == si ]] || die "Cancelado por el operador."
}

as_portal() {
  # Como systemd (EnvironmentFile): root lee el entorno protegido y lo pasa al
  # proceso de socportal, que no necesita permiso de lectura sobre el archivo.
  # shellcheck source=/dev/null
  ( set -a; . "$ENV_FILE"; set +a; cd "$APP"; runuser -u socportal -- /bin/sh -c "$*" )
}

stop_writers() {
  # Guarda qué timers estaban activos para volver a dejar exactamente esos.
  systemctl list-units --type=timer --state=active --no-legend --plain 'soc-*' \
    | awk '{print $1}' > "$1/timers-active.txt"
  if [[ ! -s "$1/timers-active.txt" ]]; then
    log "AVISO: no hay timers soc-* activos. Si un intento anterior los paró, no se reactivarán solos:"
    log "  revisa timers-active.txt de la copia de ese intento en $BACKUPS."
  fi
  log "Parando timers: $(tr '\n' ' ' < "$1/timers-active.txt")"
  [[ -s "$1/timers-active.txt" ]] && xargs -r systemctl stop < "$1/timers-active.txt"
  # Esperar a que terminen los trabajos en curso en lugar de matarlos (máx. 180 s + margen).
  local waited=0 running
  while :; do
    running=$(systemctl list-units --type=service --state=activating,deactivating --no-legend --plain 'soc-*' \
      | awk '{print $1}' | grep -Ev "$KEEP_RUNNING" || true)
    [[ -z "$running" ]] && break
    (( waited >= 240 )) && die "Siguen en ejecución tras 240 s: $running. Timers parados; revisa y vuelve a lanzar."
    (( waited % 30 == 0 )) && log "Esperando a que terminen: $(echo "$running" | tr '\n' ' ')"
    sleep 5; waited=$((waited + 5))
  done
  log "Parando soc-portal"
  systemctl stop soc-portal
}

start_writers() {
  log "Arrancando soc-portal"
  systemctl start soc-portal
  if [[ -s "$1/timers-active.txt" ]]; then
    log "Reactivando timers"
    xargs -r systemctl start < "$1/timers-active.txt"
  fi
}

backup() {
  local dir=$1
  log "Copia de seguridad en $dir"
  # API backup de SQLite: copia consistente aunque exista journal/WAL.
  "$VENV/bin/python" - "$DB" "$dir/portal.sqlite3" <<'EOF'
import sqlite3, sys
from contextlib import closing
with closing(sqlite3.connect(f'file:{sys.argv[1]}?mode=ro', uri=True)) as src, closing(sqlite3.connect(sys.argv[2])) as dst:
    src.backup(dst)
    if dst.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
        raise SystemExit('La copia de la base no supera integrity_check')
EOF
  tar -C "$APP" -czf "$dir/code.tar.gz" "${CODE_ITEMS[@]}"
  cp -a "$APP/.deployed-commit" "$dir/" 2>/dev/null || true
  chmod -R go-rwx "$dir"
}

replace_code() {
  local source=$1
  for item in "${CODE_ITEMS[@]}"; do
    rm -rf "${APP:?}/$item"
    cp -a "$source/$item" "$APP/"
  done
  find "$APP" -name __pycache__ -prune -exec rm -rf {} +
  chown -R root:root "${CODE_ITEMS[@]/#/$APP/}"
  find "${CODE_ITEMS[@]/#/$APP/}" -type d -exec chmod 0755 {} +
  find "${CODE_ITEMS[@]/#/$APP/}" -type f -exec chmod go-w,a+r {} +
  chmod 0755 "$APP/deploy/"*.sh
}

health_check() {
  local host status
  host=$(grep -m1 '^SOC_PORTAL_ALLOWED_HOSTS=' "$ENV_FILE" | cut -d= -f2- | cut -d, -f1)
  for _ in $(seq 1 15); do
    status=$(curl -s -o /dev/null -w '%{http_code}' -H "Host: ${host:-127.0.0.1}" \
      -H 'X-Forwarded-Proto: https' http://127.0.0.1:8000/login/ || true)
    [[ "$status" == 200 ]] && { log "Portal responde (login HTTP 200)"; return 0; }
    sleep 2
  done
  die "El portal no responde correctamente (último HTTP: ${status:-sin respuesta}). Revisa: journalctl -u soc-portal -n 80"
}

on_error() {
  # Las tuberías ejecutan en subshell; informar solo desde el proceso principal.
  (( BASH_SUBSHELL > 0 )) && return
  [[ -n "${ERROR_REPORTED:-}" ]] && return; ERROR_REPORTED=1
  log "La actualización se ha detenido en la línea $1."
  if [[ -n "${BACKUP_DIR:-}" && -f "$BACKUP_DIR/code.tar.gz" ]]; then
    log "Servicios y timers pueden estar parados. Para volver a la versión anterior:"
    log "  sudo $0 --rollback $BACKUP_DIR"
  fi
}
trap 'on_error $LINENO' ERR

[[ "$(id -u)" -eq 0 ]] || { echo "Ejecutar como root (sudo)." >&2; exit 1; }
[[ -d "$APP" && -x "$VENV/bin/python" && -f "$ENV_FILE" ]] || { echo "No se encuentra una instalación en $APP." >&2; exit 1; }
touch "$LOG"; chmod 0600 "$LOG"

MODE=deploy
while (( $# )); do
  case "$1" in
    --yes) ASSUME_YES=1 ;;
    --rollback) MODE=rollback; ROLLBACK_DIR=${2:-}; shift ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "Opción desconocida: $1" >&2; exit 1 ;;
  esac
  shift
done

# Una sola ejecución a la vez.
exec 9>/run/soc-portal-update.lock
flock -n 9 || die "Ya hay otra actualización en curso."

if [[ "$MODE" == rollback ]]; then
  [[ -f "$ROLLBACK_DIR/code.tar.gz" && -f "$ROLLBACK_DIR/portal.sqlite3" ]] || die "Copia no válida: $ROLLBACK_DIR"
  log "REVERSIÓN a la copia $ROLLBACK_DIR (commit $(cat "$ROLLBACK_DIR/.deployed-commit" 2>/dev/null || echo desconocido))"
  echo "Se perderán los datos del portal escritos después de esa copia."
  confirm "¿Restaurar código y base de datos?"
  BACKUP_DIR="$BACKUPS/$(date +%Y%m%d-%H%M%S)-antes-de-reversion"
  install -d -m 0700 "$BACKUP_DIR"
  stop_writers "$BACKUP_DIR"
  backup "$BACKUP_DIR"
  restore=$(mktemp -d /var/tmp/soc-rollback.XXXXXX)
  tar -C "$restore" -xzf "$ROLLBACK_DIR/code.tar.gz"
  replace_code "$restore"; rm -rf "$restore"
  for suffix in -wal -shm -journal; do
    [[ -e "$DB$suffix" ]] && mv "$DB$suffix" "$BACKUP_DIR/portal.sqlite3$suffix.descartado"
  done
  install -o socportal -g socportal -m 0600 "$ROLLBACK_DIR/portal.sqlite3" "$DB"
  cp -a "$ROLLBACK_DIR/.deployed-commit" "$APP/" 2>/dev/null || rm -f "$APP/.deployed-commit"
  "$VENV/bin/python" -m pip install --disable-pip-version-check -q --requirement "$APP/requirements.txt"
  as_portal "$VENV/bin/python manage.py collectstatic --noinput --verbosity 0"
  # Usa los timers activos antes de la actualización que se revierte.
  cp "$ROLLBACK_DIR/timers-active.txt" "$BACKUP_DIR/timers-active.txt"
  start_writers "$BACKUP_DIR"
  health_check
  log "Reversión completada. Copia del estado previo a la reversión: $BACKUP_DIR"
  exit 0
fi

# --- Despliegue ---------------------------------------------------------------
REPO=$(cd "$(dirname "$0")/.." && pwd)
git_repo() { git -c safe.directory="$REPO" -C "$REPO" "$@"; }
git_repo rev-parse --git-dir >/dev/null 2>&1 || die "$REPO no es un checkout Git."
[[ -z "$(git_repo status --porcelain --untracked-files=no)" ]] || die "El checkout tiene cambios sin commit. Haz commit o descártalos antes de desplegar."

COMMIT=$(git_repo rev-parse HEAD)
BRANCH=$(git_repo rev-parse --abbrev-ref HEAD)
CURRENT=$(cat "$APP/.deployed-commit" 2>/dev/null || echo desconocido)
[[ "$BRANCH" == main ]] || log "AVISO: la rama actual es '$BRANCH', no 'main'."
# root no tiene las credenciales de GitHub: consultar el remoto como dueño del checkout.
REMOTE=$(runuser -u "$(stat -c %U "$REPO")" -- env GIT_TERMINAL_PROMPT=0 GIT_SSH_COMMAND='ssh -o BatchMode=yes' \
  timeout 30 git -C "$REPO" ls-remote origin "refs/heads/$BRANCH" 2>/dev/null | cut -f1 || true)
if [[ -z "$REMOTE" ]]; then
  log "AVISO: no se ha podido consultar origin/$BRANCH; se despliega el commit local."
elif [[ "$REMOTE" != "$COMMIT" ]]; then
  log "AVISO: el checkout no coincide con origin/$BRANCH. ¿Falta 'git pull'?"
fi

# El código se toma del commit, nunca de archivos sueltos del árbol de trabajo.
STAGE=$(mktemp -d /var/tmp/soc-release.XXXXXX)
trap 'rm -rf "$STAGE"' EXIT
git_repo archive "$COMMIT" "${CODE_ITEMS[@]}" | tar -x -C "$STAGE"
chmod -R a+rX "$STAGE"
install -d -o socportal -g socportal -m 0700 "$STAGE/data"  # base vacía solo para las comprobaciones

log "Comprobando el commit ${COMMIT:0:12} en un directorio temporal"
runuser -u socportal -- env -i PATH=/usr/bin:/bin SOC_PORTAL_DEBUG=1 HOME=/nonexistent \
  /bin/sh -c "cd $STAGE && $VENV/bin/python manage.py check -v 0 && $VENV/bin/python manage.py makemigrations --check --dry-run -v 0" \
  || die "El commit no supera manage.py check / makemigrations --check. No se ha tocado producción."

NEW_MIGRATIONS=$(comm -13 <(ls "$APP/core/migrations" | sort) <(ls "$STAGE/core/migrations" | sort) | grep '\.py$' || true)
REQS_CHANGED=0; cmp -s "$APP/requirements.txt" "$STAGE/requirements.txt" || REQS_CHANGED=1
UNITS_CHANGED=$(for unit in "$STAGE"/deploy/systemd/* "$STAGE"/deploy/*.service "$STAGE"/deploy/*.timer; do
  installed=/etc/systemd/system/$(basename "$unit")
  [[ -f "$installed" ]] && ! cmp -s "$unit" "$installed" && basename "$unit"
done || true)

echo
echo "  Versión instalada : $CURRENT"
echo "  Versión a instalar: $COMMIT ($BRANCH)"
if [[ "$CURRENT" =~ ^[0-9a-f]{40}$ ]] && git_repo cat-file -e "$CURRENT" 2>/dev/null; then
  echo "  Commits nuevos:"; git_repo log --oneline "$CURRENT..$COMMIT" | sed 's/^/    /'
fi
echo "  Migraciones nuevas: ${NEW_MIGRATIONS:-ninguna}" | tr '\n' ' '; echo
echo "  Dependencias      : $([[ $REQS_CHANGED == 1 ]] && echo 'cambian (se instalarán)' || echo 'sin cambios')"
if [[ -n "$UNITS_CHANGED" ]]; then
  echo "  AVISO: unidades systemd distintas de las instaladas (NO se modifican):"
  echo "$UNITS_CHANGED" | sed 's/^/    /'
fi
echo
confirm "Se pararán el portal y los timers soc-* durante la actualización. ¿Continuar?"

log "Desplegando $COMMIT sobre $CURRENT"
BACKUP_DIR="$BACKUPS/$(date +%Y%m%d-%H%M%S)-${CURRENT:0:12}"
install -d -m 0700 "$BACKUPS" "$BACKUP_DIR"
stop_writers "$BACKUP_DIR"
backup "$BACKUP_DIR"

replace_code "$STAGE"
if [[ $REQS_CHANGED == 1 ]]; then
  log "Instalando dependencias"
  "$VENV/bin/python" -m pip install --disable-pip-version-check -q --requirement "$APP/requirements.txt"
fi
log "Aplicando migraciones"
as_portal "$VENV/bin/python manage.py migrate --noinput" | tee -a "$LOG"
as_portal "$VENV/bin/python manage.py collectstatic --noinput --verbosity 0"
as_portal "$VENV/bin/python manage.py check -v 0"
echo "$COMMIT" > "$APP/.deployed-commit"

start_writers "$BACKUP_DIR"
health_check

# Conservar las 10 copias más recientes de este script.
ls -1dt "$BACKUPS"/*/ 2>/dev/null | tail -n +11 | xargs -r rm -rf
log "Actualización completada: $COMMIT. Copia previa: $BACKUP_DIR"
echo "Reversión, si hiciera falta: sudo $0 --rollback $BACKUP_DIR"

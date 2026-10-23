#!/usr/bin/env bash
# Actualiza una instalación existente del portal desde el checkout Git.
#
#   sudo deploy/update.sh                   despliega el commit actual del checkout
#   sudo deploy/update.sh --rollback DIR    restaura código y base de una copia previa
#                         [--ignore-keys]  aunque falten claves con que se hizo la copia
#
# Sigue docs/deployment.md: copia consistente, escritores parados, código del
# commit (no del árbol de trabajo), migración, estáticos y comprobación. No
# instala unidades systemd ni toca Wazuh, el motor HTTPS privado ni secretos.
set -Eeuo pipefail

APP=/srv/soc-portal
VENV=/opt/soc-portal-venv
ENV_FILE=/etc/soc-portal/portal.env
BACKUPS=/var/backups/soc-portal
LOG=/var/log/soc-portal-deploy.log
CODE_ITEMS=(manage.py requirements.txt requirements-postgresql.txt core socportal templates static deploy)
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
# Fase para el manejador de salida: checks (nada parado) → stopped (parado, sin cambios) → changed → finished.
PHASE=checks
# Servicios que el script nunca detiene: portal (se gestiona aparte) y motor privado 3B.
KEEP_RUNNING='^(soc-portal|soc-wazuh-https|soc-wazuh-https-db)\.service$'

log() { printf '%s %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG" >&2; }
die() { log "ERROR: $*"; exit 1; }

confirm() {
  [[ "${ASSUME_YES:-0}" == 1 ]] && return 0
  read -r -p "$1 [escribe 'si' para continuar]: " answer
  [[ "$answer" == si ]] || die "Cancelado por el operador."
}

envfile() { "$VENV/bin/python" -I "$SCRIPT_DIR/envfile.py" "$@"; }

load_env() {
  # Como systemd (EnvironmentFile): valores literales. Con `source`, un `$` en una contraseña
  # abortaba el script (set -u) y un espacio sin comillas ejecutaba un comando.
  local exports
  exports=$(envfile --shell "$ENV_FILE")
  eval "$exports"
}

as_portal() {
  # Root lee el entorno protegido y lo pasa al proceso de socportal, que no necesita
  # permiso de lectura sobre el archivo.
  ( load_env; cd "$APP"; runuser -u socportal -- /bin/sh -c "$*" )
}

collect_static() {
  # staticfiles es derivado y pertenece a socportal (install.sh); archivos copiados
  # a mano como root impedirían a collectstatic sustituirlos.
  chown -R socportal:socportal "$APP/staticfiles"
  as_portal "$VENV/bin/python manage.py collectstatic --noinput --verbosity 0"
}

stop_writers() {
  # Guarda qué timers estaban activos para volver a dejar exactamente esos.
  systemctl list-units --type=timer --state=active --no-legend --plain 'soc-*' \
    | awk '{print $1}' > "$1/timers-active.txt"
  if [[ ! -s "$1/timers-active.txt" ]]; then
    # Ninguno activo suele indicar un intento anterior interrumpido: reactivar los habilitados.
    systemctl list-unit-files --type=timer --state=enabled --no-legend 'soc-*' \
      | awk '{print $1}' > "$1/timers-active.txt"
    log "AVISO: no hay timers soc-* activos; al terminar se arrancarán los habilitados."
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

env_value() {
  # Último valor de una variable del entorno protegido, sin cargar el resto en este shell.
  envfile --get "$1" "$ENV_FILE"
}

as_pg() {
  # Credenciales de la base solo en el subshell del comando PostgreSQL.
  ( load_env
    export PGHOST="${SOC_PORTAL_DB_HOST:-}" PGPORT="${SOC_PORTAL_DB_PORT:-}" PGUSER="${SOC_PORTAL_DB_USER:-socportal}" \
      PGDATABASE="${SOC_PORTAL_DB_NAME:-socportal}" PGPASSWORD="${SOC_PORTAL_DB_PASSWORD:-}" \
      PGSSLMODE="${SOC_PORTAL_DB_SSLMODE:-prefer}"
    "$@" )
}

restore_pg() {
  # Una transacción: borrar todas las tablas (también las que creó una versión posterior y no
  # están en la copia, que impedirían volver a migrar) y cargar la copia.
  # El SQL se genera completo en un archivo antes de tocar la base: si pg_restore se corta a
  # mitad (copia dañada o truncada), psql en tubería llegaría al final de la entrada y
  # confirmaría una restauración parcial. Así, o se carga todo o la base no cambia.
  local sql="$2/restauracion.sql"
  ( umask 077; cat > "$sql" <<'SQL'
DO $$ DECLARE t record; BEGIN
  FOR t IN SELECT tablename FROM pg_tables WHERE schemaname = 'public' LOOP
    EXECUTE 'DROP TABLE IF EXISTS public.' || quote_ident(t.tablename) || ' CASCADE';
  END LOOP;
END $$;
SQL
  )
  pg_restore --no-owner --file=- "$1" >> "$sql" || { rm -f "$sql"; die "La copia $1 no se puede leer completa. La base no se ha modificado."; }
  as_pg psql --quiet --no-psqlrc --set=ON_ERROR_STOP=1 --single-transaction --file="$sql" > /dev/null
  rm -f "$sql"
}

sqlite_ok() {
  "$VENV/bin/python" - "$1" <<'EOF'
import sqlite3, sys
from contextlib import closing
with closing(sqlite3.connect(f'file:{sys.argv[1]}?mode=ro', uri=True)) as db:
    if db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
        raise SystemExit(1)
EOF
}

existing_items() {
  local item
  for item in "${CODE_ITEMS[@]}"; do
    if [[ -e "$1/$item" ]]; then printf '%s\n' "$item"; fi
  done
}

check_space() {
  # Antes de parar nada: la copia (y en una reversión el SQL de restauración) cabe con margen.
  local size avail need
  if [[ "$ENGINE" == postgresql ]]; then
    size=$(as_pg psql -tAqX -c 'SELECT pg_database_size(current_database())')
  else
    size=$(stat -c %s "$DB")
  fi
  need=$(( size * 3 + 300 * 1024 * 1024 ))
  avail=$(df --output=avail -B1 "$BACKUPS" | tail -n 1)
  (( avail > need )) || die "Espacio insuficiente en $BACKUPS: hay $((avail / 1048576)) MiB y hacen falta unos $((need / 1048576)) MiB. No se ha parado nada."
}

check_keys() {
  # Invariante 10: una copia cifrada con claves que ya no están configuradas dejaría ilegibles
  # los secretos guardados (MFA, VPN, conectores). Se comparan huellas, nunca las claves.
  local saved="$1/key-fingerprints.txt" missing
  if [[ ! -f "$saved" ]]; then
    log "AVISO: la copia no guarda huellas de las claves (anterior a esta comprobación)."
    return 0
  fi
  missing=$(comm -23 <(sort -u "$saved") <(envfile --fingerprints "$ENV_FILE" | sort -u) | awk '{print $1}' | sort -u)
  [[ -z "$missing" ]] && return 0
  if [[ "${IGNORE_KEYS:-0}" == 1 ]]; then
    log "AVISO: se restaura sin las claves originales de: $(echo "$missing" | tr '\n' ' ')(--ignore-keys)."
    return 0
  fi
  die "La copia se hizo con claves que ya no están en $ENV_FILE: $(echo "$missing" | tr '\n' ' '). Vuelve a añadir la clave anterior al final de su lista (o la SECRET_KEY de entonces) antes de revertir, o usa --ignore-keys si sabes que esos datos no se necesitan."
}

backup() {
  local dir=$1
  log "Copia de seguridad en $dir"
  echo "$ENGINE" > "$dir/engine"
  if [[ "$ENGINE" == postgresql ]]; then
    # Instantánea consistente de pg_dump; pg_restore --list comprueba que el archivo es legible.
    as_pg pg_dump --format=custom --no-owner --file="$dir/portal.pgdump"
    pg_restore --list "$dir/portal.pgdump" > /dev/null
  else
    # API backup de SQLite: copia consistente aunque exista journal/WAL.
    "$VENV/bin/python" - "$DB" "$dir/portal.sqlite3" <<'EOF'
import sqlite3, sys
from contextlib import closing
with closing(sqlite3.connect(f'file:{sys.argv[1]}?mode=ro', uri=True)) as src, closing(sqlite3.connect(sys.argv[2])) as dst:
    src.backup(dst)
    if dst.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
        raise SystemExit('La copia de la base no supera integrity_check')
EOF
  fi
  local items
  mapfile -t items < <(existing_items "$APP")
  tar -C "$APP" -czf "$dir/code.tar.gz" "${items[@]}"
  cp -a "$APP/.deployed-commit" "$dir/" 2>/dev/null || true
  envfile --fingerprints "$ENV_FILE" > "$dir/key-fingerprints.txt"
  chmod -R go-rwx "$dir"
}

replace_code() {
  local source=$1 item items
  for item in "${CODE_ITEMS[@]}"; do
    rm -rf "${APP:?}/$item"
    # Una copia antigua puede no contener los elementos añadidos después.
    if [[ -e "$source/$item" ]]; then cp -a "$source/$item" "$APP/"; fi
  done
  find "$APP" -name __pycache__ -prune -exec rm -rf {} +
  mapfile -t items < <(existing_items "$APP")
  chown -R root:root "${items[@]/#/$APP/}"
  find "${items[@]/#/$APP/}" -type d -exec chmod 0755 {} +
  find "${items[@]/#/$APP/}" -type f -exec chmod go-w,a+r {} +
  chmod 0755 "$APP/deploy/"*.sh
}

install_requirements() {
  "$VENV/bin/python" -m pip install --disable-pip-version-check -q --requirement "$APP/requirements.txt"
  if [[ "$ENGINE" == postgresql && -f "$APP/requirements-postgresql.txt" ]]; then
    "$VENV/bin/python" -m pip install --disable-pip-version-check -q --requirement "$APP/requirements-postgresql.txt"
  fi
}

health_check() {
  local host status
  host=$(env_value SOC_PORTAL_ALLOWED_HOSTS | cut -d, -f1 | tr -d '[:space:]')
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
}

on_exit() {
  # También tras `die` (exit no dispara ERR). Decide según lo que ya se haya cambiado.
  local status=$?
  set +e
  [[ -n "${STAGE:-}" ]] && rm -rf "$STAGE"
  (( status == 0 )) && return
  case "$PHASE" in
    stopped)
      # Código y base sin tocar: dejar el servicio como estaba en lugar de parado y sin avisos.
      log "Código y base sin cambios: se vuelven a arrancar el portal y los timers."
      start_writers "$BACKUP_DIR" || log "No se han podido arrancar. Arráncalos a mano: soc-portal y los timers de $BACKUP_DIR/timers-active.txt"
      ;;
    changed)
      log "Servicios y timers pueden estar parados. Para volver al estado anterior:"
      log "  sudo $0 --rollback $BACKUP_DIR"
      ;;
  esac
}
trap 'on_error $LINENO' ERR
trap on_exit EXIT

[[ "$(id -u)" -eq 0 ]] || { echo "Ejecutar como root (sudo)." >&2; exit 1; }
[[ -d "$APP" && -x "$VENV/bin/python" && -f "$ENV_FILE" ]] || { echo "No se encuentra una instalación en $APP." >&2; exit 1; }
touch "$LOG"; chmod 0600 "$LOG"
ENGINE=$(env_value SOC_PORTAL_DB_ENGINE); ENGINE=${ENGINE:-sqlite}
case "$ENGINE" in
  sqlite) DB=$(env_value SOC_PORTAL_SQLITE_PATH); DB=${DB:-$APP/data/portal.sqlite3} ;;
  postgresql) command -v pg_dump > /dev/null && command -v pg_restore > /dev/null \
                || { echo "Faltan pg_dump/pg_restore (paquete postgresql-client)." >&2; exit 1; } ;;
  *) echo "SOC_PORTAL_DB_ENGINE no válido en $ENV_FILE." >&2; exit 1 ;;
esac

MODE=deploy
while (( $# )); do
  case "$1" in
    --yes) ASSUME_YES=1 ;;
    --rollback) MODE=rollback; ROLLBACK_DIR=${2:-}; shift ;;
    --ignore-keys) IGNORE_KEYS=1 ;;
    -h|--help) sed -n '2,11p' "$0"; exit 0 ;;
    *) echo "Opción desconocida: $1" >&2; exit 1 ;;
  esac
  shift
done

# Una sola ejecución a la vez.
exec 9>/run/soc-portal-update.lock
flock -n 9 || die "Ya hay otra actualización en curso."

if [[ "$MODE" == rollback ]]; then
  [[ -f "$ROLLBACK_DIR/code.tar.gz" ]] || die "Copia no válida: $ROLLBACK_DIR"
  if [[ "$ENGINE" == postgresql ]]; then DUMP="$ROLLBACK_DIR/portal.pgdump"; else DUMP="$ROLLBACK_DIR/portal.sqlite3"; fi
  [[ -f "$DUMP" ]] || die "La copia no contiene la base de $ENGINE (¿se hizo con otro motor?): $ROLLBACK_DIR"
  if [[ "$ENGINE" == postgresql ]]; then
    pg_restore --list "$DUMP" > /dev/null || die "La copia de PostgreSQL no es legible: $DUMP"
  else
    sqlite_ok "$DUMP" || die "La copia de SQLite no supera integrity_check: $DUMP. No se ha tocado nada."
  fi
  check_keys "$ROLLBACK_DIR"
  install -d -m 0700 "$BACKUPS"
  check_space
  log "REVERSIÓN a la copia $ROLLBACK_DIR (commit $(cat "$ROLLBACK_DIR/.deployed-commit" 2>/dev/null || echo desconocido))"
  echo "Se perderán los datos del portal escritos después de esa copia."
  confirm "¿Restaurar código y base de datos?"
  BACKUP_DIR="$BACKUPS/$(date +%Y%m%d-%H%M%S)-antes-de-reversion"
  install -d -m 0700 "$BACKUP_DIR"
  PHASE=stopped
  stop_writers "$BACKUP_DIR"
  backup "$BACKUP_DIR"
  STAGE=$(mktemp -d /var/tmp/soc-rollback.XXXXXX)
  tar -C "$STAGE" -xzf "$ROLLBACK_DIR/code.tar.gz"
  # Base antes que código: si la restauración falla, código y base siguen siendo los actuales.
  PHASE=changed
  if [[ "$ENGINE" == postgresql ]]; then
    restore_pg "$DUMP" "$BACKUP_DIR"
  else
    for suffix in -wal -shm -journal; do
      [[ -e "$DB$suffix" ]] && mv "$DB$suffix" "$BACKUP_DIR/portal.sqlite3$suffix.descartado"
    done
    install -o socportal -g socportal -m 0600 "$DUMP" "$DB"
  fi
  replace_code "$STAGE"
  cp -a "$ROLLBACK_DIR/.deployed-commit" "$APP/" 2>/dev/null || rm -f "$APP/.deployed-commit"
  install_requirements
  collect_static
  # Usa los timers activos antes de la actualización que se revierte.
  cp "$ROLLBACK_DIR/timers-active.txt" "$BACKUP_DIR/timers-active.txt"
  start_writers "$BACKUP_DIR"
  health_check
  # Comprobación de solo lectura: los secretos guardados se descifran con las claves actuales.
  as_portal "$VENV/bin/python manage.py rotate_encryption_keys" > /dev/null \
    || log "AVISO: hay valores cifrados que no se descifran con las claves actuales. Revisa: manage.py rotate_encryption_keys"
  PHASE=finished
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
git_repo archive "$COMMIT" "${CODE_ITEMS[@]}" | tar -x -C "$STAGE"
chmod -R a+rX "$STAGE"
install -d -o socportal -g socportal -m 0700 "$STAGE/data"  # base vacía solo para las comprobaciones

log "Comprobando el commit ${COMMIT:0:12} en un directorio temporal"
runuser -u socportal -- env -i PATH=/usr/bin:/bin SOC_PORTAL_DEBUG=1 HOME=/nonexistent \
  /bin/sh -c "cd $STAGE && $VENV/bin/python manage.py check -v 0 && $VENV/bin/python manage.py makemigrations --check --dry-run -v 0" \
  || die "El commit no supera manage.py check / makemigrations --check. No se ha tocado producción."

NEW_MIGRATIONS=$(comm -13 <(ls "$APP/core/migrations" | sort) <(ls "$STAGE/core/migrations" | sort) | grep '\.py$' || true)
REQS_CHANGED=0
for reqs in requirements.txt requirements-postgresql.txt; do
  cmp -s "$APP/$reqs" "$STAGE/$reqs" || REQS_CHANGED=1
done
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

install -d -m 0700 "$BACKUPS"
check_space
log "Desplegando $COMMIT sobre $CURRENT"
BACKUP_DIR="$BACKUPS/$(date +%Y%m%d-%H%M%S)-${CURRENT:0:12}"
install -d -m 0700 "$BACKUP_DIR"
PHASE=stopped
stop_writers "$BACKUP_DIR"
backup "$BACKUP_DIR"

PHASE=changed
replace_code "$STAGE"
if [[ $REQS_CHANGED == 1 ]]; then
  log "Instalando dependencias"
  install_requirements
fi
log "Aplicando migraciones"
as_portal "$VENV/bin/python manage.py migrate --noinput" | tee -a "$LOG"
collect_static
as_portal "$VENV/bin/python manage.py check -v 0"
echo "$COMMIT" > "$APP/.deployed-commit"

start_writers "$BACKUP_DIR"
health_check
PHASE=finished

# Conservar las 10 copias más recientes de este script.
ls -1dt "$BACKUPS"/*/ 2>/dev/null | tail -n +11 | xargs -r rm -rf
log "Actualización completada: $COMMIT. Copia previa: $BACKUP_DIR"
echo "Reversión, si hiciera falta: sudo $0 --rollback $BACKUP_DIR"

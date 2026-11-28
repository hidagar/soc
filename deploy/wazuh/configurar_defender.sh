#!/usr/bin/env bash
# Antivirus de equipos: Wazuh recoge los avisos de Microsoft Defender de los PC y servidores de los clientes.
#
#   sudo deploy/wazuh/configurar_defender.sh --reglas          instala la regla del informe de salud y reinicia el gestor
#   sudo deploy/wazuh/configurar_defender.sh --grupo CODIGO    crea o actualiza el grupo de agentes soc-CODIGO
#   sudo deploy/wazuh/configurar_defender.sh --ver             muestra qué está aplicado
#   (añade --yes para no pedir confirmación)
#
# --reglas: copia deploy/wazuh/soc_defender_rules.xml a /var/ossec/etc/rules/, comprueba la configuración con
#   wazuh-analysisd -t y solo entonces reinicia wazuh-manager. Si la comprobación falla, restaura lo anterior.
# --grupo: crea el grupo de agentes del cliente y su agent.conf compartido (canal de Defender, plantilla
#   deploy/wazuh/agente_defender.conf.example, y vigilancia en tiempo real de los puntos de arranque automático
#   y de acceso, deploy/wazuh/agente_integridad.conf.example). Se puede repetir: añade solo lo que falte.
#   Los agentes que se instalen con ese grupo leen Defender.
#   Pertenecer al grupo no asigna el equipo al cliente en el portal: se asigna en «Antivirus de equipos».
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
OSSEC=${SOC_WAZUH_DIR:-/var/ossec}
RULES=$OSSEC/etc/rules/soc_defender_rules.xml
SHARED=$OSSEC/etc/shared
BACKUPS=${SOC_BACKUP_DIR:-/var/backups/soc-wazuh}

die() { echo "ERROR: $*" >&2; exit 1; }
confirm() {
  [[ "${ASSUME_YES:-0}" == 1 ]] && return 0
  read -r -p "$1 [escribe 'si' para continuar]: " answer
  [[ "$answer" == si ]] || die "Cancelado."
}

show() {
  if [[ -f "$RULES" ]] && cmp -s "$RULES" "$HERE/soc_defender_rules.xml"; then
    echo "Regla del informe de salud: instalada ($RULES)."
  elif [[ -f "$RULES" ]]; then
    echo "Regla del informe de salud: instalada, pero distinta de la del repositorio."
  else
    echo "Regla del informe de salud: NO instalada."
  fi
  local found=0 dir
  for dir in "$SHARED"/soc-*/; do
    [[ -d "$dir" ]] || continue
    found=1
    if grep -q 'Microsoft-Windows-Windows Defender/Operational' "$dir/agent.conf" 2>/dev/null; then
      echo "Grupo $(basename "$dir"): lee el canal de Defender."
    else
      echo "Grupo $(basename "$dir"): SIN el canal de Defender."
    fi
    if grep -q 'soc-integridad' "$dir/agent.conf" 2>/dev/null; then
      echo "Grupo $(basename "$dir"): vigila en tiempo real el arranque automático y los accesos."
    else
      echo "Grupo $(basename "$dir"): SIN la vigilancia en tiempo real (repetir --grupo para añadirla)."
    fi
  done
  [[ $found == 1 ]] || echo "Grupos de clientes (soc-*): ninguno."
}

install_rules() {
  [[ -x "$OSSEC/bin/wazuh-analysisd" ]] || die "No se encuentra $OSSEC/bin/wazuh-analysisd: ¿es el gestor de Wazuh?"
  if [[ -f "$RULES" ]] && cmp -s "$RULES" "$HERE/soc_defender_rules.xml"; then
    echo "La regla ya está instalada."; return 0
  fi
  confirm "Se instalará $RULES y se reiniciará wazuh-manager (unos segundos sin analizar eventos). ¿Continuar?"
  local backup
  backup="$BACKUPS/$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$backup"
  [[ -f "$RULES" ]] && cp -p "$RULES" "$backup/"
  install -m 0660 "$HERE/soc_defender_rules.xml" "$RULES"
  chown wazuh:wazuh "$RULES" 2>/dev/null || true
  if ! "$OSSEC/bin/wazuh-analysisd" -t >/dev/null 2>&1; then
    "$OSSEC/bin/wazuh-analysisd" -t || true
    if [[ -f "$backup/soc_defender_rules.xml" ]]; then cp -p "$backup/soc_defender_rules.xml" "$RULES"; else rm -f "$RULES"; fi
    die "Wazuh no acepta la regla; se ha restaurado lo anterior sin reiniciar."
  fi
  systemctl restart wazuh-manager
  echo "Regla instalada y gestor reiniciado. Copia de lo anterior en $backup."
}

configure_group() {
  local code=$1 group dir conf
  [[ "$code" =~ ^[a-z0-9][a-z0-9_-]{0,39}$ ]] || die "Código de cliente no válido: minúsculas, números, - y _ (como en el portal)."
  group="soc-$code"
  dir="$SHARED/$group"
  conf="$dir/agent.conf"
  if [[ ! -d "$dir" ]]; then
    [[ -x "$OSSEC/bin/agent_groups" ]] || die "No se encuentra $OSSEC/bin/agent_groups: ¿es el gestor de Wazuh?"
    confirm "Se creará el grupo de agentes $group. ¿Continuar?"
    "$OSSEC/bin/agent_groups" -a -g "$group" -q >/dev/null
  fi
  if grep -q 'Microsoft-Windows-Windows Defender/Operational' "$conf" 2>/dev/null; then
    echo "El grupo $group ya lee el canal de Defender."
  else
    if [[ -s "$conf" ]] && ! grep -q '^<agent_config>\s*</agent_config>$' "$conf"; then
      # Ya tiene otra configuración: se añade el bloque de Defender sin tocar lo existente.
      mkdir -p "$BACKUPS" && cp -p "$conf" "$BACKUPS/$group-agent.conf.$(date +%Y%m%d-%H%M%S)"
      sed -n '/<agent_config/,$p' "$HERE/agente_defender.conf.example" >> "$conf"
    else
      cp "$HERE/agente_defender.conf.example" "$conf"
    fi
    chown wazuh:wazuh "$conf" 2>/dev/null || true
    chmod 0660 "$conf"
    echo "Grupo $group: configurado para leer Microsoft Defender."
  fi
  if grep -q 'soc-integridad' "$conf" 2>/dev/null; then
    echo "El grupo $group ya vigila en tiempo real el arranque automático y los accesos."
  else
    mkdir -p "$BACKUPS" && cp -p "$conf" "$BACKUPS/$group-agent.conf.$(date +%Y%m%d-%H%M%S)"
    cat "$HERE/agente_integridad.conf.example" >> "$conf"
    chown wazuh:wazuh "$conf" 2>/dev/null || true
    chmod 0660 "$conf"
    echo "Grupo $group: añadida la vigilancia en tiempo real (integridad de archivos). Los agentes la reciben en unos minutos."
  fi
  cat <<EOF

Instalar el agente en cada equipo Windows del cliente con el grupo $group, por ejemplo:
  msiexec /i wazuh-agent.msi /q WAZUH_MANAGER="<dirección del SOC alcanzable desde la sede>" WAZUH_AGENT_GROUP="$group"
(añadir WAZUH_REGISTRATION_PASSWORD si el gestor exige contraseña de alta; no la pegues en el chat).

En cada servidor o equipo Linux, con el repositorio de paquetes de Wazuh ya añadido (misma versión que el gestor):
  Debian/Ubuntu:  sudo WAZUH_MANAGER="<dirección del SOC>" WAZUH_AGENT_GROUP="$group" apt-get install wazuh-agent
  RHEL/Rocky/Alma: sudo WAZUH_MANAGER="<dirección del SOC>" WAZUH_AGENT_GROUP="$group" dnf install wazuh-agent
  y después:      sudo systemctl enable --now wazuh-agent
Los accesos (SSH, sudo) llegan si existe /var/log/auth.log (Debian/Ubuntu) o /var/log/secure (RHEL). En sistemas
solo con journald (p. ej. Debian 12 mínimo), instalar rsyslog; no añadir además journald al agente (contaría dos veces).

Después, en el portal: «Cobertura y salud › Antivirus de equipos › Agentes sin asignar» → asignarlos al cliente.
EOF
}

ASSUME_YES=0
for arg in "$@"; do [[ "$arg" == --yes ]] && ASSUME_YES=1; done
case "${1:-}" in
  --ver) show ;;
  --reglas) [[ $EUID -eq 0 || -n "${SOC_WAZUH_DIR:-}" ]] || die "Ejecutar con sudo."; install_rules ;;
  --grupo) [[ $EUID -eq 0 || -n "${SOC_WAZUH_DIR:-}" ]] || die "Ejecutar con sudo."; [[ -n "${2:-}" ]] || die "Falta el código del cliente."; configure_group "$2" ;;
  *) die "Uso: $0 --reglas | --grupo CODIGO | --ver [--yes]" ;;
esac

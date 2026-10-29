# Operación diaria y trabajos

## Qué revisar

Salud del SOC: servicios, último éxito/duración/reintentos de cada trabajo, cola/antigüedad, fuentes ambiguas y detección verificada. El programador correcto solo prueba que lanzó tareas. API, exportación, recepción y amenaza validada son controles separados.

```sh
sudo systemctl is-active soc-portal wazuh-manager wazuh-indexer
sudo systemctl is-active soc-wazuh-https soc-wazuh-https-db soc-https-delivery.timer
sudo systemctl list-timers 'soc-*'
sudo journalctl -u soc-job@transport.service -n 50 --no-pager
```

Journal es información privada: redactar antes de adjuntarlo a un issue. No imprimir entorno ni reader para diagnosticar.

## Monitor exterior

Las comprobaciones de «Salud del SOC» y el correo de operaciones no pueden avisar si cae la VM entera. Para eso:

- **Latido saliente** (recomendado): crear un control en un servicio externo de latidos (p. ej. Healthchecks.io, periodo 5 minutos y gracia 10) y poner su URL en `SOC_PORTAL_HEARTBEAT_URL`. El trabajo `health` la llama cada 5 minutos si el SOC está sano y llama a `<URL>/fail` al momento si no. El servicio externo avisa por correo o móvil cuando la llamada falta o falla. No se envía ningún dato del SOC.
- **Consulta** `GET /healthz/`: sin sesión, responde `200 ok` o `503 revisar`, sin más detalle. Sirve para monitores que consultan (UptimeRobot, el monitor de la red); el proxy público debe dejar pasar esa ruta.

«Sano» significa que el trabajo `health` terminó hace menos de 5 minutos y no hay abierto ninguno de estos fallos: portal, Wazuh manager o indexador detenidos, disco por debajo del 15 %, monitor de avisos urgentes atrasado o **silencio de todos los equipos** (`platform:ingest-silence`, crítico, también por correo). Los avisos menores (IP real, ensayo de recuperación pendiente) no cambian el resultado.

El silencio global se compara con la misma franja horaria de los 7 días anteriores, porque la recepción solo cuenta alertas de Wazuh (varias reglas del SOC son de nivel 0) y de noche puede pasar una hora sin nada sin que falle nada. Se avisa si pasa una **hora completa sin ningún evento** que esos 7 días siempre tuvo al menos 10; antes, a los **30 minutos** si a esas horas siempre llegan más de 60 por hora; y siempre a las **24 horas**. Sin una semana de historia, a las 6 horas. Hasta la versión de octubre de 2026 el umbral era fijo de 30 minutos y podía dar avisos críticos falsos de madrugada.

## Conservación de datos

El trabajo horario `housekeeping` borra, por bloques y con un minuto como máximo por ejecución, las detecciones sin incidencia y los contadores por hora más antiguos que «Retención de evidencias» (Copias y recuperación, 90 días por defecto) y los intentos de acceso de más de un día (`core/retention.py`; último resultado en `WorkerState` «retention»). Antes solo se hacía al final de una copia correcta: con copias fallidas la base crecía sin límite, y un borrado de golpe retenía el escritor de SQLite.

## Versión instalada

«Salud del SOC» muestra a quien tiene acceso global el commit instalado, su fecha y el motor de base. Lo registra `deploy/update.sh` en `/srv/soc-portal/.deployed-commit`; una instalación que no se haya actualizado con el script aparece como «sin registrar».

## Programación

`soc-monitor.timer` invoca dispatcher; `run_soc_job` toma lock por nombre. `JOBS` define 16 tareas separadas. `soc-job@.service` limita ejecución a 180 s y escritura a rutas permitidas; intervalos no garantizan latencia máxima. HTTPS añade timer de 5 s tras finalizar la unidad. Véase [referencia](reference/jobs.md).

Timers semanales y urgentes coexisten con dispatcher. Revisar unidad/overrides reales; no duplicar programación por intuición.

| Acción | Efectos |
|---|---|
| `monitor_soc --no-notify` | Programa trabajos root; omite notifications/invitations del dispatcher. No es modo global de solo lectura: otras tareas/timers escriben o envían según configuración. |
| `run_soc_job <job>` | Ejecuta tarea protegida con sus efectos. |
| `sync_wazuh_sources` | Cambia receptor/reglas y puede reiniciar Wazuh tras validar. |
| `weekly_soc_reports` | Refresca informes; con `--send`, envía activados. |
| `poll_urgent_alerts` | Escanea y envía pendientes. |
| `rebuild_customer_projection --client ID` | Reencola proyección derivada; no borra evidencia original. |
| `operate_soc vpn/changes/backup` | Red/sistema, firewall o copia; no diagnóstico de lectura. |

## Backlog HTTPS

Revisar recibos por equipo. `confirmed` v2: procesados y alertas verificadas; `forwarded` v1 sigue sin ACK. Fallos se retienen. Antes de repetir un v1 ambiguo, comprobar posible duplicado; los nuevos conservan UID. No vaciar tablas/colas para quitar una alerta operativa.

Al cambiar Wazuh/reglas, verificar y sincronizar perfil con servicios privados parados; conservar bandeja, DB y secretos. Seguir [3B](entrega-wazuh-https.md). No usar perfil de laboratorio como producción.

## Entrega

Registrar versión, migración y manifiesto; copia/reversión; distinguir generación y envío; comprobar login/MFA/scope/descargas, tareas y llegada real cuando exista equipo disponible. Registrar lo no validado. No cerrar ausencia de logs por un API correcto.

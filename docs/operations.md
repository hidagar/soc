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

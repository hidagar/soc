# Comandos, trabajos y unidades

Generado desde el código por `python docs/tools/generate_reference.py`. No es telemetría ni una declaración de permisos efectivos.

Estos comandos pueden escribir, configurar equipos, enviar correo o cambiar el sistema. Revisar [operación](../operations.md) y permisos root; el inventario no autoriza su ejecución.

| Comando manage.py | Argumentos declarados |
|---|---|
| [core/management/commands/dashboard_sources.py](../../core/management/commands/dashboard_sources.py) | Sin argumentos propios |
| [core/management/commands/monitor_soc.py](../../core/management/commands/monitor_soc.py) | parser.add_argument('--no-notify', action='store_true') |
| [core/management/commands/operate_soc.py](../../core/management/commands/operate_soc.py) | parser.add_argument('job', choices=['vpn', 'changes', 'backup']); parser.add_argument('--daily', action='store_true') |
| [core/management/commands/poll_urgent_alerts.py](../../core/management/commands/poll_urgent_alerts.py) | Sin argumentos propios |
| [core/management/commands/rebuild_customer_projection.py](../../core/management/commands/rebuild_customer_projection.py) | parser.add_argument('--client', type=int) |
| [core/management/commands/rotate_encryption_keys.py](../../core/management/commands/rotate_encryption_keys.py) | parser.add_argument('--apply', action='store_true', help='Escribir los valores recifrados') |
| [core/management/commands/run_soc_job.py](../../core/management/commands/run_soc_job.py) | parser.add_argument('job', choices=sorted(JOBS)) |
| [core/management/commands/sync_wazuh_sources.py](../../core/management/commands/sync_wazuh_sources.py) | Sin argumentos propios |
| [core/management/commands/transfer_database.py](../../core/management/commands/transfer_database.py) | parser.add_argument('--source', required=True, help='Copia SQLite de origen (se abre en solo lectura)'); parser.add_argument('--check', action='store_true', help='Solo comprobación previa; no escribe nada'); parser.add_argument('--replace-target', action='store_true', help='Confirma que se vacían las tablas del destino PostgreSQL antes de copiar') |
| [core/management/commands/weekly_soc_reports.py](../../core/management/commands/weekly_soc_reports.py) | parser.add_argument('--week', help='Lunes de la semana (AAAA-MM-DD); por defecto, la última semana completa'); parser.add_argument('--send', action='store_true', help='Enviar por SendGrid los informes activados') |

## Dispatcher

| Trabajo | Intervalo objetivo (s) | Etiqueta |
|---|---:|---|
| `receipts` | 60 | Lectura local de Wazuh |
| `reconciliation` | 60 | Recuperación por fuente |
| `transport` | 30 | Entrega de lotes HTTPS |
| `geography` | 120 | Mapa y geografía |
| `databases` | 3600 | Bases GeoIP y ASN |
| `invitations` | 60 | Invitaciones de usuarios |
| `reports` | 300 | Informes |
| `inventory` | 60 | Inventario y conectividad |
| `exposure` | 300 | Exposición de equipos |
| `archives` | 300 | Copias de configuración |
| `attribution` | 300 | Identidad de activos |
| `zenarmor` | 120 | Exportación Zenarmor |
| `dashboards` | 300 | Ámbitos de Wazuh |
| `health` | 60 | Salud de la plataforma |
| `notifications` | 60 | Avisos operativos |
| `housekeeping` | 3600 | Conservación y limpieza |

## Unidades incluidas

La unidad instalada puede tener overrides no presentes en Git. Consultar su configuración real antes de programar otra tarea.

- [deploy/relay/soc-log-relay.service](../../deploy/relay/soc-log-relay.service)
- [deploy/soc-urgent-alerts.service](../../deploy/soc-urgent-alerts.service)
- [deploy/soc-urgent-alerts.timer](../../deploy/soc-urgent-alerts.timer)
- [deploy/soc-wazuh-dashboards.service](../../deploy/soc-wazuh-dashboards.service)
- [deploy/soc-wazuh-dashboards.timer](../../deploy/soc-wazuh-dashboards.timer)
- [deploy/soc-wazuh-sources.service](../../deploy/soc-wazuh-sources.service)
- [deploy/soc-wazuh-sources.timer](../../deploy/soc-wazuh-sources.timer)
- [deploy/soc-weekly-reports.service](../../deploy/soc-weekly-reports.service)
- [deploy/soc-weekly-reports.timer](../../deploy/soc-weekly-reports.timer)
- [deploy/systemd/soc-backup-daily.service](../../deploy/systemd/soc-backup-daily.service)
- [deploy/systemd/soc-backup-daily.timer](../../deploy/systemd/soc-backup-daily.timer)
- [deploy/systemd/soc-backup.service](../../deploy/systemd/soc-backup.service)
- [deploy/systemd/soc-backup.timer](../../deploy/systemd/soc-backup.timer)
- [deploy/systemd/soc-changes.service](../../deploy/systemd/soc-changes.service)
- [deploy/systemd/soc-changes.timer](../../deploy/systemd/soc-changes.timer)
- [deploy/systemd/soc-https-delivery.timer](../../deploy/systemd/soc-https-delivery.timer)
- [deploy/systemd/soc-job@.service](../../deploy/systemd/soc-job@.service)
- [deploy/systemd/soc-monitor.service](../../deploy/systemd/soc-monitor.service)
- [deploy/systemd/soc-monitor.timer](../../deploy/systemd/soc-monitor.timer)
- [deploy/systemd/soc-vpn.service](../../deploy/systemd/soc-vpn.service)
- [deploy/systemd/soc-vpn.timer](../../deploy/systemd/soc-vpn.timer)
- [deploy/systemd/soc-wazuh-https-db.service](../../deploy/systemd/soc-wazuh-https-db.service)
- [deploy/systemd/soc-wazuh-https.service](../../deploy/systemd/soc-wazuh-https.service)

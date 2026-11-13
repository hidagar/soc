# Trabajo pendiente

Lista única de lo que falta, actualizada el **13/11/2026**. Reúne los «Pendiente» de la [hoja de ruta](roadmap.md), del [traspaso](handoff.md) y de cada entrega del [registro de cambios](changelog.md).

**Cómo se mantiene:** cada entrega quita aquí lo que cierra y añade lo que deja pendiente, en el mismo pull request (AGENTS.md, «Antes de terminar»). Cada punto indica quién puede hacerlo:
- **Usuario:** requiere producción, credenciales, equipos de clientes o una decisión de negocio. No se hace desde el código.
- **Código:** desarrollo en el repositorio.

## Acciones del usuario fuera del código

| Pendiente | Origen | Notas |
|---|---|---|
| **Probar la fase 2 de las políticas en un firewall propio** antes de usarla con clientes | 13/11 | Desplegada, pero sin validar en un OPNsense real: preparar un plan en un equipo de ib-red, revisar el alias y la regla desactivada en su consola, activarlo y comprobar el acceso desde un origen autorizado y desde otro. |
| Desplegar los plazos de las solicitudes y activarlos | 13/11 | Migración 0075. Se activan en «Plazos de atención»; revisar antes los valores por defecto (8 h y 5 días; urgentes, 1 h y 1 día). |
| «Correo de operaciones» activo en «Copias y recuperación» | 11/11 | Para recibir las solicitudes y las decisiones de los clientes. |
| Comprobar si algún equipo usa firma SSH `ssh-rsa` (SHA-1) antes de subir `paramiko` a 5.x | Auditoría 11/11 | Las páginas de conexión SSH y de copias SFTP lo avisan al obtener la huella. Si ninguno lo usa, la subida es segura. |
| Ejecutar `sudo deploy/configurar_registros.sh` | Auditoría 29/10 | Registros de Nginx y gunicorn sin URL secretas. [Despliegue](deployment.md#registros-sin-secretos-de-url). |
| `X-Forwarded-For` en el Nginx público y `deploy/configurar_ip_real.sh` | Continuidad 29/10 | Sin esto, el límite de login por IP ve la IP del proxy. |
| Configurar `SOC_PORTAL_HEARTBEAT_URL` (monitor exterior) | Bloque 8 | Implementado, falta la URL del servicio de monitorización. |
| Ensayo completo de recuperación de la VM | Bloque 8 | Restaurar en una VM aislada y medir pérdida de datos y tiempo. |
| Activar los plazos de atención (SLA) | Bloque 5, 30/10 | Desactivados hasta activarlos en «Plazos de atención». |
| Lista de bloqueo en observación para Pollença | Bloqueo, 27/10 | Piloto acordado; también Conservas Roselló. |
| Activar la política BCM | Conversación 05/11 | Pendiente de decisión del usuario. |
| Bot de Telegram del SOC (`SOC_PORTAL_TELEGRAM_BOT_TOKEN`) y primer cliente con Teams | Avisos por chat, 06/11 | [Guía](reports-and-mail.md#avisos-urgentes-por-teams-y-telegram). |
| `SOC_PORTAL_NVD_KEY` (opcional) y activar «Avisos de vulnerabilidad» por cliente | Vulnerabilidades, 06/11 | Revisar la primera tanda en «Vulnerabilidades». |
| `SOC_PORTAL_AUDIT_ANCHOR_EMAIL` (opcional) | Anclaje, 06/11 | Sin ella, el ancla va al correo de copia de informes. |
| Revisar los valores del índice de seguridad con clientes reales | Índice, 06/11 | Ajustar `WEIGHTS` si algún factor no refleja la realidad. |
| Activar el webhook firmado de SendGrid | Bloque 6 | Hasta entonces, «Aceptado por SendGrid» no confirma la entrega. |
| Primer relay HTTPS real en una sede | Bloque 3/7 | Descartado por ahora por el usuario; no reabrir sin su decisión. |
| Licencia de exportación de Zenarmor (SOHO/Business) | Bloque 7 | Requisito para recibir sus eventos. |
| Confirmar la ruta de menú de Syslog en un GCC real | Traspaso 20/10 | Las pruebas siguen la plantilla actual. |
| Revisar las 12 unidades systemd de la VM que difieren de `deploy/` | Traspaso 20/10 | Formato o ajustes locales. |
| Cerrar en GitHub los PR abiertos que ya están en `main` | Registro de cambios | #4–#24, #26, #27, #29, #31, #48, #54 y #56. |

## Desarrollo pendiente por área

### Políticas de firewall propuestas (fase 1 entregada el 11/11)
- Hecho el 13/11: restringir un servicio en OPNsense con el control de cambios (alias de autorizados y regla propia). Pendiente de validar en un equipo real.
- **Fase 2 · filtro por país en OPNsense:** alias GeoIP con la misma plantilla. Exige comprobar antes que la base GeoIP del firewall carga la tabla; vacía, bloquearía a todo el mundo.
- **Fase 2 · IPv6 y destinos que no son una IP fija** (alias, el propio firewall, varias interfaces): hoy se aplican a mano.
- El control de exposición debería reconocer la regla del SOC y dejar de mostrar el servicio como abierto a cualquier origen.
- **Fase 2 · UniFi por API:** reenvíos de puertos y restricción por región. Hoy es una actuación guiada.
- **Fase 3 · mínimo privilegio:** conocer el tráfico legítimo con resúmenes de Zenarmor por API (aplicaciones y categorías), sin recibir cada conexión. Antes, confirmar qué ofrece su API.
- Recordatorio al cliente si una propuesta lleva más de 14 días sin decisión.

### Solicitudes de clientes
- Hecho el 13/11: plazos de primera respuesta y resolución. Falta el horario laboral (igual que en las incidencias) y plazos propios por cliente.
- Adjuntos.

### Vulnerabilidades
- UniFi Network Application, si se obtiene su versión.
- Productos de Hillstone y Grandstream con datos reales de NVD.

### Avisos y comunicaciones
- Avisos de actuaciones o del informe mensual por Teams o Telegram, si se piden.
- Mostrar al cliente el cumplimiento de los plazos de atención (decidir qué se publica de los casos internos).

### Plazos de atención (SLA)
- Horario laboral y pausa mientras se espera al cliente.

### Conexión a Internet
- Duración de las caídas con el estado de las consolas en la nube de UniFi (requiere comprobarlo en campo).
- Regla de Wazuh para las alarmas de gateway de OPNsense, si se envían.

### Inteligencia y bloqueo
- Q-Feeds fase 2: firewalls propios de ib-red con el plugin oficial y regla con control de cambios. Fase 3, en clientes, solo con acuerdo escrito de licencia.
- Reputación propia: distribuirla como opción de la lista de bloqueo cuando la medida lo justifique.
- CrowdSec: decidir si el motor comparte señales; decidir qué reputación se publica al cliente.

### Base, despliegue y continuidad (bloques 4 y 8)
- Ensayo con una copia de la base real en staging y restauración completa de la copia cifrada con PostgreSQL.
- Configuración multiambiente y entrega reproducible completa.
- Rotación de `SECRET_KEY` (afecta a sesiones, enlaces firmados y cadena de auditoría): necesita un plan propio.

### Conectores y cobertura (bloque 7)
- Matriz fabricante/versión/capacidades con una muestra real por motor y red (GCC, ClamAV).
- Hillstone en el recorrido API opcional; lectura de Zenarmor cuando exista contrato contrastado.

### Propuestas de la auditoría de noviembre

Auditoría del 11/11/2026: herramientas automáticas (ruff, bandit, pip-audit), recorrido de todas las rutas con administrador y cliente, y revisión manual del código nuevo desde el 30/10. Lo corregido está en el [registro de cambios](changelog.md). Queda propuesto:

**Seguridad y mantenimiento**
- Subir `paramiko` de 4.0.0 a 5.x: corrige el uso de SHA-1 en firmas RSA (PYSEC-2026-2858). La batería completa pasa con 5.1.0, pero un firewall antiguo que solo acepte `ssh-rsa` dejaría de conectar: comprobarlo antes (ver acciones del usuario).
- Conservación de las tablas nuevas: `ChatNotice`, `ConnectivityEvent`, `CustomerRequestEntry` y las propuestas «Ya no aplica» crecen sin límite. Añadirlas al trabajo `housekeeping` con un plazo acordado.
- Tras confirmar el doble factor, volver a la página donde estaba el usuario (hoy tiene que repetir la operación a mano).

**Usabilidad del SOC**
- Hecho el 12/11: contadores en el menú lateral y buscador global.
- Buscador: añadir usuarios del portal y texto de las conversaciones si se echa en falta.
- Hecho el 12/11: línea de tiempo por cliente. Posible ampliación: versión resumida para el portal del cliente, solo con lo publicado.
- Hecho el 13/11: las cinco páginas de inteligencia y bloqueo comparten una entrada del menú, con pestañas.

**Valor para el cliente**
- Hecho el 13/11: el informe mensual incluye vulnerabilidades, solicitudes y cambios.
- Recordatorio si una propuesta de cambio lleva más de 14 días sin decisión.

### Ideas propuestas sin empezar
- Evidencias para NIS2/ENS.
- Aviso de equipos nuevos en la red.
- Credenciales filtradas del dominio del cliente.

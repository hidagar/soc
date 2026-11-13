# Registro de cambios

Todo lo que se ha entregado en el repositorio, de lo más reciente a lo más antiguo, con su pull request, la migración y el estado de despliegue. Lo que falta por hacer está en [trabajo pendiente](pending.md).

**Cómo se mantiene:** cada entrega añade aquí su fila en el mismo pull request (AGENTS.md, «Antes de terminar»). Cuando el usuario confirma el despliegue, se cambia el estado. Estados:
- **En rama:** pull request abierto, sin integrar en `main`.
- **En `main`:** integrado. El flujo de despliegue integra en `main` justo antes de ejecutar `sudo deploy/update.sh`, así que en la práctica coincide con lo desplegado. Aun así, se anota la confirmación del usuario cuando la da.
- **Desplegado (confirmado):** el usuario confirmó que está en producción.

`main` en producción a 13/11/2026: `73b573b` (#66). El usuario confirmó ese despliegue, y `update.sh` instala `main` entero, así que todo lo anterior también está desplegado.

Antes del 20/10/2026 no hay historial en Git: la importación inicial (`5162974`) trajo la aplicación construida hasta entonces. Su estado se describe en el [traspaso](handoff.md).

## Pendiente de integrar y desplegar

| Fecha | PR | Cambio | Migración | Estado |
|---|---|---|---|---|
| 13/11/2026 | [#64](https://github.com/hidagar/soc/pull/64) | **Mapa de detecciones mejorado.** Líneas de ataque animadas de cada país a la zona de las sedes, países coloreados por volumen, arco con la proporción de permitidas, zoom (botones, doble clic, Ctrl + rueda, «Europa») con arrastre, y mapa más grande sin hueco: «Evolución» y «Motores» pasan debajo. Nueva variable opcional `SOC_PORTAL_MAP_HOME`. | — | Desplegado (confirmado 12/11) |
| 13/11/2026 | rama `politicas/fase2` | **Políticas propuestas, fase 2: restringir un servicio con el control de cambios (OPNsense).** Desde una propuesta aprobada, «Preparar con el control de cambios» pide los orígenes autorizados y crea un plan: un alias propio y una regla de bloqueo, desactivada, para todo origen que no esté autorizado. No modifica la publicación del cliente. Activación con MFA, punto de recuperación y reversión automática; aborta si la tabla de autorizados queda vacía. Al confirmarse, la propuesta pasa sola a «Aplicada» y la verificación vigila que la regla siga activa. Sin validar todavía en un OPNsense real. | — | En rama |
| 13/11/2026 | [#66](https://github.com/hidagar/soc/pull/66) | **Informe mensual ampliado y páginas de inteligencia agrupadas.** El informe mensual (portal, enlace y PDF) añade «Trabajo del SOC con vuestra empresa»: vulnerabilidades avisadas, corregidas y pendientes; solicitudes recibidas y resueltas, con el tiempo habitual de primera respuesta; y cambios propuestos, aplicados y comprobados. Solo incluye lo que el cliente ya ve en su portal. En el menú, «Reputación CrowdSec», «Listas de CrowdSec», «Listas de bloqueo», «Q-Feeds» y «Reputación propia» pasan a una sola entrada, «Inteligencia y bloqueo», con pestañas. | — | Desplegado (confirmado 13/11, `73b573b`) |
| 12/11/2026 | [#65](https://github.com/hidagar/soc/pull/65) | **Línea de tiempo por cliente.** Botón en la ficha del cliente: incidencias, avisos urgentes, solicitudes, vulnerabilidades, cambios propuestos, actuaciones y comunicaciones, informes, caídas de Internet y cambios en firewalls, por día (hora local) y con enlace a cada página. Filtros por tipo y periodo (30, 90 o 365 días). Vista interna del SOC. | — | Desplegado (confirmado 12/11, `92c7297`) |
| 12/11/2026 | [#63](https://github.com/hidagar/soc/pull/63) | **Contadores en el menú y buscador global.** El menú lateral muestra cuántas solicitudes, vulnerabilidades y políticas esperan al SOC (en rojo si hay algo urgente) y lo suma en el grupo plegado. Buscador en el menú (tecla `/`): clientes, sedes, firewalls, incidencias, solicitudes, políticas, CVE e IPs, siempre dentro del ámbito del usuario; una referencia exacta o un único resultado abre directamente su página. | — | Desplegado (confirmado 13/11) |
| 11/11/2026 | [#62](https://github.com/hidagar/soc/pull/62) | **Auditoría de noviembre.** Correcciones: el portal del cliente no mostraba los mensajes de confirmación; el resumen del SOC no incluía solicitudes, cambios aprobados, vulnerabilidades ni políticas por revisar (y «vulnerabilidades sin revisar» aparecía como fallo de la plataforma); una política «sin efecto comprobado» desaparecía de la vista de trabajo; el aviso de una solicitud no salía si la cuenta del portal no tenía correo; una fecha dañada detenía la descarga del catálogo de vulnerabilidades. Nueva prueba de humo de todas las rutas. Detalle y propuestas: [pendientes](pending.md#propuestas-de-la-auditoría-de-noviembre). | — | Desplegado (confirmado 12/11) |
| 11/11/2026 | [#61](https://github.com/hidagar/soc/pull/61) (incluye #60), en `main` (`370ea44`) | **Políticas de firewall propuestas, fase 1.** El SOC propone por cliente, a partir de su exposición y de 30 días de detecciones: restringir servicios publicados, filtro por país, IPS en bloqueo, lista de salida C2 y lista de bloqueo. Se revisan en «Cobertura y salud › Políticas propuestas»; el cliente las aprueba o rechaza en «Cambios propuestos» con MFA; el SOC las aplica y se verifican a los 7 días. Incluye este registro de cambios y la [lista de pendientes](pending.md). Detalle: [operación](operations.md#políticas-de-firewall-propuestas). | 0074 | Desplegado (confirmado 12/11) |
| 06/11/2026 | [#60](https://github.com/hidagar/soc/pull/60) | **Solicitudes al SOC desde el portal:** consultas, cambios, desbloqueos y sospechas de incidente. Conversación con notas internas, incidencia enlazada, aviso al equipo y aviso al cliente sin el texto. | 0073 | Desplegado (confirmado 12/11) |

## Noviembre de 2026

| Fecha | PR | Cambio | Migración | Estado |
|---|---|---|---|---|
| 06/11 | [#59](https://github.com/hidagar/soc/pull/59) | Avisos de vulnerabilidad dirigidos: CVE de NVD (alta, crítica o KEV de CISA) cruzadas con modelo y versión de cada firewall; revisión del SOC, portal por firewall, un correo por cliente y efecto en «Firmware al día». | 0072 | Desplegado (confirmado 06/11) |
| 06/11 | [#58](https://github.com/hidagar/soc/pull/58) | Avisos urgentes también por Microsoft Teams (Workflows) y Telegram (bot del SOC), con prueba antes de activar y una publicación por aviso y canal. | 0071 | Desplegado (confirmado 06/11) |
| 06/11 | [#57](https://github.com/hidagar/soc/pull/57) | Conexión a Internet por sede: caídas notificadas por UniFi, en el portal, el informe mensual y la ficha del SOC. | 0070 | Desplegado (confirmado 06/11) |
| 06/11 | [#56](https://github.com/hidagar/soc/pull/56) | Índice de seguridad del cliente (0–100) con 8 factores, histórico diario y plan de mejora. | 0069 | Desplegado (confirmado 06/11) |
| 06/11 | [#55](https://github.com/hidagar/soc/pull/55) | Bloque 8: ancla externa diaria de la auditoría por correo, con comprobación automática y manual. | 0068 | Desplegado (confirmado 06/11) |
| 05/11 | [#54](https://github.com/hidagar/soc/pull/54) | Alta guiada en 7 pasos: cliente, sede, firewall, conexión, registros, comprobación y servicios. | — | Desplegado (confirmado 06/11) |
| 05/11 | [#53](https://github.com/hidagar/soc/pull/53) | Servicios del cliente en un solo sitio (ficha del cliente y de cada sede). | — | Desplegado (confirmado 06/11) |
| 05/11 | [#52](https://github.com/hidagar/soc/pull/52) | Entrega y avisos: acentos dañados y prueba de codificación de plantillas. | — | Desplegado (confirmado 05/11) |
| 05/11 | [#51](https://github.com/hidagar/soc/pull/51) | Bloque 6: informe mensual para dirección, publicado con versión inmutable, PDF y correo opcional. | 0067 | Desplegado (confirmado 05/11) |
| 05/11 | [#50](https://github.com/hidagar/soc/pull/50) | Reputación propia del SOC en observación: IPs que atacan a varios clientes. | 0066 | Desplegado (confirmado 05/11) |
| 05/11 | [#49](https://github.com/hidagar/soc/pull/49) | Q-Feeds: explicar los planes sin categoría por indicador. | — | Desplegado (confirmado 05/11) |
| 05/11 | [#48](https://github.com/hidagar/soc/pull/48) | Inteligencia Q-Feeds, fase 1: listas descargadas y coincidencias en observación, sin enviar IPs. | 0065 | Desplegado (confirmado 05/11) |

## Octubre de 2026

| Fecha | PR | Cambio | Migración | Estado |
|---|---|---|---|---|
| 30/10 | [#47](https://github.com/hidagar/soc/pull/47) | Bloque 6: avisos por correo al cliente sobre sus actuaciones. | 0064 | Desplegado |
| 30/10 | [#46](https://github.com/hidagar/soc/pull/46) | Bloque 5: plazos de atención (acuse, diagnóstico y resolución) con escalado y mantenimiento con motivo. | 0063 | Desplegado |
| 29/10 | [#43](https://github.com/hidagar/soc/pull/43), [#44](https://github.com/hidagar/soc/pull/44), [#45](https://github.com/hidagar/soc/pull/45) | Correcciones de la auditoría completa: limpieza independiente de las copias, silencio global aprendido, URL secretas fuera de los registros, fallos de plataforma en el resumen, gunicorn con hilos, auditoría incremental, SHA-1 en SSH, tamaño de respuestas, PHP y avisos de MFA. | — | Desplegado |
| 29/10 | [#42](https://github.com/hidagar/soc/pull/42) | Continuidad: IP real detrás del Nginx público, monitor exterior y ensayo de recuperación medido. | — | Desplegado |
| 29/10 | [#41](https://github.com/hidagar/soc/pull/41) | Pruebas de navegador (Playwright) en CI. | — | Desplegado |
| 29/10 | [#39](https://github.com/hidagar/soc/pull/39), [#40](https://github.com/hidagar/soc/pull/40) | Ataques a varios clientes con bloqueo común; atacantes repetidos e indicio de eficacia en UniFi. | 0062 | Desplegado |
| 28/10 | [#35](https://github.com/hidagar/soc/pull/35)–[#38](https://github.com/hidagar/soc/pull/38) | UniFi: lista y políticas de bloqueo creadas desde el SOC, orden por API y comprobación de solo lectura. | 0061 | Desplegado |
| 28/10 | [#30](https://github.com/hidagar/soc/pull/30), [#32](https://github.com/hidagar/soc/pull/32)–[#34](https://github.com/hidagar/soc/pull/34) | Revisión de la interfaz en cuatro fases: componentes comunes, bandeja, incidencias, formularios, investigación, usuarios, auditoría, exposición, inventario, mapa e informes del cliente. | — | Desplegado |
| 28/10 | [#31](https://github.com/hidagar/soc/pull/31) | Alta de equipos: reutilizar el destino syslog creado a mano. | — | Desplegado |
| 27/10 | [#29](https://github.com/hidagar/soc/pull/29) | Listas de bloqueo en UniFi mantenidas por el SOC. Su contenido está en `main` con otros hashes; el PR sigue abierto en GitHub. | 0060 | Desplegado |
| 27/10 | [#25](https://github.com/hidagar/soc/pull/25)–[#28](https://github.com/hidagar/soc/pull/28) | Listas de bloqueo fase 2: bloqueos manuales, detecciones del SOC, eficacia de la regla, lista de salida C2 y bloqueo visible para el cliente. | 0058, 0059 | Desplegado |
| 23/10 | [#23](https://github.com/hidagar/soc/pull/23), [#24](https://github.com/hidagar/soc/pull/24) | «Ver como cliente» y revisión completa: seguridad, portal, CrowdSec, despliegue e ingesta. | 0056, 0057 | Desplegado |
| 21–22/10 | [#18](https://github.com/hidagar/soc/pull/18)–[#22](https://github.com/hidagar/soc/pull/22) | CrowdSec: reputación (motor local y CTI), portal del cliente con firewalls y detecciones, listas de bloqueo del SOC (7A/C2 fase 1) y recomendador de listas. | 0050–0055 | Desplegado |
| 20/10 | [#3](https://github.com/hidagar/soc/pull/3)–[#17](https://github.com/hidagar/soc/pull/17) | Bloque 4 (CI, PostgreSQL opcional, traslado verificado, versión visible, login limitado por IP, copias con PostgreSQL, install.sh reproducible), bloque 5 (historial de tareas), bloque 6 (informes inmutables), bloque 8 (rotación de claves), pruebas de aislamiento y del control de cambios, limpieza. | 0047–0049 | Desplegado |
| 20/10 | [#1](https://github.com/hidagar/soc/pull/1), [#2](https://github.com/hidagar/soc/pull/2) | `deploy/update.sh` (primera ejecución real ese día) y menú lateral por áreas. | — | Desplegado |
| 20/10 | — | Importación inicial de la plataforma (`5162974`) y documentación del proyecto. | hasta 0046 | Desplegado antes del registro |

En GitHub siguen abiertos varios PR cuyo contenido ya está en `main`: #4–#24, #26, #27, #29, #31, #48, #54 y #56. Se pueden cerrar sin perder nada (ver [pendientes](pending.md#acciones-del-usuario-fuera-del-código)).

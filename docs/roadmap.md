# Hoja de ruta

Actualizada: 20 de octubre de 2026.



Tamaño relativo: **S** cambio acotado; **M** varias capas y pruebas integradas; **L** datos/infraestructura y ensayo de migración o recuperación. Son tamaños de planificación, no fechas comprometidas.

| Orden | Entrega | Qué recibe el equipo | Tamaño | Criterio para cerrarla |
|---|---|---|---|---|
| **1** | **Permisos, publicación e integridad inmediata** | Corregir SEC-01/02/03, DAT-01/02, ALT-01 y NOC-01. Una proyección de datos de cliente compartida por portal, enlace y PDF; prioridad antes del límite; envío independiente del escaneo. | L, dividir en cambios pequeños | Cliente ajeno recibe 404 en HTML/JSON/descargas; caso no publicado no aparece por ningún canal; consulta parcial no reemplaza informe ni avanza cursor; tormenta de 50.000 candidatos progresa; riesgo alto sigue visible. |
| **2** | **Modelo de evento e informe coherente** | Acción, motor, firma, propietario y activo históricos coherentes; corregir REP-01/02/03, DAT-03 y COM-01. Conjunto de formatos reales anonimizados por versión. | M | Un evento produce la misma interpretación en evidencia, informe, mapa y aviso; un cambio de fuentes no pierde el atraso; escaneo y malware conservan recomendaciones distintas. |
| **3** | **Ingesta durable y operación medible** | Bandeja persistente del relay HTTPS, cursores por fuente, entrega reintentable, trabajos independientes y métricas de retraso/error por cliente. | L | Reinicio en cada punto de entrega sin pérdida ni doble evidencia; reintentos idempotentes; una API caída no bloquea recepción o avisos de otras fuentes; prueba de carga reproducible. |
| **4** | **Base y despliegue preparados para crecimiento** | PostgreSQL en staging, migración verificada, backup/restore adaptado, versión de entrega visible y despliegue completo reproducible con CI. | L | Conteos, IDs y propiedad conservados; dos escritores concurrentes correctos; reconstrucción desde una VM de prueba limpia; reversión y restauración ensayadas. |
| **4A / C1** | **Contexto de reputación CrowdSec** | Tras 3B y la base de 4: enriquecer IP/incidencias/mapa mediante worker CTI con caché, cuotas y fecha del dato. Reputación separada de detección e infección; sin remediación en esta entrega. | M | Límites y plan comprobados; fallos no bloquean el SOC; aislamiento por cliente; informes históricos conservan el contexto emitido; la reputación sola no genera un caso de infección. |
| **4B / V1** | **Piloto condicional VictoriaLogs** | Medir archivo de logs y búsqueda desde incidencias en instancia aislada. Decisión de adopción por recursos, cobertura, aislamiento y recuperación; no retrasa las correcciones de 5/6. | M/L | Corpus e identidades conciliados, incluidos rechazos parciales; pruebas de reinicio/disco/retención y acceso cruzado; capacidad/coste medidos y restauración verificada. No sustituye el indexador Wazuh ni cierra 3B por sí solo. |
| **5** | **Investigación y colaboración con el cliente** | Corregir OPS-01/02 y UX-01; conversación completa, pendientes e histórico separados, SLA de acuse/investigación/resolución por cliente y severidad, mantenimiento con motivo y caducidad. | M | Reabrir tarea reabre acción; historial conserva todas las respuestas; tarea pendiente no desaparece por volumen; plazos y escalados explicables y auditados. |
| **6** | **Informes publicados verificables y comunicaciones** | Versión publicada inmutable de HTML/PDF, rectificación explícita, cobertura y fecha de corte, marca común en semanal/mensual/urgente/bienvenida y preferencias por destinatario. | M | Abrir el informe emitido meses después reproduce la versión original; los cambios de seguimiento aparecen en su espacio actual; corrección conserva ambas versiones; entrega firmada correlacionada cuando se active SendGrid. |
| **7** | **Conectores y cobertura efectiva** | Matriz fabricante/versión/capacidades; primer GCC y primer relay reales; Hillstone integrado en el recorrido API opcional; completar lectura Zenarmor cuando exista contrato contrastado, UPnP/ACL y políticas/NAT aplicados. | M/L según equipo disponible | Una muestra real por motor/red y versión, con origen/destino/acción; distinguir API accesible, logs recibidos y amenaza validada. Cada ausencia tiene motivo y siguiente paso. |
| **7A / C2** | **CrowdSec: detección y remediación controlada** (fase 1 en revisión: listas por cliente, observación, freno y plantilla OPNsense) | Tras C1 y controles de casos/auditoría: observar logs reales del reverse proxy; primer bouncer acotado al SOC, con caducidad, excepciones y retirada. Integración por cliente y versión en fases posteriores. | M/L | IP real validada; decisiones aisladas; prueba de detección, aplicación, eficacia y retirada; gestión recuperable; cero bloqueos cruzados entre clientes. Observar o emitir una decisión no acredita bloqueo efectivo. |
| **8** | **Confianza y continuidad del servicio** | Rotación de claves independiente, anclaje externo de auditoría, prueba completa de recuperación VM y monitor exterior. | M/L | Rotar sin perder MFA/secretos; detectar truncamiento de auditoría; restaurar la VM aislada y medir pérdida máxima de datos y tiempo de recuperación. |

Las pruebas de autorización, navegador y concurrencia deben acompañar todas las entregas. La auditoría y la recuperación se preparan desde el primer bloque; su cierre depende de disponer del destino y laboratorio necesarios.



## Actualización: solicitudes al SOC desde el portal (06/11/2026)

El cliente pide al SOC desde su portal:
- consultas;
- cambios;
- desbloqueos;
- sospechas de incidente.

El SOC las atiende desde su bandeja:
- responde (con aviso por correo sin el texto);
- pide información o resuelve;
- añade notas internas;
- abre una incidencia enlazada.

Detalle: [operación](operations.md#solicitudes-de-clientes).

Pendiente: plazos de respuesta para las solicitudes, adjuntos y solicitudes en el informe mensual.

## Actualización: avisos de vulnerabilidad dirigidos (06/11/2026)

El SOC cruza el modelo y la versión de cada firewall con las CVE de NVD (gravedad alta o crítica, o explotadas según CISA). Revisa, publica al cliente con una nota y el portal muestra el seguimiento hasta la versión corregida. Se envía un solo correo por cliente y el resultado cuenta en el factor «Firmware al día» del índice. Detalle: [operación](operations.md#avisos-de-vulnerabilidad-dirigidos).

Pendiente:
- llevar las vulnerabilidades avisadas al informe mensual;
- vigilar UniFi Network Application si se obtiene su versión;
- productos de Hillstone y Grandstream con datos reales.

## Actualización: avisos urgentes por Teams y Telegram (06/11/2026)

Los avisos urgentes llegan también a un canal de Teams (flujo de Workflows) o a un grupo de Telegram (bot del SOC), con el mismo contenido que el correo, prueba antes de activar y una sola publicación por aviso y canal. Detalle: [informes y correo](reports-and-mail.md#avisos-urgentes-por-teams-y-telegram).

Pendiente: crear el bot del SOC y probarlo con un cliente real; avisos de actuaciones o del informe mensual por chat si se piden.

## Actualización: conexión a Internet por sede (06/11/2026)

Se recogen las caídas de Internet que notifican los firewalls UniFi. Se muestran por sede en el portal, en el informe mensual y en la ficha del SOC.

No hay duración ni porcentaje de disponibilidad: el fabricante no envía la recuperación, y OPNsense no envía sus alarmas de gateway (comprobado con los datos reales). Detalle: [operación](operations.md#conexión-a-internet-por-sede).

Pendiente: duración mediante el estado de las consolas en la nube de UniFi.

## Actualización: índice de seguridad del cliente (06/11/2026)

Implementado el índice de seguridad, de 0 a 100, con 8 factores medidos por el SOC y una foto diaria con su evolución. Se ve en el portal (resumen y página propia, con los 3 pasos que más lo mejorarían), en el informe mensual y en la ficha del cliente. Detalle: [operación](operations.md#índice-de-seguridad-del-cliente).

Siguientes ideas de valor para el cliente:
- disponibilidad de Internet por sede;
- avisos urgentes por Teams (hecho, también Telegram);
- avisos de vulnerabilidad dirigidos (hecho);
- solicitudes al SOC desde el portal (hecho).

## Actualización: bloque 8, anclaje externo de la auditoría (06/11/2026)

Implementado el ancla diaria de la auditoría por correo:
- comprobación automática de las anclas enviadas, con aviso crítico si se borra o altera el final de la cadena;
- comprobación manual de un ancla recibida por correo desde «Auditoría».

Detalle: [seguridad](security.md).

Pendiente del bloque: rotación de `SECRET_KEY`, ensayo completo de recuperación de la VM y configurar la URL del monitor exterior.

## Actualización: bloque 6, informe mensual para dirección (05/11/2026)

Implementado el informe mensual para dirección:
- calculado con los informes semanales del mes y lo ya publicado al cliente;
- valoración del SOC;
- versión inmutable con rectificación;
- marca común en página, PDF y correo;
- correo opcional por cliente, con enlace firmado y sin reintento si el resultado es dudoso.

Detalle: [informe mensual](reports-and-mail.md#informe-mensual-para-dirección).

Con esto el bloque 6 queda cubierto. Pendiente: mostrar al cliente el cumplimiento de los plazos de atención, cuando se decida qué publicar sobre casos internos.

## Actualización: reputación propia del SOC, observación (05/11/2026)

Implementada la reputación propia del SOC: IPs que atacan a varios clientes, clasificadas en confirmada, propia o en observación, con frenos contra falsos positivos.

La página mide si la lista habría protegido a otros clientes: cuántas IPs marcadas atacan después a un cliente nuevo. Detalle: [integraciones](integrations.md#reputación-propia-del-soc-observación).

Pendiente: distribuirla como opción de la lista de bloqueo de cada cliente, cuando la medida preventiva lo justifique.

## Actualización: inteligencia Q-Feeds, fase 1 (05/11/2026)

Implementada la descarga de las listas de Q-Feeds como fuente de inteligencia del SOC, en modo observación:
- copia local con vigencia;
- consulta en «Investigar IP»;
- coincidencias con los orígenes entrantes y, por primera vez, con los destinos salientes de los clientes, sin enviar IPs a terceros.

Detalle: [integraciones](integrations.md#inteligencia-q-feeds-fase-1).

Comprobado con una clave real del plan gratuito, que no incluye categorías por indicador.

Pendiente:
- fase 2: firewalls propios de ib-red, con el plugin oficial y la regla creada por el SOC con control de cambios;
- fase 3: firewalls de clientes, solo con acuerdo escrito de licencia.

## Actualización: bloque 6, avisos de actuaciones (30/10/2026)

Implementado el aviso por correo al cliente al asignar, devolver o validar una actuación publicada. Es opcional por cliente, con bandeja propia y sin reintento automático si el resultado es dudoso. Lleva solo el título, la fecha y el enlace al portal. Detalle: [avisos de actuaciones](reports-and-mail.md#avisos-de-actuaciones). Pendiente del bloque: informe mensual para dirección con versión publicada inmutable y correo mensual opcional.

## Actualización: bloque 5, plazos de atención (30/10/2026)

Implementados: plazos de acuse, diagnóstico y resolución por gravedad (globales y por cliente), hitos registrados la primera vez que ocurren, escalado con constancia en el caso, auditoría y aviso (crítico y por correo con gravedad alta o crítica), cola y columna en la bandeja, panel en la ficha y mantenimiento con motivo y caducidad (30 días). Detalle: [operación](operations.md#plazos-de-atención-sla). Pendiente del bloque: horario laboral, pausa mientras se espera al cliente y mostrar el cumplimiento al cliente (informes). Desactivados hasta que se activen en «Plazos de atención».

## Actualización: 4A/C1 en revisión (21/10/2026)

Reputación CrowdSec implementada con caché, fecha del dato y filtro de privacidad, solo para el equipo SOC y sin remediación. Modo gratuito preferente: listas del motor local (lista comunitaria y de la consola), comprobado contra un motor real; la API CTI de pago se combina con las listas para las IPs prioritarias, con cupo diario y mensual. Pendiente: instalar e inscribir el motor en la VM y decidir si comparte señales (lista completa o «Lite»); mostrarla en incidencias, mapa o informes requiere decidir qué se publica al cliente (y, en informes, congelarla con la versión publicada).

## Actualización: 3B servidor desplegado (20/10/2026)

Bandeja cifrada, confirmación por mensaje del motor nativo, identidad estable en el índice y deduplicación de evidencias/contadores. Pruebas de cortes, reinicio y repetición en laboratorio, y servicios privados comprobados con systemd. El Syslog anterior conserva su recorrido.

No se cierra el bloque 3 completo: falta el piloto real. El usuario ha descartado por ahora instalar un reenviador Linux en una sede. No se sustituye esa validación por pruebas de laboratorio. El siguiente bloque de desarrollo independiente es PostgreSQL y despliegue reproducible (4).

Detalle: [Entrega confirmada Wazuh 3B](entrega-wazuh-https.md).

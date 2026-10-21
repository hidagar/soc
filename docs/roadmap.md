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
| **7A / C2** | **CrowdSec: detección y remediación controlada** | Tras C1 y controles de casos/auditoría: observar logs reales del reverse proxy; primer bouncer acotado al SOC, con caducidad, excepciones y retirada. Integración por cliente y versión en fases posteriores. | M/L | IP real validada; decisiones aisladas; prueba de detección, aplicación, eficacia y retirada; gestión recuperable; cero bloqueos cruzados entre clientes. Observar o emitir una decisión no acredita bloqueo efectivo. |
| **8** | **Confianza y continuidad del servicio** | Rotación de claves independiente, anclaje externo de auditoría, prueba completa de recuperación VM y monitor exterior. | M/L | Rotar sin perder MFA/secretos; detectar truncamiento de auditoría; restaurar la VM aislada y medir pérdida máxima de datos y tiempo de recuperación. |

Las pruebas de autorización, navegador y concurrencia deben acompañar todas las entregas. La auditoría y la recuperación se preparan desde el primer bloque; su cierre depende de disponer del destino y laboratorio necesarios.



## Actualización: 4A/C1 en revisión (21/10/2026)

Reputación CrowdSec implementada con caché, fecha del dato y filtro de privacidad, solo para el equipo SOC y sin remediación. Modo gratuito preferente: listas del motor local (lista comunitaria y de la consola), comprobado contra un motor real; la API CTI de pago queda como alternativa con cupo. Pendiente: instalar e inscribir el motor en la VM y decidir si comparte señales (lista completa o «Lite»); mostrarla en incidencias, mapa o informes requiere decidir qué se publica al cliente (y, en informes, congelarla con la versión publicada).

## Actualización: 3B servidor desplegado (20/10/2026)

Bandeja cifrada, confirmación por mensaje del motor nativo, identidad estable en el índice y deduplicación de evidencias/contadores. Pruebas de cortes, reinicio y repetición en laboratorio, y servicios privados comprobados con systemd. El Syslog anterior conserva su recorrido.

No se cierra el bloque 3 completo: falta el piloto real. El usuario ha descartado por ahora instalar un reenviador Linux en una sede. No se sustituye esa validación por pruebas de laboratorio. El siguiente bloque de desarrollo independiente es PostgreSQL y despliegue reproducible (4).

Detalle: [Entrega confirmada Wazuh 3B](entrega-wazuh-https.md).

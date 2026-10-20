# Estado y traspaso para continuar el desarrollo

**Fecha del registro: 20/10/2026.** Revalidar antes de operar producción.

## Qué hay construido

Aplicación Django de gestión para equipos SOC y clientes: clientes/sedes/firewalls, onboarding guiado, credenciales cifradas, inventario, detecciones e incidentes, tareas, protección y cobertura, exposición, mapa, informes, invitaciones/MFA, SendGrid, auditoría, copias y dashboards Wazuh con acceso mediado por sesión.

La versión importada estaba en `codex/soc-platform-2026-10-20` (commit de importación `5162974`). `main` conservaba entonces únicamente el commit inicial. Comprobar el estado de ramas actual; no trabajar desde una base vacía por asumir otro flujo.

A 20/10/2026, `main` y `codex/soc-platform-2026-10-20` apuntan al mismo commit (`ea038d9`), que incluye la aplicación y la documentación. `main` es la rama base para nuevas ramas de trabajo.

La batería completa tenía 2 fallos en `core/test_grandstream_gcc.py`: las pruebas esperaban la ruta de menú anterior del GCC (`System Settings → System Diagnosis → Syslog`) y el formato `puerto / UDP`, mientras que la plantilla `grandstream_gcc_instructions.html` ya indicaba `Networking → Maintenance → System Diagnostics → Syslog` y `destino:puerto` con `Protocol: UDP`. Se actualizaron las pruebas a la plantilla; la ruta de menú sigue pendiente de confirmar en un GCC real.

## Estado comprobado de la entrega anterior

| Área | Situación a la fecha indicada |
|---|---|
| Bloques 1 y 2 | Se registraron correcciones de permisos/publicación, integridad de consultas, propiedad histórica y contrato de interpretación v1. Ver pruebas del repositorio. |
| 3A | Bandeja HTTPS cifrada antes del 202; trabajos independientes; cursores por fuente y métricas operativas. |
| 3B servidor | Desplegado con migración `0046`, motor/DB Wazuh privados, confirmación nativa, create con ID estable y deduplicación en el portal. |
| Ensayos | Batería de 595 pruebas correcta antes del último ajuste de lector; 73 dirigidas después, ensayo concurrente SQLite y ensayo nativo de 260 mensajes/9 lotes/4 alertas. Ensayo systemd con restricciones de producción. No son cifras de capacidad garantizada. |
| Producción | Portal, manager e indexador principales y los dos servicios privados activos en la comprobación; 20 archivos cotejados; trabajo transport sin error; login HTTPS respondía. |
| Primer relay real | **Pendiente**. Cero canales HTTPS configurados en esa comprobación. El usuario descartó por ahora instalar un Linux reenviador en una sede. No reabrir esa instalación como si estuviera aceptada. |
| GitHub | Código subido a la rama de importación y hash remoto comprobado. No equivale a merge ni a despliegue automático. |

Las pruebas del laboratorio usaron base de pruebas e índices temporales separados; no se presentaron fixtures como amenazas reales de clientes.

## Próximo trabajo recomendado

**Bloque 4: base y despliegue preparados para crecimiento.** El código usa SQLite y rutas específicas de la VM; PostgreSQL, configuración multiambiente, entrega reproducible y CI aún requieren trabajo.

Secuencia propuesta para quien continúe:

1. Inventariar versión de Python/Wazuh, servicios, esquema, volúmenes y dependencias de la instalación en un registro privado.
2. Preparar staging sin credenciales reales, notificaciones externas ni rutas a equipos de clientes.
3. Hacer configurable la base sin retirar soporte de reversión; revisar JSONField, índices condicionales, fechas y reservas de escritor.
4. Ensayar migración SQLite→PostgreSQL conservando IDs, conteos, relaciones, ámbitos históricos y secretos cifrados. Ajustar secuencias y transacciones; no basta con exportar/importar filas.
5. Adaptar backup/restore y ensayar regreso a una versión compatible. No reutilizar directamente el backup SQLite como respaldo PostgreSQL.
6. Versionar la entrega completa (código, esquema, reglas, servicios, objetos Wazuh y perfil privado), añadir CI y demostrar reconstrucción/rollback en VM aislada.

Cerrar cuando existan evidencias de migración, concurrencia, recuperación, aislamiento y reconstrucción. No cambiar la base de producción solo porque se haya añadido un driver.

## Pendientes que siguen abiertos

- Piloto real del canal HTTPS y muestras reales por motor/red/versión, especialmente GCC y ClamAV. La API cloud accesible no acredita amenazas recibidas.
- Zenarmor oficina: exportación Syslog sujeta a licencia/capacidad real; la activación SOHO/Business se dejó pendiente.
- SendGrid: activación del webhook firmado de entrega pendiente por decisión del usuario. Aceptado por SendGrid no significa entregado.
- SLA y conversación/histórico de tareas, publicaciones HTML/PDF inmutables y rectificaciones, matrices de cobertura y pruebas completas de continuidad: bloques 5–8.
- CrowdSec: contexto CTI primero; bloqueo controlado más adelante. VictoriaLogs: piloto condicional, sin sustituir Wazuh ni dar por cerrada la ingesta.
- Rotación independiente de claves y anclaje externo de auditoría. La cadena local no acredita por sí sola que no se borrara su tramo final.

## Para retomar sin historia del chat

Leer AGENTS, arquitectura y seguridad; comprobar rama, migraciones y servicios reales; ejecutar pruebas del área; consultar los criterios del roadmap. Registrar hechos nuevos en este archivo. No buscar credenciales en el chat ni reconstruirlas a partir de ejemplos.

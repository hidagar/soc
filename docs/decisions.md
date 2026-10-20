# Decisiones de diseño y deuda

Decisiones observables, no aprobación de cambios futuros.

| Decisión | Motivo / consecuencia |
|---|---|
| Django y templates | Portal único sin toolchain Node; las fronteras de dominio importan dentro de `core`. |
| Wazuh analizador | Portal interpreta/proyecta y opera; no duplica cada pantalla del fabricante. |
| Scope y propiedad temporal | Evita transferir histórico al dueño actual; públicos/workers autorizan explícitamente. |
| Reader separado de mTLS admin | Leer no concede aprovisionamiento de índices/roles. |
| Jobs systemd | Locks, límites y fallos independientes sin Celery/Redis; dispatcher correcto no acredita finalización. |
| Bandeja cifrada antes de 202 | Persistencia verificada antes de retirar lote local. |
| Motor nativo privado | Recibo por mensaje sin archivo global ni cambio de Filebeat; mantener proceso, DB y perfil adicionales. |
| ID/create estable y verificación | HTTP correcto puede no dejar documento; dedup de portal no equivale a correlación exactamente una vez. |
| Revisar v1 ambiguo | UDP pudo llegar; no inventar ACK antiguo. |
| Invitación | Usuario elige contraseña; enlace de un uso resistente a lectura por escáner. |
| Correo con enlace | Formato acordado con descarga web; firma no implica snapshot inmutable. |
| SQLite actual | Reservas/ensayos de concurrencia; PostgreSQL y su recuperación son bloque 4. |
| CrowdSec/VictoriaLogs condicionados | CTI/piloto pueden aportar contexto; no corrigen por sí solos ingesta/aislamiento ni están desplegados como 3B. |

## Deuda visible

- Infraestructura reproducible, CI, versiones, migración PostgreSQL.
- Publicaciones inmutables/rectificación, SLA/conversaciones y corpus real ampliado.
- Rotación versionada de claves y anclaje externo de auditoría.
- Piloto de relay y recuperación VM con RPO/RTO medidos.
- Rutas fijas y utilidades históricas en `deploy/`: no son herramientas genéricas.

Cambiar una decisión requiere plan de migración, pruebas, efectos operativos y actualización de [traspaso](handoff.md)/[roadmap](roadmap.md), sin reescribir la historia.

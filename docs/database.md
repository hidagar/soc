# Base de datos del portal: SQLite y PostgreSQL

Estado: **20/10/2026**. Producción sigue en SQLite. PostgreSQL está soportado por el código y la batería de pruebas, pero ninguna instalación real lo usa todavía.

## Selección

`SOC_PORTAL_DB_ENGINE` elige el motor (`sqlite` por defecto, `postgresql`); el resto de variables está en [configuración](configuration.md). El driver va aparte (`requirements-postgresql.txt`) para no cambiar las dependencias de una instalación SQLite. Cambiar la variable **no traslada datos**: una base PostgreSQL vacía arranca un portal vacío.

## Qué se ha comprobado

| Comprobación | Resultado |
|---|---|
| Batería completa sobre PostgreSQL 16 | Correcta; también en CI en cada pull request. |
| Migraciones `0001`–`0046` sobre PostgreSQL | Se aplican desde cero sin cambios. |
| Escritores concurrentes reales (`core/test_database_concurrency.py`) | Cadena de auditoría única y válida; un lote HTTPS repetido a la vez se guarda una vez. En PostgreSQL y en SQLite de archivo. |
| Búsquedas `LIKE` con distinta sensibilidad a mayúsculas | Solo se usan con prefijos internos en minúscula: mismo resultado en ambos motores. |

## Diferencias encontradas y corregidas

- `select_for_update()` con `select_related` hacia una relación opcional falla en PostgreSQL (`FOR UPDATE cannot be applied to the nullable side of an outer join`). `evidence_repair.repair_hillstone` bloquea ahora solo la evidencia (`of=('self',)`).
- **También afectaba a SQLite en producción:** `audit()` y las filas de bloqueo de asignación HTTPS, propiedad de fuentes y VPN hacían `get_or_create` (lectura) antes del `UPDATE` que serializa. Con dos escritores a la vez, SQLite devolvía `database is locked` sin esperar, contrario al invariante 7. `WorkerState.reserve()` escribe primero; el ensayo concurrente fallaba siempre antes del cambio y pasa después.
- Dos pruebas dependían de SQLite: una IP construida con `pk` (en PostgreSQL los ID no se reinician entre pruebas) y un texto no IP guardado en un campo IP (PostgreSQL valida el tipo `inet`).

## Componentes que todavía solo admiten SQLite

Se niegan explícitamente con PostgreSQL en lugar de trabajar sobre el archivo SQLite abandonado:

- `core/recovery.py` (copia cifrada): marca la copia como fallida.
- `deploy/sync_wazuh_dashboards.py` (dashboards internos): lee el motor de `/etc/soc-portal/portal.env` y se detiene.
- `deploy/update.sh`: se detiene antes de parar servicios.

Adaptarlos (bloque 4, paso 5) es requisito antes de usar PostgreSQL en producción.

## Riesgos que el traslado debe comprobar

PostgreSQL aplica restricciones que SQLite no aplica: longitud máxima de `CharField`, formato de `GenericIPAddressField`, caracteres NUL en texto y JSON, y claves foráneas. Un dato histórico que incumpla alguna hace fallar el traslado o una escritura posterior; debe detectarse antes de copiar.

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

## Traslado de SQLite a PostgreSQL

`python manage.py transfer_database` (código en `core/database_transfer.py`) copia la base SQLite a la conexión `default`, que debe ser PostgreSQL:

1. **Origen:** una copia consistente, nunca la base en uso. Sirve la que deja `deploy/update.sh` en `/var/backups/soc-portal/<copia>/portal.sqlite3`, hecha con la API backup y los escritores parados. Se abre en solo lectura.
2. **Destino:** base PostgreSQL nueva con `migrate` ejecutado con el **mismo commit**. Se niega si las migraciones aplicadas difieren o si ya hay clientes o usuarios.
3. **Comprobación previa** (`--check`, no escribe): busca lo que SQLite admite y PostgreSQL rechaza (textos más largos que `max_length`, IP no válidas, caracteres NUL en texto y JSON, enteros fuera de rango y claves foráneas huérfanas). Informa por tabla, campo y número de filas, **sin mostrar valores**. No necesita PostgreSQL: puede ejecutarse ya en la VM sobre una copia de la base real para saber si sus datos son trasladables.
4. **Copia** (`--replace-target`): una sola transacción. Vacía las tablas del destino (también grupos, permisos y tipos sembrados por las migraciones, que se sustituyen por los del origen), copia todas las tablas con sus claves primarias, sin que `auto_now`/`auto_now_add` reescriban fechas, y ajusta las secuencias.
5. **Verificación antes de confirmar:** filas y huella SHA-256 por tabla, calculadas en origen y destino sobre valores normalizados (JSON con claves ordenadas, IP canónicas, fechas en UTC) e independientes del orden. Cualquier diferencia deshace todo el traslado.

```sh
SOC_PORTAL_DB_ENGINE=postgresql ... python manage.py migrate
SOC_PORTAL_DB_ENGINE=postgresql ... python manage.py transfer_database --source /ruta/copia.sqlite3 --check
SOC_PORTAL_DB_ENGINE=postgresql ... python manage.py transfer_database --source /ruta/copia.sqlite3 --replace-target
```

Ensayado en el contenedor de desarrollo con PostgreSQL 16 y datos anonimizados (66 tablas, 50 636 filas, 50 000 evidencias): 12 s, verificación correcta, inicio de sesión con la contraseña copiada, secreto MFA descifrable, cadena de auditoría íntegra, ámbito de cliente aplicado y nuevas filas con ID posteriores a los copiados. **No es un ensayo con la base real** ni mide el tiempo de producción. Las pruebas `core/test_database_transfer.py` repiten el traslado en CI.

El traslado no cambia el motor del servicio: después habría que añadir las variables al entorno protegido, instalar `requirements-postgresql.txt` y reiniciar. No hacerlo en producción hasta adaptar la copia y la restauración (apartado anterior) y ensayar el regreso a SQLite.

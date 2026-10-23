# Copias y recuperación

## Almacenes distintos

Portal SQLite, índices/objetos/seguridad OpenSearch, RBAC/API Wazuh, secretos/configuración, proxy/red, copias de firewalls y estado del motor privado requieren tratamientos propios. Exportar Django no cubre toda la solución.

`recovery.py`: copia consistente de la base del portal (API backup de SQLite o `pg_dump` con PostgreSQL; ver [base de datos](database.md)), snapshot nativo, manifiesto/hashes, cifrado y verificación. `recovery_components.py`: perfil/componentes exigidos. RBAC se copia separadamente evitando WAL obsoleto. Revisar rutas exactas de la versión instalada.

| Evidencia | Qué acredita |
|---|---|
| local_verified | Archivo local validado, no persistencia fuera de VM. |
| verified / external_verified | Transferencia externa comprobada según destino. |
| native_restore en detalles | Ensayo del snapshot en índices temporales con prefijo propio: una muestra (el índice más reciente de cada familia, más los objetos guardados), no todo el histórico. `pospuesta` si dejaría el disco del indexador por encima del 80 %; se avisa en «Salud del SOC» (`platform:restore-test`). |
| Declaración de backup VM | Información del operador; no consulta automática del hipervisor. |

El ensayo del indexador se repite a los 30 días o cuando cambian las familias de índices (un cliente nuevo), no con la rotación diaria de alertas: antes cada copia diaria restauraba todos los índices en el clúster vivo y duplicaba su disco. La espera de recuperación llega a 10 minutos. Al empezar cada copia se borran los índices `soc-restore-check-*` y las carpetas `build-*` que dejara una copia cortada (contienen el entorno y la base en claro). Si systemd para la copia (SIGTERM), se ejecuta su limpieza y queda como fallida. Los archivos de copias fallidas caducan con la misma retención.

El usuario realiza copias de VM: no inventar/configurar SFTP por ello. Registrar fecha/destino externo y restaurar en aislamiento. No afirmar RPO/RTO sin medir pérdida máxima y tiempo real.

## Claves

`/etc/soc-portal/recovery.key` queda fuera del archivo que cifra. Custodia separada y recuperación ensayada. Claves de conectores, SECRET_KEY, reader y proxy deben recuperarse con los datos compatibles; regenerarlas no descifra valores previos.

No subir `.socbak`, tar, snapshots, bases o entornos a GitHub, ni en repositorios privados.

## Motor HTTPS

Copia interna incluye su `etc`, pero no acredita restaurar todas las correlaciones. La copia VM debe cubrir `/var/lib/soc-wazuh-https`. Bandeja SQL/UID permiten reintentar transporte; no reconstruyen por sí solos el estado interno exacto de Wazuh.

## Ensayo

VM/red aislada, sin salida a equipos reales, correos ni IP en conflicto. Validar manifiesto/rutas, restaurar claves/configuración/DB/snapshots bajo procedimiento revisado; arrancar dependencias, verificar permisos, scope, HTML/PDF, SSO, colas/trabajos. Comparar IDs, conteos y propiedad. Medir tiempos y faltantes.

No lanzar recuperación como prueba inocua en producción. Revisar prefijos y limpieza de índices temporales antes de autorizar el ensayo. Bloque 4 debe adaptar backup/restore antes de migrar a PostgreSQL.

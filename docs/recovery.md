# Copias y recuperación

## Almacenes distintos

Portal SQLite, índices/objetos/seguridad OpenSearch, RBAC/API Wazuh, secretos/configuración, proxy/red, copias de firewalls y estado del motor privado requieren tratamientos propios. Exportar Django no cubre toda la solución.

`recovery.py`: backup SQLite consistente, snapshot nativo, manifiesto/hashes, cifrado y verificación. `recovery_components.py`: perfil/componentes exigidos. RBAC se copia separadamente evitando WAL obsoleto. Revisar rutas exactas de la versión instalada.

| Evidencia | Qué acredita |
|---|---|
| local_verified | Archivo local validado, no persistencia fuera de VM. |
| verified / external_verified | Transferencia externa comprobada según destino. |
| native_restore en detalles | Ensayo específico del snapshot en índices temporales y ámbito. |
| Declaración de backup VM | Información del operador; no consulta automática del hipervisor. |

El usuario realiza copias de VM: no inventar/configurar SFTP por ello. Registrar fecha/destino externo y restaurar en aislamiento. No afirmar RPO/RTO sin medir pérdida máxima y tiempo real.

## Claves

`/etc/soc-portal/recovery.key` queda fuera del archivo que cifra. Custodia separada y recuperación ensayada. Claves de conectores, SECRET_KEY, reader y proxy deben recuperarse con los datos compatibles; regenerarlas no descifra valores previos.

No subir `.socbak`, tar, snapshots, bases o entornos a GitHub, ni en repositorios privados.

## Motor HTTPS

Copia interna incluye su `etc`, pero no acredita restaurar todas las correlaciones. La copia VM debe cubrir `/var/lib/soc-wazuh-https`. Bandeja SQL/UID permiten reintentar transporte; no reconstruyen por sí solos el estado interno exacto de Wazuh.

## Ensayo

VM/red aislada, sin salida a equipos reales, correos ni IP en conflicto. Validar manifiesto/rutas, restaurar claves/configuración/DB/snapshots bajo procedimiento revisado; arrancar dependencias, verificar permisos, scope, HTML/PDF, SSO, colas/trabajos. Comparar IDs, conteos y propiedad. Medir tiempos y faltantes.

No lanzar recuperación como prueba inocua en producción. Revisar prefijos y limpieza de índices temporales antes de autorizar el ensayo. Bloque 4 debe adaptar backup/restore antes de migrar a PostgreSQL.

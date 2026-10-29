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

La copia diaria (03:15) se crea si ese día local aún no tiene ninguna en cola, en curso o correcta (`queue_daily_backup`). Antes se comparaba con la fecha UTC: si el temporizador se recuperaba entre las 00:00 y las 02:00 tras un apagado, la copia del día anterior contaba como la de hoy.

Tras una copia verificada se retiran las copias y snapshots que superan la retención. Si eso falla (por ejemplo, el repositorio de snapshots no responde), la copia sigue verificada y se avisa aparte (`platform:backup-retention`, advertencia); antes ese fallo la marcaba como fallida con aviso crítico. La limpieza de detecciones antiguas ya no depende de las copias: véase [operación](operations.md#conservación-de-datos).

El usuario realiza copias de VM: no inventar/configurar SFTP por ello. Registrar fecha/destino externo y restaurar en aislamiento. No afirmar RPO/RTO sin medir pérdida máxima y tiempo real.

## Claves

`/etc/soc-portal/recovery.key` queda fuera del archivo que cifra. Custodia separada y recuperación ensayada. Claves de conectores, SECRET_KEY, reader y proxy deben recuperarse con los datos compatibles; regenerarlas no descifra valores previos.

No subir `.socbak`, tar, snapshots, bases o entornos a GitHub, ni en repositorios privados.

## Motor HTTPS

Copia interna incluye su `etc`, pero no acredita restaurar todas las correlaciones. La copia VM debe cubrir `/var/lib/soc-wazuh-https`. Bandeja SQL/UID permiten reintentar transporte; no reconstruyen por sí solos el estado interno exacto de Wazuh.

## Ensayo

Con copias de VM, «Salud del SOC» avisa (`platform:restore-rehearsal`) si no hay un ensayo registrado con la pérdida de datos y el tiempo medidos, o si tiene más de 6 meses.

Procedimiento:

1. **Aislar.** Restaurar la copia más reciente de la VM como una VM nueva **sin red** o en una red sin salida (sin acceso a los firewalls de clientes, UniFi, CrowdSec, SendGrid ni a la IP de producción). Anotar la hora de inicio.
2. **Parar lo que habla con el exterior** antes de dar red interna a la VM: `sudo systemctl disable --now 'soc-*.timer'`.
3. **Arrancar** `soc-portal`, Wazuh y PostgreSQL si lo usa, y ejecutar como en `update.sh`:
   `sudo bash -c 'eval "$(python3 /srv/soc-portal/deploy/envfile.py --shell /etc/soc-portal/portal.env)"; cd /srv/soc-portal && runuser -u socportal -- /opt/soc-portal-venv/bin/python manage.py comprobar_restauracion'`
   Es solo lectura. Muestra si quedan temporizadores con salida activos, migraciones, recuentos, el último dato de cada tipo, la cadena de auditoría (que también confirma `SECRET_KEY`) y si las claves descifran los valores guardados. No muestra IPs, clientes ni claves.
4. **Probar a mano** desde un equipo de la red aislada: acceso con MFA, una ficha de cliente, un informe HTML/PDF y los dashboards de Wazuh. Anotar la hora en que todo funciona.
5. **Medir.** Pérdida de datos: «Última detección recibida» del clon frente a la hora en que se hizo la copia restaurada (o el mismo dato en producción en ese momento). Tiempo: del paso 1 al paso 4.
6. **Registrar** en «Copias y recuperación» la fecha, la confirmación de red aislada, la referencia, la pérdida (horas) y el tiempo (minutos). El aviso desaparece.
7. **Destruir el clon** cuando termine: contiene datos y claves reales.

Requisitos generales: VM/red aislada, sin salida a equipos reales, correos ni IP en conflicto. Validar manifiesto/rutas, restaurar claves/configuración/DB/snapshots bajo procedimiento revisado; arrancar dependencias, verificar permisos, scope, HTML/PDF, SSO, colas/trabajos. Comparar IDs, conteos y propiedad. Medir tiempos y faltantes.

No lanzar recuperación como prueba inocua en producción. Revisar prefijos y limpieza de índices temporales antes de autorizar el ensayo. Bloque 4 debe adaptar backup/restore antes de migrar a PostgreSQL.

# Entrega confirmada del canal HTTPS a Wazuh (3B)

Fecha: 20 de octubre de 2026.

## Alcance

Cada lote nuevo recibido por HTTPS se guarda cifrado antes de responder 202. Cada mensaje tiene un identificador estable derivado del canal, lote, huella y posición. El 202 acredita almacenamiento, no una detección.

El worker envía al socket Unix de una instancia nativa de Wazuh separada, con su propia base interna y una copia verificada de los decodificadores y reglas instalados. No se habilita el archivo global del manager principal ni se modifica Filebeat. El encabezado de transporte cambia para transportar la identidad; el programa y cuerpo se conservan en los formatos ensayados. Los mensajes JSON usan un adaptador de transporte; el motor nativo conserva su clasificación.

El archivo nativo confirma el procesamiento. Se comprueba identidad, origen y huella del mensaje, se sincroniza el archivo a disco y se guarda la confirmación SQL. Un mensaje sin alerta queda como procesado, sin crear una amenaza ficticia.

Las alertas nativas de nivel 3 o superior se publican con una operación create y un identificador estable. Se consulta el documento indexado y se compara antes de darlo por confirmado. Un éxito HTTP del indexador no basta. La proyección de evidencias y contadores se deduplica en la transacción SQL. La primera clasificación nativa confirmada queda congelada para la publicación.

## Cortes y errores

- Si el motor no responde, el mensaje sigue en la bandeja cifrada; se reintenta con espera creciente. Tras ocho envíos sin confirmación queda retenido para revisión.
- Si el indexador falla, se conserva el resultado nativo cifrado. Los reintentos de publicación esperan al menos 60 segundos.
- Un reinicio entre indexación y commit permite repetir create y verificar el documento existente, sin sumar otra evidencia o contador.
- Una reasignación de cliente retiene el lote pendiente para revisión de su ámbito.
- Los lotes anteriores v1 conservan el tratamiento de envíos UDP ambiguos. No se puede atribuir retroactivamente una confirmación a esos envíos.

No se garantiza ejecución exactamente una vez dentro del motor nativo: sus correlaciones pueden observar reenvíos después de una interrupción ambigua. La identidad estable evita duplicar el documento y su proyección en el portal. Tampoco se garantiza la entrega del primer salto Syslog UDP desde el firewall al reenviador.

## Operación y recuperación

Servicios: `soc-wazuh-https-db.service`, `soc-wazuh-https.service`; temporizador `soc-https-delivery.timer`, que ejecuta el trabajo transport con su exclusión mutua. Salud del SOC comprueba ambos servicios y la antigüedad de las colas.

Árbol privado: `/var/lib/soc-wazuh-https/var/ossec`. Límites: base interna 256 MiB; proceso de análisis 1 GiB; pausa de nuevos envíos si los logs privados superan 512 MiB o el espacio libre cae por debajo del 15 %. El almacenamiento de la bandeja sigue limitado por canal y globalmente. Estos límites no son una capacidad de tráfico garantizada.

Los archivos privados cerrados caducan a las 24 horas. Se preservan los archivos activos. El cuerpo cifrado de un lote confirmado y la copia cifrada de su alerta indexada se eliminan a los siete días; los pendientes se conservan. Las marcas compactas de deduplicación permanecen.

Después de actualizar Wazuh o sus reglas, el perfil debe verificarse y sincronizarse. El worker se detiene ante una huella distinta y conserva la bandeja. Procedimiento: detener los dos servicios privados, ejecutar `deploy/wazuh/prepare_https_engine.py /var/lib/soc-wazuh-https --pipeline ID_VERIFICADO`, iniciar primero la base y luego el motor, comprobar transport. No detener el manager principal. La copia completa de VM debe incluir el árbol privado. La copia interna del portal incluye su configuración, pero no acredita una restauración de las correlaciones internas del motor; eso necesita la copia de VM.

## Validación

Pruebas unitarias de identidades, confirmación, archivo parcial, fsync anterior al commit, duplicados, reasignación, errores de socket y publicación. Ensayo nativo optativo `core.test_native_pipeline`, con base Django de archivo aislada, motor privado de laboratorio e índice temporal exclusivo: lote repetido, caída del motor, clasificación de cuatro familias, caída del indexador, reinicio y repetición tras create.

La parte servidor de 3B está desplegada. Migración 0046 aplicada; 20 archivos verificados por SHA-256, sin diferencias. Portal, manager e indexador principales, analizador privado, base privada y temporizador activos. Trabajo transport completado sin error. Cero canales HTTPS configurados en producción; no se han generado amenazas de laboratorio en los índices de clientes.

Verificación: batería completa Linux de 595 pruebas correcta (dos ensayos requieren ejecución separada). Después del ajuste final de generación de archivos: 73 pruebas dirigidas correctas, ensayo SQLite de archivo con dos escritores correcto, ensayo nativo de 260 mensajes/9 lotes y 4 alertas correcto. Reenvío tras reinicio y create repetido mantienen cuatro evidencias y los mismos contadores. Índice temporal con las mismas plantillas de producción; borrado comprobado al terminar. Los servicios privados también se probaron con systemd, restricciones de escritura y límites de memoria.

El ensayo incluye indisponibilidad del motor e indexador y repetición de un lote después de una confirmación HTTP perdida. El endpoint se ejercita con el cliente de pruebas Django; no se presenta como una prueba de una sede ni una medición de capacidad garantizada de la red.

Copia de reversión anterior al despliegue: `/home/deploy/soc-third-b-backup-20261020T150743Z`.

La ruta privada de indexación conserva la configuración nativa, admite fechas ISO8601 con precisión completa y devuelve errores en vez de descartar el documento. La ruta original permanece intacta. [Formato de fecha del procesador de OpenSearch](https://docs.opensearch.org/latest/ingest-pipelines/processors/date-index-name/). No hay piloto en una sede: el usuario ha descartado por ahora el reenviador Linux. El bloque 3 completo no se da por cerrado con pruebas de laboratorio.

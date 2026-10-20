# Ingesta y significado de las confirmaciones

## Dos recorridos coexistentes

1. **Existente:** firewall → Syslog UDP 5514 → manager principal → Filebeat/indexador → lector local/reconciliación del portal.
2. **HTTPS opcional:** firewall → UDP LAN 5515 → relay con SQLite → HTTPS por canal → bandeja cifrada → motor Wazuh privado → archivo nativo → índice → proyección del portal.

El segundo permite cambiar IP pública sin usarla como identidad. Requiere un reenviador/emisor compatible; no convierte automáticamente un firewall Syslog en cliente HTTPS. El piloto en sede está pendiente.

```mermaid
sequenceDiagram
  participant R as Relay
  participant P as Portal
  participant D as Bandeja SQL
  participant W as Wazuh privado
  participant I as Indexador
  R->>P: UUID de lote + mensajes + Bearer
  P->>D: Guardar cifrado y digest en transacción
  P-->>R: 202 con confirmación durable
  Note over R: Retirar lote solo tras verificar respuesta
  P->>W: Worker envía frame con UID estable
  W-->>P: Archivo nativo; fsync antes de ACK SQL
  alt Alerta de nivel 3 o superior
    P->>I: create con ID estable
    P->>I: mget y comparación del documento
    P->>D: Evidencia, contador y confirmación idempotentes
  else Sin alerta
    P->>D: Procesado sin inventar amenaza
  end
```

## Contrato del receptor

`POST /ingest/<uuid:channel_id>/`, HTTPS obligatorio, `Authorization: Bearer <clave del canal>`, `Content-Type: application/json`.

Ejemplo de estructura, **no una orden de inyección en producción**:

```json
{"batch_id":"00000000-0000-4000-8000-000000000001","messages":["mensaje de laboratorio"]}
```

Entre 1 y 32 mensajes por lote; una línea UTF-8 de hasta 8192 bytes por mensaje, controles limitados, cuerpo de hasta 128 KiB. Límite por canal: 200 lotes/minuto y 10 MiB/minuto. Cola pendiente: hasta 64 MiB por canal y 256 MiB globales de payload contabilizado. Son límites de admisión, no SLA de rendimiento.

| Resultado | Significado |
|---|---|
| 202 | Persistencia cifrada; validar `persisted`, UUID, digest y cantidad. No basta el status. |
| 202 duplicate | UUID/digest ya conocido; no crear otro lote. |
| 400 | HTTPS/cuerpo/formato inválido; corregir origen. |
| 401 | Canal/token no autorizado, revocado o fuera de ámbito. |
| 409 | UUID reutilizado con otro contenido; no cambiar payload pendiente. |
| 429 | Cuota temporal; conservar lote y esperar. |
| 503 | Receptor no preparado o cola sin capacidad; conservar y revisar. |
| 405 / 413 | Método/cuerpo fuera del contrato. |

El digest es SHA-256 del JSON compacto de la lista (`ensure_ascii=False`, separadores `,` y `:`). El relay conserva UUID tras una respuesta perdida. `wazuh_processed` cambia tras cerrar la confirmación; `wazuh_verified` permanece separado y no acredita una prueba de detección.

## Motor privado y deduplicación

`wazuh_delivery.py` deriva UID de canal/lote/digest/posición, reemplaza encabezado de transporte y conserva programa/cuerpo en formatos ensayados. No se presume soporte para todo Syslog: RFC5424/desconocidos se conservan opacos hasta disponer de adaptador contrastado.

El recibo nativo debe coincidir en alias, marcador y huella. El lector soporta rotación/compresión y comprueba generación antes de saltarse bytes. Congela el primer resultado confirmado. Alertas: documento `soc-relay-<uid>` con create y verificación; pipeline privado con fechas precisas y errores explícitos. `projected_at` y la transacción evitan doble contribución al portal.

## Cortes, limpieza y límites

Ocho intentos sin confirmación llevan a revisión; no se borran pendientes. Publicación al índice espera al menos 60 segundos ante incertidumbre. Perfil cambiado obliga a verificar/sincronizar reglas/binarios. Archivos privados cerrados: 24 h; cuerpos confirmados y alertas cifradas indexadas: siete días. Marcas de deduplicación permanecen. Pausa por logs privados >512 MiB o espacio libre <15 %, con mínimo de seguridad.

La ejecución interna de Wazuh es al menos una vez: un reenvío ambiguo puede afectar correlación interna. El documento/proyección estable no debe duplicarse. El primer salto UDP sigue sin garantía. Recibos v1 conservan revisión de envíos ambiguos; no inventar un ACK retroactivo.

Más detalle: [entrega 3B](entrega-wazuh-https.md), [relay](../deploy/relay/LEEME.md), `test_wazuh_delivery`, `test_durable_operations` y `test_native_pipeline`.

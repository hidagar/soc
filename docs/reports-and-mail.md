# Informes, publicaciones y comunicaciones

## Del dato al informe

`reporting.py` consulta el indexador con reader limitado, fuentes y propiedad temporal; mantiene un informe por cliente/lunes. Ventana semanal en Europe/Madrid. Consulta parcial, timeout o fallo de shards no debe sustituir el último informe válido ni presentarse como cero incidencias.

`event_contract.py`, `findings.py` y el contexto aportan acción, motor, activo y recomendaciones. Software del equipo no es versión del motor. No atribuir infección por firma/reputación aislada. Los conteos describen datos recibidos, no toda la actividad del fabricante.

## Superficies y publicación

- Interna: contexto/permisos del operador.
- Cliente autenticado y enlace: `service_development.customer_report_context`, con datos publicables. No filtrar solo el listado dejando una descarga sin scope.
- PDF: ReportLab con el mismo contexto de cliente; no volver a consultar el contexto interno para renderizar.
- `ReportShare`: firma, nonce, revocación y caducidad. Concede acceso a ese informe, no al panel.
- `CustomerPublication`: comunicación visible vinculada a cliente/incidencia/informe; notas internas no se publican automáticamente.

Los enlaces actuales tienen vigencia de 90 días en `report_sharing.py`. Publicación completamente inmutable con rectificaciones versionadas sigue pendiente; firma no equivale a instantánea histórica.

## Correo

SendGrid se configura en el panel: clave cifrada, región, remitente probado, reply-to y copia. Preferencias/direcciones semanales y urgentes son distintas del contacto general y requieren activación. Pauta acordada: **semanal**, formal, logo de empresas, `ib-red` en minúsculas y enlace HTTPS; sin PDF adjunto, con descarga web. La instalación usa NOC como respuesta/copia; comprobar valores vivos en MailSettings.

`weekly_soc_reports --send` puede enviar correos reales; sin esa opción actualiza informes. `poll_urgent_alerts` escanea y entrega pendientes, incluso si falla una fase; no es diagnóstico inocuo. `send_test_email` genera un envío real.

## Entrega

`MailDispatch` correlaciona envío/destinatario y `MailEvent` deduplica. `/reports/delivery-events/` exige firma ECDSA, tamaño, ventana temporal, dispatch y destinatario coincidente. Procesa processed/delivered/deferred/bounce/dropped; no confiar en JSON sin firma.

La activación del webhook quedó pendiente por decisión del usuario. Hasta observar eventos firmados, indicar aceptación del proveedor, no entrega. Una petición incierta pudo enviar correo: revisar antes de repetir.

## Bienvenida y urgentes

Invitación de un solo uso y 48 h: usuario establece contraseña sin que el administrador la elija. GET de escáner no consume el enlace. Avisos urgentes usan interpretación común, agrupación/estado y acuse; no convertir toda alerta menor o fallo del colector en ataque al cliente.

Revisar HTML, texto, PDF, logo y pruebas de scope al cambiar comunicaciones. Véase [frontend](frontend.md) e [inventario de pruebas](reference/verification.md).

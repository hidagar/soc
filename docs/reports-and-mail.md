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

## Avisos de actuaciones

Con «Avisar por correo de las actuaciones del portal» activado en la ficha del cliente (desactivado por defecto), el cliente recibe un correo cuando una actuación publicada en su portal:

- **se le asigna:** se publica pendiente, o el SOC la vuelve a dejar pendiente;
- **se le devuelve:** el SOC pide más información («Requiere más información»);
- **se valida:** el SOC la da por buena.

Guardar sin cambiar el estado, un borrador, la respuesta del propio cliente o una cancelación no avisan. El destinatario es «Correo para avisos de actuaciones» o, si está vacío, el de contacto (después, el de informes).

El correo lleva la marca común, el nombre de la empresa, el título de la actuación, la fecha acordada y el enlace al portal, donde se entra con MFA. **Nunca** las instrucciones, la respuesta del SOC, el caso interno ni datos técnicos (invariante 3).

Cada aviso es una fila `CustomerNotice` que envía el trabajo «Avisos operativos» (cada minuto, hasta 5 por vuelta):

- Si antes del envío la actuación cambió de estado, se despublicó o el cliente desactivó los avisos, queda «Ya no aplica».
- Un error de configuración queda «No enviado».
- Un error de red, o un envío interrumpido más de 10 minutos, queda «Por comprobar» y **no se reintenta solo** (invariante 6).
- La aceptación de SendGrid queda «Aceptado por SendGrid»; la entrega se sigue en «Entrega y avisos» como «Aviso de actuación».

El último aviso de cada tarea aparece en la ficha de la incidencia.

## Versiones publicadas (inmutables)

El cliente nunca ve el informe calculado en el momento: ve una `ReportVersion` congelada (HTML y PDF con sus SHA-256). La versión 1 se crea al enviar el informe o, si se publicó sin correo, la primera vez que el cliente lo abre por el portal o el enlace firmado. Después no cambia aunque cambien sedes, equipos, casos, publicaciones o el propio `WeeklyReport`.

Rectificar (ficha del informe, permiso `manage_connections`) congela el contenido actual como versión siguiente con un motivo obligatorio que el cliente ve; no envía correo. El portal del cliente lista todas las versiones y permite abrir cada una y su PDF (`?version=N`); el enlace firmado muestra la última con el aviso de rectificación. Los cambios de seguimiento posteriores aparecen en «Seguimiento y próximos pasos», no en informes ya publicados.

Cada versión guarda el PDF en la base (del orden de cien KB por informe y semana). Las versiones congeladas antes de esta entrega no existen: los informes ya enviados se congelan con el contenido del primer acceso posterior al despliegue.

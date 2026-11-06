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

### Avisos urgentes por Teams y Telegram

Los avisos urgentes pueden llegar también a un canal de Microsoft Teams o a un grupo de Telegram del cliente (`core/chat_alerts.py`). El correo sigue saliendo igual; el chat es una copia con el mismo contenido (`urgent_alerts.content`): qué ha pasado, equipo, origen, acción del firewall y qué hacer. Las URL del registro se desactivan (`hxxp://`) y los corchetes se cambian para que no haya enlaces pulsables.

- **Dónde:** ficha del cliente › «Servicios del cliente» › «Avisos urgentes por Teams o Telegram» › «Configurar». Guardar, probar o activar exige `change_client` y MFA reciente; desactivar no espera al MFA. Todo queda auditado sin el destino.
- **Orden:** guardar el destino, «Enviar mensaje de prueba», comprobar que ha llegado y «Activar». Cambiar el destino desactiva el canal hasta repetir la prueba. Solo salen los avisos creados después de activar, dentro del plazo de envío inmediato (2 h); los ya revisados por el SOC, los de caídas de Internet sin esa opción y los repetidos de la última hora no salen.
- **Teams:** en el canal, «⋯ › Workflows» y la plantilla «Publicar en un canal cuando se recibe una solicitud de webhook». Solo se aceptan URL HTTPS de flujos de Microsoft (`*.logic.azure.com`, `*.powerplatform.com`, `*.webhook.office.com`), sin seguir redirecciones. La URL lleva su firma: se guarda cifrada con `SOC_PORTAL_MAIL_KEY` y no se vuelve a mostrar. Teams responde 202: «Aceptado por Teams» indica que el flujo aceptó la tarjeta, no que se publicara.
- **Telegram:** un bot único del SOC (`SOC_PORTAL_TELEGRAM_BOT_TOKEN`, ver [configuración](configuration.md)). El cliente añade el bot a su grupo; «Buscar grupos del bot» (acceso global, porque muestra los grupos de todos los clientes) lista los grupos de las últimas 24 h con su identificador. «Publicado en Telegram» se confirma con el identificador del mensaje.
- **Entrega:** un registro por aviso y canal (`ChatNotice`, restricción única), reservado antes de llamar a la API. Un rechazo se reintenta hasta 3 veces (Telegram 429: lo que pida esperar). Un corte de conexión, un tiempo agotado o un 5xx quedan «Entrega por comprobar» y **no se reintentan**: podría haberse publicado. Lo envía `poll_urgent_alerts` cada minuto, después del correo; un fallo del chat no retrasa el correo.
- **Límites:** el chat no sustituye al correo (los avisos urgentes siguen necesitando su correo activado); no hay confirmación de lectura; el token del bot va en la ruta de la API de Telegram, así que los errores se describen con texto propio, sin URL ni respuesta del fabricante.

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

## Informe mensual para dirección

`core/monthly_report.py`, desde «Resumen mensual» del cliente (sección «Informe mensual para el cliente»). El resumen ejecutivo de esa página sigue siendo interno del SOC; el informe mensual es una proyección distinta, solo con lo que ya se publica al cliente (invariante 3):

- **Cifras:** la suma de los informes semanales de las semanas que **empiezan** en el mes, para que coincidan con lo que el cliente recibió cada semana. Se comparan con el mes anterior solo si tiene todas sus semanas.
- **Contenido:**
  - evolución por semanas y firewalls con datos;
  - bloqueo proactivo (cifras agregadas del mes);
  - hasta 5 recomendaciones de los hallazgos semanales, por frecuencia;
  - comunicaciones publicadas;
  - actuaciones del portal validadas en el mes y pendientes al publicar;
  - la **valoración del SOC**, texto libre que se escribe al publicar.
- **Nunca incluye:** incidencias sin publicar, acciones o notas internas, ni borradores de tareas.

**Publicación** (permiso `change_incident`):
- Solo cuando han terminado el mes y su última semana, y cada semana se puede publicar (recopilación completa y propiedad verificada). Si no, la página explica qué falta.
- «Vista previa para el cliente» muestra el resultado con los datos de hoy sin congelar nada.
- Publicar congela HTML y PDF como versión 1 (`MonthlyReportVersion`, con SHA-256). Dos publicaciones simultáneas no crean dos versiones.
- Rectificar (`manage_connections`) añade la versión siguiente con motivo, y puede cambiar la valoración. No envía correo.
- El cliente lo ve en «Informes», con sus versiones y el PDF.

**Correo opcional:** en la ficha del cliente, «Informe mensual», con un destinatario propio (por ejemplo, dirección) o el de informes.
- Al publicar se puede enviar en el mismo paso. Lo envía el trabajo «Avisos operativos» con copia a NOC, como el semanal.
- El correo solo lleva un enlace firmado a `/reports/mensual-<token>/`, válido 90 días, revocable y renovable desde la página. Los registros de Django y Nginx ocultan el token con las reglas del semanal.
- Un error de red o un envío interrumpido queda «Por comprobar» y no se repite solo. Reenviarlo exige confirmar que se ha revisado «Entrega y avisos», donde figura como «Informe mensual».
- Con el envío activado, si el informe del mes anterior sigue sin publicar 3 días después de poder publicarse, se abre un aviso en «Salud del SOC» (`report:monthly:<cliente>`).


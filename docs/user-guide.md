# Guía funcional para entender el producto

Los nombres de menús pueden evolucionar; las rutas/handlers están en la referencia. Usar un entorno de desarrollo para recorrer estos flujos sin cambiar equipos o enviar correo reales.

## Operador

1. Acceder por correo y contraseña propia; completar MFA. El perfil de cuenta limita clientes y acciones.
2. Crear/seleccionar cliente y sede. Al añadir sede desde cliente, conservar ese contexto; no debe abrir acceso al catálogo de otros clientes.
3. Añadir equipo con fabricante/perfil (incluido OPNsense + Zenarmor). Elegir gestión API/SSH cuando se necesite automatización, o instrucciones manuales cuando basten.
4. Completar dirección remota/selección cloud/MAC y credenciales solo en formularios específicos. Inventario descubre datos disponibles sin borrar los últimos hechos conocidos si falla una lectura.
5. Configurar exportación siguiendo el wizard. Revisar conflictos, categorías, destino, protocolo y red protegida. API conectada no cierra la recepción.
6. Comprobar evento real recibido e interpretado. La validación de amenaza es un paso aparte; dejarlo pendiente si no se puede generar/observar una muestra real segura.
7. Consultar Salud del SOC y bandeja de trabajo. Investigar detecciones, activos, acciones, exposición y cobertura; asignar tareas/runbook y publicar solo la comunicación apropiada.
8. Revisar informe y acciones propuestas antes de activar envío semanal/avisos. Publicación y dirección de contacto no equivalen a preferencias de correo activadas.

## Cliente

Recibe invitación para establecer contraseña. La cuenta pertenece exactamente a su empresa; puede consultar comunicaciones e informes publicados, responder tareas permitidas y acceder a su dashboard Wazuh si el ámbito está preparado. El mapa agregado es opcional. No accede a notas/secretos del operador ni a incidentes internos por el hecho de existir.

Con «Mostrar firewalls y detecciones en el portal del cliente» activado en la ficha del cliente (desactivado por defecto), el portal añade:

- **Firewalls:** por equipo, sede, fabricante, modelo, versión, estado resumido («Protegido y monitorizado», «Comprobaciones en curso», «En revisión por el SOC», mantenimiento o pausa), último registro recibido, motores de protección con su estado y modo IPS/IDS, aviso de actualizaciones disponibles y detecciones de los últimos 7 días. No muestra los textos de las brechas del SOC, errores de gestión ni datos de conexión.
- **Detecciones:** periodo de 24 h, 7 o 30 días, con filtros por firewall y acción; totales, evolución diaria, tipo de detección, países de origen, firmas más frecuentes, IPs públicas de origen más activas y registro paginado con fecha, firewall, firma, categoría, origen, país, destino, puerto y acción. Son los mismos campos que la proyección del índice Wazuh del cliente.
- **Menú del portal** (Resumen, Firewalls, Detecciones, Mapa si está activado, Informes y Actuaciones). Informes y Actuaciones son páginas propias y siempre están disponibles: todos los informes publicados, y las tareas pendientes y las 20 cerradas más recientes. El Resumen muestra los tres últimos informes y las tareas pendientes y enlace «Panel avanzado (Wazuh)» solo cuando su ámbito Wazuh está verificado. El menú también aparece al abrir un informe o una tarea.
- **Informes:** el listado muestra el estado de cada informe («Publicado el…», «Rectificado · versión N»), no las cifras del momento, que pueden diferir de lo publicado. Una publicación que enlace un informe sin recopilación completa (semana abierta, sin fuentes o con la propiedad histórica pendiente) no lo publica: no aparece ni se congela al abrirlo.
- **Actuaciones:** «Ver tarea y responder» solo mientras está pendiente o el SOC pide más información. Tras responder, la tarea muestra «Respuesta enviada» hasta que el SOC la valide; las validadas y canceladas indican que no hay que hacer nada más.
- **Mapa:** vista agregada por país sin el detalle de eventos; en el portal se consulta como mucho cada 60 s, también en modo presentación.

**Ver como cliente (personal del SOC):** el botón «Ver como cliente» de la ficha del cliente abre su portal tal como lo ve él, con las mismas páginas, opciones activadas y proyección de datos. Es de solo lectura: no se puede responder a tareas ni cerrar su sesión. Lo pueden usar los usuarios del SOC con ese cliente en su ámbito (fuera de él da 404), y cada página consultada queda en la auditoría (`customer.preview`). Las cuentas de cliente no tienen acceso.

Nunca se muestran notas internas, recomendaciones del SOC, identificadores de Wazuh, identidades de equipos, incidencias no publicadas ni reputación CrowdSec. Las detecciones se limitan al propietario histórico de la evidencia (`client_scope_id`) que coincide con el cliente actual del equipo, como en el resto de vistas.

El correo semanal enlaza al informe web, desde donde puede descargar PDF. No se adjunta PDF. Un enlace firmado está limitado a ese informe y puede caducar/revocarse; no da acceso al panel entero.

## Pantallas y significado

| Pantalla | Pregunta que responde |
|---|---|
| Conexiones / ficha | ¿Podemos gestionar el equipo y qué inventario se conoce? |
| Wizard / recepción | ¿Está configurada la salida y se ha recibido/interpretado un evento? |
| Salud del SOC | ¿Funcionan tareas y servicios? ¿Hay silencio, atraso o errores? |
| Protección/cobertura | ¿Qué motor/red está configurado, observado y validado? |
| Detecciones / investigación | ¿Qué evidencia llegó, qué acción indicó el motor y qué activo puede atribuirse? |
| Bandeja/incidencias/tareas | ¿Qué requiere trabajo, quién lo atiende y qué se ha comunicado? |
| Mapa | ¿Desde/hacia qué infraestructura pública se observaron eventos? No acredita identidad del atacante. |
| Auditoría | ¿Quién hizo qué acción y cuándo? No sustituye logs del firewall ni anclaje externo. |
| Copias | ¿Qué copia y verificación existen? No prueba por sí sola una restauración VM completa. |

Eliminar una sede o cambiar propiedad no es una limpieza inocua: revisar relaciones, permisos y datos históricos según el formulario/constraints. No usar una operación masiva para saltarse las señales de propiedad.

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

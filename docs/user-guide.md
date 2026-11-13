# Guía funcional para entender el producto

Los nombres de menús pueden evolucionar; las rutas/handlers están en la referencia. Usar un entorno de desarrollo para recorrer estos flujos sin cambiar equipos o enviar correo reales.

## Operador

1. Acceder por correo y contraseña propia; completar MFA. El perfil de cuenta limita clientes y acciones.
2. **Alta guiada en 7 pasos:** cliente → sede → firewall → conexión → envío de logs → comprobación → servicios.
   - «+ Añadir cliente» abre el paso 1: nombre y, si se quiere, contacto. El identificador se genera solo.
   - Cada paso lleva al siguiente. Al confirmar la recepción, «Activar los servicios del cliente» abre su panel de servicios.
   - Se puede dejar a medias: la ficha del cliente indica el siguiente paso («Añadir la primera sede», «añadir firewall», «Continuar asistente»).
   - Un equipo nuevo siempre se da de alta con el asistente; la edición del cliente solo tiene sus datos básicos.
   - **«Servicios del cliente»**, en la ficha del cliente y en la de cada sede, reúne todo lo que se activa:
     - **Se editan ahí, con un solo botón:** portal (firewalls y detecciones, mapa en vivo), informe semanal y mensual por correo, avisos urgentes (y caídas de Internet) y avisos de actuaciones, cada uno con su destinatario.
     - **Se ven con su estado y un enlace a su página,** que conserva MFA y control de cambios: avisos urgentes por Teams o Telegram, lista de bloqueo, plazos de atención, informe mensual y panel Wazuh.
     - **Avisos de vulnerabilidad:** activarlo para que el cliente reciba un correo cuando el SOC publique vulnerabilidades de sus firewalls. Se revisan y publican en «Cobertura y salud › Vulnerabilidades».
     - **Teams o Telegram:** guardar el canal, enviar la prueba, comprobar que llega y activar. Solo salen los avisos nuevos; el correo sigue saliendo igual.
     - **Acceso al portal:** con administración de seguridad y acceso global, «Dar acceso al portal» crea la cuenta del cliente (solo verá ese cliente) y le envía la invitación en un paso. Pide el MFA reciente. La lista muestra quién tiene la invitación pendiente.
   - **«Sedes y firewalls»** (o «Firewalls de esta sede») muestra por equipo la recepción de registros, Zenarmor, la regla de bloqueo del SOC y las copias de configuración.
3. Añadir equipo con fabricante/perfil (incluido OPNsense + Zenarmor). Elegir gestión API/SSH cuando se necesite automatización, o instrucciones manuales cuando basten.
4. Completar dirección remota/selección cloud/MAC y credenciales solo en formularios específicos. Inventario descubre datos disponibles sin borrar los últimos hechos conocidos si falla una lectura.
5. Configurar exportación siguiendo el wizard. Revisar conflictos, categorías, destino, protocolo y red protegida. API conectada no cierra la recepción.
6. Comprobar evento real recibido e interpretado. La validación de amenaza es un paso aparte; dejarlo pendiente si no se puede generar/observar una muestra real segura.
7. Consultar Salud del SOC y bandeja de trabajo. Investigar detecciones, activos, acciones, exposición y cobertura; asignar tareas/runbook y publicar solo la comunicación apropiada.
   - El menú lateral muestra junto a «Solicitudes de clientes», «Vulnerabilidades» y «Políticas propuestas» cuántas esperan al SOC, en rojo si hay algo urgente.
   - «Línea de tiempo», en la ficha de cada cliente, reúne por día todo lo ocurrido con él (incidencias, avisos, solicitudes, vulnerabilidades, cambios, informes y caídas de Internet), con filtros por tipo y periodo.
   - «Inteligencia y bloqueo» reúne en pestañas la reputación CrowdSec, sus listas, las listas de bloqueo, Q-Feeds y la reputación propia.
   - El buscador del menú (tecla `/`) encuentra clientes, sedes, firewalls, incidencias, solicitudes (`SOL-`), políticas (`POL-`), CVE e IPs.
8. Atender los plazos de cada caso (si están activados en «Plazos de atención»): asumirlo es el acuse; la primera nota, acción, tarea para el cliente o comprobación de la guía es el diagnóstico. La cola «Plazo vencido o próximo» de la bandeja ordena lo urgente.
9. Con Q-Feeds configurado, revisar en «Inteligencia Q-Feeds» las conexiones salientes permitidas hacia indicadores de malware o C2: cada una es un motivo para investigar el equipo interno, no una infección confirmada.
10. Con acceso global, «Reputación propia» muestra las IPs que atacan a varios clientes y si, una vez marcadas, atacaron después a otros: es la medida para decidir si distribuir esa lista. No bloquea nada.
11. Atender las **solicitudes de clientes** («Respuesta › Solicitudes de clientes», también en la bandeja). Opciones:
    - **Responder:** el cliente lo ve en su portal y recibe un aviso por correo sin el texto. Al responder se elige si la solicitud queda en curso, esperando al cliente o resuelta.
    - **Nota interna:** no la ve el cliente.
    - **Asignársela.**
    - **Abrir una incidencia enlazada:** se usa cuando hay que investigar.

    Si los plazos de solicitudes están activados («Plazos de atención»), cada una muestra hasta cuándo hay que dar la primera respuesta y resolverla; las vencidas salen en el resumen.

    Las nuevas, y las que tienen un mensaje nuevo del cliente, llegan por correo al «Correo de operaciones» (Copias y recuperación). Si el cliente marca «afecta al trabajo ahora», el aviso lleva «URGENTE».
12. Revisar las **políticas propuestas** («Cobertura y salud › Políticas propuestas»):
    - Descartar las que no proceden.
    - Ofrecer las demás al cliente, con una explicación y una ventana.
    - Cuando el cliente apruebe, aplicar en la ventana y marcarlas como aplicadas. Para «restringir un servicio» en un OPNsense con API, «Preparar con el control de cambios» crea el plan con los orígenes autorizados; al confirmarlo activo, la propuesta se marca sola. El SOC comprueba el efecto a partir de los 7 días.
13. Revisar informe y acciones propuestas antes de activar envío semanal/avisos. Publicación y dirección de contacto no equivalen a preferencias de correo activadas.

## Cliente

Recibe invitación para establecer contraseña. La cuenta pertenece exactamente a su empresa; puede consultar comunicaciones e informes publicados, responder tareas permitidas y acceder a su dashboard Wazuh si el ámbito está preparado.

**Cambios propuestos** (portal › «Cambios propuestos», solo si el SOC ha ofrecido alguno):
- El SOC propone cambios en sus firewalls, con el motivo en cifras y una ventana.
- El cliente los aprueba o los rechaza con su código de doble factor, y puede dejar un comentario (por ejemplo, la IP de su proveedor).
- Nada se aplica sin su aprobación, y el historial muestra si se aplicaron y comprobaron.

**Solicitudes al SOC** (portal › «Solicitudes»):
- Elige qué necesita: consulta, cambio en el firewall o la red, desbloquear algo o sospecha de incidente. Después indica el asunto, la sede (opcional), el detalle y si afecta al trabajo ahora.
- Sigue la conversación y recibe un correo, sin el texto, cuando el SOC responde.
- Puede cerrarla cuando está resuelta y reabrirla, si no lo está, durante 14 días.
- Límites: 20 abiertas a la vez y 10 nuevas al día. El mapa agregado es opcional. No accede a notas/secretos del operador ni a incidentes internos por el hecho de existir.

Con «Mostrar firewalls y detecciones en el portal del cliente» activado en la ficha del cliente (desactivado por defecto), el portal añade:

- **Firewalls:** por equipo, sede, fabricante, modelo, versión, estado resumido («Protegido y monitorizado», «Comprobaciones en curso», «En revisión por el SOC», mantenimiento o pausa), último registro recibido, motores de protección con su estado y modo IPS/IDS, aviso de actualizaciones disponibles y detecciones de los últimos 7 días. No muestra los textos de las brechas del SOC, errores de gestión ni datos de conexión.
- **Detecciones:** periodo de 24 h, 7 o 30 días, con filtros por firewall y acción; totales, evolución diaria, tipo de detección, países de origen, firmas más frecuentes, IPs públicas de origen más activas y registro paginado con fecha, firewall, firma, categoría, origen, país, destino, puerto y acción. Son los mismos campos que la proyección del índice Wazuh del cliente.
- **Menú del portal** (Resumen, Firewalls, Detecciones, Mapa si está activado, Informes y Actuaciones). Informes y Actuaciones son páginas propias y siempre están disponibles: todos los informes publicados, y las tareas pendientes y las 20 cerradas más recientes. El Resumen muestra los tres últimos informes y las tareas pendientes y enlace «Panel avanzado (Wazuh)» solo cuando su ámbito Wazuh está verificado. El menú también aparece al abrir un informe o una tarea.
- **Índice de seguridad:** una cifra de 0 a 100 en el resumen y en su propia página, con lo que suma y lo que resta, los 3 pasos que más la subirían y su evolución. También aparece en el informe mensual, congelado con su versión, y el SOC lo ve en la ficha del cliente. Véase [operación](operations.md#índice-de-seguridad-del-cliente).
- **Conexión a Internet:** el resumen muestra, por sede, las caídas de Internet que ha notificado su firewall en 30 días. Se indica cuándo un firewall no informa de caídas, y no se muestra la duración porque el fabricante no la envía. Véase [operación](operations.md#conexión-a-internet-por-sede).
- **Informes mensuales:** cuando el SOC publica el informe del mes, aparece en «Informes» por encima de los semanales, con su PDF y sus versiones. Si el cliente lo pide, también llega un enlace por correo a la dirección. Véase [informe mensual](reports-and-mail.md#informe-mensual-para-dirección).
- **Informes:** el listado muestra el estado de cada informe («Publicado el…», «Rectificado · versión N»), no las cifras del momento, que pueden diferir de lo publicado. Una publicación que enlace un informe sin recopilación completa (semana abierta, sin fuentes o con la propiedad histórica pendiente) no lo publica: no aparece ni se congela al abrirlo.
- **Actuaciones:** «Ver tarea y responder» solo mientras está pendiente o el SOC pide más información. Tras responder, la tarea muestra «Respuesta enviada» hasta que el SOC la valide; las validadas y canceladas indican que no hay que hacer nada más.
- **Avisos de actuaciones por correo:** con la opción activada en la ficha del cliente, recibe un correo al asignarle, devolverle o validarle una actuación, con el título y el enlace al portal; las instrucciones solo se ven en el portal. Véase [avisos de actuaciones](reports-and-mail.md#avisos-de-actuaciones).
- **Bloqueo proactivo:** si el SOC aplica su lista de bloqueo en el firewall del cliente, la página Firewalls y el informe semanal indican cuántas IPs maliciosas contiene y cuántos paquetes bloqueó, sin mostrar las IPs ni los motivos.
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
| Auditoría | ¿Quién hizo qué acción y cuándo? Con ancla diaria por correo para detectar borrados. No sustituye los logs del firewall. |
| Copias | ¿Qué copia y verificación existen? No prueba por sí sola una restauración VM completa. |

Eliminar una sede o cambiar propiedad no es una limpieza inocua: revisar relaciones, permisos y datos históricos según el formulario/constraints. No usar una operación masiva para saltarse las señales de propiedad.

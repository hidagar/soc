# Operación diaria y trabajos

## Qué revisar

Salud del SOC: servicios, último éxito/duración/reintentos de cada trabajo, cola/antigüedad, fuentes ambiguas y detección verificada. El programador correcto solo prueba que lanzó tareas. API, exportación, recepción y amenaza validada son controles separados.

```sh
sudo systemctl is-active soc-portal wazuh-manager wazuh-indexer
sudo systemctl is-active soc-wazuh-https soc-wazuh-https-db soc-https-delivery.timer
sudo systemctl list-timers 'soc-*'
sudo journalctl -u soc-job@transport.service -n 50 --no-pager
```

Journal es información privada: redactar antes de adjuntarlo a un issue. No imprimir entorno ni reader para diagnosticar.

## Monitor exterior

Las comprobaciones de «Salud del SOC» y el correo de operaciones no pueden avisar si cae la VM entera. Para eso:

- **Latido saliente** (recomendado): crear un control en un servicio externo de latidos (p. ej. Healthchecks.io, periodo 5 minutos y gracia 10) y poner su URL en `SOC_PORTAL_HEARTBEAT_URL`. El trabajo `health` la llama cada 5 minutos si el SOC está sano y llama a `<URL>/fail` al momento si no. El servicio externo avisa por correo o móvil cuando la llamada falta o falla. No se envía ningún dato del SOC.
- **Consulta** `GET /healthz/`: sin sesión, responde `200 ok` o `503 revisar`, sin más detalle. Sirve para monitores que consultan (UptimeRobot, el monitor de la red); el proxy público debe dejar pasar esa ruta.

«Sano» significa que el trabajo `health` terminó hace menos de 5 minutos y no hay abierto ninguno de estos fallos: portal, Wazuh manager o indexador detenidos, disco por debajo del 15 %, monitor de avisos urgentes atrasado o **silencio de todos los equipos** (`platform:ingest-silence`, crítico, también por correo). Los avisos menores (IP real, ensayo de recuperación pendiente) no cambian el resultado.

El silencio global se compara con la misma franja horaria de los 7 días anteriores, porque la recepción solo cuenta alertas de Wazuh (varias reglas del SOC son de nivel 0) y de noche puede pasar una hora sin nada sin que falle nada. Se avisa si pasa una **hora completa sin ningún evento** que esos 7 días siempre tuvo al menos 10; antes, a los **30 minutos** si a esas horas siempre llegan más de 60 por hora; y siempre a las **24 horas**. Sin una semana de historia, a las 6 horas. Hasta la versión de octubre de 2026 el umbral era fijo de 30 minutos y podía dar avisos críticos falsos de madrugada.

## Resumen y portal

- «Requiere atención» incluye **Fallos de la plataforma del SOC** (copias, disco, servicios, recepción global, cadena de auditoría) para el personal con acceso global; antes solo contaba los problemas de equipos, y justo los más graves no aparecían.
- Gunicorn arranca con `deploy/gunicorn.conf.py`: 2 procesos con 8 hilos cada uno. Con procesos de un solo hilo, dos acciones lentas a la vez (UniFi, CrowdSec, OPNsense) dejaban sin atender la ingesta HTTPS y las descargas de las listas de bloqueo, que llegan a este mismo servicio (medido: el login esperaba 15 s con cuatro peticiones lentas en curso; ahora 0,14 s). Nginx sigue cortando la respuesta al navegador a los 30 s, pero la operación termina.

## Plazos de atención (SLA)

Administración → «Plazos de atención» (acceso global y permiso de operaciones) fija, por gravedad, tres objetivos desde que el caso entra en el SOC: **acuse** (alguien lo asume, se le asigna responsable o pasa a investigación), **diagnóstico** (primer avance documentado: nota, acción, tarea para el cliente o comprobación de la guía) y **resolución**. Valores iniciales:

| Gravedad | Acuse | Diagnóstico | Resolución |
|---|---|---|---|
| Crítica | 15 min | 1 h | 1 d |
| Alta | 30 min | 4 h | 3 d |
| Media | 4 h | 1 d | 7 d |
| Baja | 1 d | 3 d | 30 d |

- Cada cliente puede tener plazos propios (un contrato con otros tiempos); lo que se deja en blanco usa el global.
- Vienen **desactivados**. Al activarlos solo cuentan los casos que entran desde ese momento: los abiertos antes no se marcan como vencidos.
- Reloj continuo (24x7). No se detiene mientras se espera al cliente; el horario laboral y la pausa por espera quedan para una fase posterior.
- Cada hito se guarda la primera vez que ocurre (`Incident.acknowledged_at`, `investigated_at`, `resolved_at`). Un caso resuelto cuenta el acuse y el diagnóstico como hechos al resolverse si no se registraron antes.
- **Escalado** (trabajo «Avisos operativos», cada minuto): al vencer un plazo se anota una vez en el historial del caso (`sla_breaches`) y en la auditoría, y se abre el aviso `sla:<caso>:<hito>` en «Salud del SOC». Con gravedad alta o crítica es crítico y llega por correo de operaciones a los 5 minutos. El aviso se cierra al cumplirse el hito; la constancia del vencimiento queda en el caso.
- Dónde se ve: indicador y cola «Plazo vencido o próximo» (queda menos de una cuarta parte del plazo) y columna «Plazo» en la bandeja; panel «Plazos de atención» en la ficha; fila «Incidencias con plazo de atención vencido» en el resumen.

El mantenimiento de un equipo exige motivo y dura como máximo 30 días; el motivo aparece en «Salud del SOC».

## Conservación de datos

El trabajo horario `housekeeping` borra, por bloques y con un minuto como máximo por ejecución, las detecciones sin incidencia y los contadores por hora más antiguos que «Retención de evidencias» (Copias y recuperación, 90 días por defecto) y los intentos de acceso de más de un día (`core/retention.py`; último resultado en `WorkerState` «retention»). Antes solo se hacía al final de una copia correcta: con copias fallidas la base crecía sin límite, y un borrado de golpe retenía el escritor de SQLite.

## Versión instalada

«Salud del SOC» muestra a quien tiene acceso global el commit instalado, su fecha y el motor de base. Lo registra `deploy/update.sh` en `/srv/soc-portal/.deployed-commit`; una instalación que no se haya actualizado con el script aparece como «sin registrar».

## Programación

`soc-monitor.timer` invoca dispatcher; `run_soc_job` toma lock por nombre. `JOBS` define 16 tareas separadas. `soc-job@.service` limita ejecución a 180 s y escritura a rutas permitidas; intervalos no garantizan latencia máxima. HTTPS añade timer de 5 s tras finalizar la unidad. Véase [referencia](reference/jobs.md).

Timers semanales y urgentes coexisten con dispatcher. Revisar unidad/overrides reales; no duplicar programación por intuición.

| Acción | Efectos |
|---|---|
| `monitor_soc --no-notify` | Programa trabajos root; omite notifications/invitations del dispatcher. No es modo global de solo lectura: otras tareas/timers escriben o envían según configuración. |
| `run_soc_job <job>` | Ejecuta tarea protegida con sus efectos. |
| `sync_wazuh_sources` | Cambia receptor/reglas y puede reiniciar Wazuh tras validar. |
| `weekly_soc_reports` | Refresca informes; con `--send`, envía activados. |
| `poll_urgent_alerts` | Escanea y envía pendientes. |
| `rebuild_customer_projection --client ID` | Reencola proyección derivada; no borra evidencia original. |
| `operate_soc vpn/changes/backup` | Red/sistema, firewall o copia; no diagnóstico de lectura. |

## Backlog HTTPS

Revisar recibos por equipo. `confirmed` v2: procesados y alertas verificadas; `forwarded` v1 sigue sin ACK. Fallos se retienen. Antes de repetir un v1 ambiguo, comprobar posible duplicado; los nuevos conservan UID. No vaciar tablas/colas para quitar una alerta operativa.

Al cambiar Wazuh/reglas, verificar y sincronizar perfil con servicios privados parados; conservar bandeja, DB y secretos. Seguir [3B](entrega-wazuh-https.md). No usar perfil de laboratorio como producción.

## Entrega

Registrar versión, migración y manifiesto; copia/reversión; distinguir generación y envío; comprobar login/MFA/scope/descargas, tareas y llegada real cuando exista equipo disponible. Registrar lo no validado. No cerrar ausencia de logs por un API correcto.

## Índice de seguridad del cliente

`core/security_score.py`. Es una cifra de 0 a 100 que resume lo que el SOC puede comprobar de la protección de un cliente. El trabajo `security_score` la calcula cada hora y guarda una foto por día (`SecurityScore`) para mostrar su evolución.

| Factor | Puntos | Cómo se mide |
|---|---|---|
| Exposición a Internet | 20 | Servicios publicados de riesgo alto (0) o medio (mitad) sin excepción documentada; control de exposición de los últimos 7 días |
| Protección en marcha | 10 | Motores en ejecución, sin detener ni en bypass |
| IPS en modo bloqueo | 10 | Suricata o el IPS de UniFi en modo IPS, frente a IDS |
| Firmware al día | 15 | OPNsense sin actualizaciones pendientes y catálogo comprobado en 7 días. Cualquier firewall con una vulnerabilidad publicada al cliente y sin resolver cuenta 0; con una pendiente de revisar por el SOC, «sin comprobar». Los que no son OPNsense cuentan como correctos si el catálogo de vulnerabilidades de su producto está al día y no tienen ninguna |
| Visibilidad del SOC | 15 | Registros recibidos sin silencio |
| Ataques que entran | 10 | Detecciones permitidas en 30 días: ninguna, hasta 10 (mitad) o más |
| Bloqueo proactivo del SOC | 10 | Lista de bloqueo publicada con regla activa |
| Actuaciones al día | 10 | Sin actuaciones visibles con la fecha acordada vencida |

**Cómo se calcula:**
- Los factores por firewall son la media de los firewalls activos del cliente.
- **Lo que no se puede comprobar cuenta la mitad** y se muestra como «Sin comprobar», con el paso para que el SOC pueda comprobarlo.
- **Niveles:** 85 o más, «Bien»; de 65 a 84, «Mejorable»; menos de 65, «Requiere atención».
- Los pesos están en `WEIGHTS` para ajustarlos.

**Qué ve el cliente:**
- En el portal: el resumen y la página «Índice de seguridad», con cada factor en texto claro (solo recuentos), los 3 pasos que más puntos darían y la evolución.
- En el informe mensual: la foto del último día del mes, comparada con la del mes anterior y congelada con la versión.
- Nunca ve IPs, títulos internos del control de exposición ni notas del SOC (invariante 3).

**Qué ve el SOC:** el índice en la ficha del cliente, que enlaza a «Ver como cliente».

**Límite:** no garantiza la ausencia de riesgos. Mide lo que el SOC comprueba.

## Conexión a Internet por sede

`core/connectivity.py`.

**Origen de los datos.** Se comprobó con los datos reales de noviembre de 2026:
- UniFi envía «Internet Down», «Multiple Internet Disconnections» y «Device Offline», pero no la recuperación de la conexión.
- OPNsense no envía al SOC las alarmas de su gateway.

Por eso se registran y se cuentan **las caídas notificadas**, sin duración ni porcentaje de disponibilidad.

**Recogida:** el trabajo `connectivity`, cada 15 minutos.
- Lee esos eventos del índice de Wazuh desde un cursor, repasando 30 minutos de margen. La primera vez recupera 35 días.
- Una consulta incompleta no avanza el cursor (invariante 5), y cada evento se guarda una sola vez (`ConnectivityEvent`).
- El evento se asigna al cliente propietario del origen en esa fecha (invariante 2) y al firewall que lo envió.

**Dónde se ve:**
- **Portal:** en el resumen, por sede y firewall, las caídas de los últimos 30 días y la última.
- **Informe mensual:** las caídas del mes por sede, congeladas con la versión. No se publica la lista de eventos.
- **SOC:** la columna «Internet (30 d)» en «Sedes y firewalls».

Los firewalls que no informan de caídas aparecen como «No informa», nunca como «Sin caídas».

**Siguiente paso:** obtener la duración consultando el estado de conexión de las consolas en la nube de UniFi, y añadir una regla de Wazuh para las alarmas de gateway de OPNsense si se envían.

## Avisos de vulnerabilidad dirigidos

`core/vulnerabilities.py`. Avisa solo a los clientes cuyo firewall tiene una versión afectada.

**Catálogo:** el trabajo `vulnerabilities` (cada hora) descarga de NVD las CVE de cada producto vigilado, como mucho una vez cada 20 horas por producto.
- Para cada CVE guarda los rangos de versiones afectadas, la gravedad CVSS y si CISA la marca como explotada activamente (KEV).
- A NVD solo se le envía el nombre del producto; nunca versiones, equipos ni datos de clientes.
- Una descarga incompleta no se guarda ni cuenta como actualizada. Si el catálogo tiene más de 3 días y falla, se abre un aviso en «Salud del SOC».
- `SOC_PORTAL_NVD_KEY` es opcional: sin ella, NVD permite 5 peticiones cada 30 segundos y la descarga va más despacio.

**Productos:**
- OPNsense: `a:opnsense:opnsense`, con la versión del inventario.
- Consolas UniFi: `o:ui:unifi_os` y el producto de su modelo (`UNIFI_MODELS`: UDM Pro, UDM SE, UCG Ultra…), con la versión de UniFi OS que da la nube.
- Otros fabricantes (Hillstone, Grandstream): NVD apenas tiene datos. El SOC puede indicar su producto en «Firewalls que no se pueden vigilar».

**Cruce:** compara la versión de cada firewall activo con los rangos.
- Solo cuentan las gravedades alta y crítica y las explotadas activamente (`DeviceExposure`).
- Si un formato de versión no se puede comparar con seguridad (por ejemplo, `5.5R10P2` frente a `5.5R10`), no se abre ni se cierra nada.
- Cuando el inventario muestra una versión corregida, se marca resuelta; si vuelve a una afectada, se reabre.
- Comprobado con NVD real (noviembre de 2026): OPNsense 25.7.3 queda afectado por 5 CVE corregidas en 26.1.4–26.1.8; una UDM Pro con 4.3.6, por 9 CVE, 3 de ellas explotadas activamente.

**Revisión del SOC:** «Cobertura y salud › Vulnerabilidades», agrupado por cliente.
- **Publicar las pendientes** (o una sola), con una nota para el cliente sobre qué hará el SOC y cuándo. Requiere `change_incident`.
- **Descartar**, con un motivo interno (falso positivo, servicio no activo). El cliente no lo ve.
- Mientras haya algo sin revisar, «Salud del SOC» muestra el aviso «Vulnerabilidades sin revisar», crítico si alguna se está explotando.

**Cliente:**
- Página del portal «Vulnerabilidades» (solo lo publicado: CVE, gravedad, versión corregida, firewalls con su versión, estado y la nota del SOC) y una tarjeta en el resumen mientras quede alguna pendiente.
- Si tiene activado «Avisos de vulnerabilidad» en «Servicios del cliente», recibe **un solo correo por cliente** con lo publicado en esa pasada. Va sin datos técnicos y enlaza al portal.
- El correo se envía desde el trabajo de avisos operativos. Un envío dudoso queda «por comprobar» y no se repite (invariante 6).

**Límites:**
- La versión del inventario puede ir con retraso respecto a la real.
- NVD puede tardar días en analizar una CVE nueva; sin rangos de versión no se puede cruzar.
- La UniFi Network Application no se vigila: la nube no da su versión.
- Una versión afectada no demuestra un ataque.

## Solicitudes de clientes

`core/customer_requests.py`, con los modelos `CustomerRequest` y `CustomerRequestEntry`.

- **Estados:** recibida, en curso, esperando al cliente y resuelta.
- **Primera respuesta:** se guarda en `first_response_at`, para medir el tiempo de respuesta.
- **Avisos del trabajo `notifications`:**
  - `notify_soc` envía un correo interno al «Correo de operaciones» con las solicitudes nuevas o con un mensaje nuevo del cliente. Las marca antes de enviar: como mucho un correo por novedad.
  - `send_pending` envía al cliente un aviso de cada respuesta del SOC (`MailDispatch` de tipo `request`). Agrupa por solicitud, no incluye el texto y, si el envío es dudoso, no lo repite.
- **Lo que ve el cliente:** sus solicitudes y los mensajes del SOC dirigidos a él. Nunca ve las notas internas ni la incidencia enlazada (invariante 3).
- **Pendiente:** plazos de respuesta para las solicitudes (hoy solo se mide la primera respuesta) y adjuntos.

## Políticas de firewall propuestas

`core/policy_proposals.py` (motor y verificación) y `core/policy_views.py` (páginas y avisos), con el modelo `PolicyProposal`. Fase 1: reducir la exposición y endurecer, con lo que el SOC ya ve.

**Qué propone el trabajo `policy_proposals`** (cada 6 horas, con 30 días de evidencia):

| Tipo | Cuándo | Confianza |
|---|---|---|
| Restringir un servicio publicado | El control de exposición ve una publicación o un permiso WAN abierto a cualquier origen, de riesgo alto o con ataques a ese puerto | Alta con ataques permitidos o 20 o más; media con algún ataque; baja sin ataques |
| Filtrar por país | Además, 20 o más ataques, al menos el 90 % de fuera de los países del cliente (`SOC_PORTAL_POLICY_HOME_COUNTRIES`, por defecto ES) y 3 o más países | Media |
| IPS en modo bloqueo | Suricata o el IPS de UniFi en modo detección según la última lectura | Alta con detecciones permitidas |
| Lista de salida C2 | Q-Feeds ve destinos de malware o control remoto y la lista de salida del SOC no está activa | Alta con conexiones permitidas |
| Lista de bloqueo del SOC | 10 o más orígenes atacan 3 veces o más y la lista no está activa | Alta desde 50 orígenes |

Cada propuesta lleva:
- la evidencia: ataques, permitidos, orígenes y países;
- el cambio con los pasos del fabricante (OPNsense o UniFi);
- lo que podría romper.

Una propuesta que nadie ha ofrecido y deja de cumplirse pasa a «Ya no aplica». Una rechazada o descartada se vuelve a proponer a los 90 días si sigue aplicando. Una verificada se reabre si la situación vuelve.

**Ciclo**, en «Cobertura y salud › Políticas propuestas»:
1. **Revisión del SOC** (`change_incident`):
   - **Ofrecer al cliente:** con un título, una explicación (se sugiere un texto con solo cifras) y una ventana. Lo que ve el cliente se congela en `customer_summary`: cifras, servicio y firewall, nunca IPs, reglas internas ni notas.
   - **Descartar:** con un motivo interno.
   - **Retirar:** quita la propuesta del portal mientras está pendiente.
2. **Cliente:** en «Cambios propuestos» del portal la aprueba o la rechaza, con un comentario opcional.
   - Exige MFA reciente (`customer_policy_decision` está en `FRESH_MFA_VIEWS`).
   - Queda registrado quién decidió y cuándo, también en la auditoría.
   - Una propuesta ya decidida no cambia.
3. **Aplicación** (`change_device`): el SOC aplica en la ventana y marca la propuesta como aplicada, con lo que cambió o el plan del control de cambios.
   - Las listas del SOC usan el control de cambios que ya existe.
   - Restringir un servicio, el filtro por país y el modo del IPS se aplican a mano con los pasos de la propuesta. La plantilla automática es la fase 2.
4. **Verificación** (a partir de 7 días):
   - Servicio restringido: el control de exposición ya no lo ve abierto a cualquier origen y no entran ataques permitidos a ese puerto.
   - IPS: está en modo bloqueo.
   - Listas: están publicadas y hay una regla activa que las usa.
   - Si no se puede comprobar en 30 días, queda «Sin efecto comprobado» con el motivo.

**Avisos** (trabajo `notifications`):
- **Al cliente:** un correo por cliente con las propuestas ofrecidas, sin detalles y con enlace al portal (`MailDispatch` de tipo `policy`). Usa la opción y el destinatario de «Avisos de actuaciones».
- **Al equipo:** las decisiones de los clientes llegan al «Correo de operaciones», como mucho una vez por decisión.

**Límites:**
- Sin el tráfico legítimo del cliente no se proponen políticas de mínimo privilegio (fase 3).
- Las cifras son de eventos recibidos: un ataque no implica éxito, y una regla aplicada no garantiza el bloqueo; por eso se verifica.
- El filtro por país depende de la base GeoIP del firewall.


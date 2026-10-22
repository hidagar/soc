# Integraciones y alta de equipos

## Flujo de alta

Cliente seleccionado → sede → equipo/perfil → método → instrucciones/configuración → recepción → validación de detección. La sede queda asociada al cliente del contexto; no aceptar otro cliente manipulando POST. OPNsense + Zenarmor es un perfil adicional, no otro fabricante.

API/SSH son opcionales cuando basta Syslog guiado. Inventario intenta descubrir modelo, firmware, serie y versión/edición Zenarmor con datos allowlisted. Desconocido no borra un hecho conocido: mostrar origen, fecha y pendiente. No exigir datos que el conector puede descubrir.

## Capacidades implementadas

| Equipo / motor | Gestión e inventario | Exportación / evidencia | Límites |
|---|---|---|---|
| OPNsense | API key/secret + CA; SSH con huella | Provisioning de destino Syslog; recepción separada | Permisos, ruta, certificado con SAN correcto; algunas lecturas SSH requieren privilegios. |
| Suricata | Descubrimiento de configuración/cobertura | Syslog EVE / JSON y reglas nativas; validación | Una casilla habilitada no acredita IPS; comprobar red/interfaz/acción real. |
| Zenarmor | Configuración/capacidad por API, asociado a OPNsense | Syslog con licencia/capacidad; decoder/rules propios | No eludir suscripción ni raspar DB de informes como reemplazo no contrastado. Revisar bypass/redes. |
| UniFi | Site Manager/Cloud Connector, selección de consola/site | Activity Logging gestionado y verificado por lectura; CEF | No equivale a todos los Flows/CyberSecure. Tratar conflictos con otro SIEM sin sobrescribirlo. |
| Hillstone | Login REST StoneOS e inventario acotado; SSH separado | Syslog y decoder/rules de amenazas | Perfil limitado por firmware; no asumir escritura API ni todas las versiones. Log-Only no es bloqueo. |
| GCC / GDMS | OAuth por región, selección remota/MAC, inventario | Syslog guiado y comprobación de recepción | No hay escritura documentada de Syslog implementada en el cliente cloud. Proxy web no es API estable. Amenaza real pendiente. |
| ClamAV | Cobertura cuando hay datos | Contemplado por contrato | Corpus v1 sin muestra real; no afirmar validación completa. |

## Reputación CrowdSec (solo lectura)

Contexto de reputación de IPs externas (hoja de ruta 4A/C1), en `core/reputation.py`. El trabajo protegido `reputation` (cada 15 minutos) consulta y guarda la caché `IpReputation`; la web solo lee la caché. Dos fuentes, cada una activa si tiene clave y combinables (modo `lapi+cti`):

| Fuente | Coste | Consulta | Caché | Qué IPs |
|---|---|---|---|---|
| Listas del motor local | Gratuito | `GET <SOC_PORTAL_CROWDSEC_LAPI_URL>/v1/decisions?ip=<ip>` con la cabecera `X-Api-Key` (clave de bouncer). La IP no sale de la VM. | 6 horas; hasta 500 IPs por ejecución | Todas las candidatas |
| API CTI | De pago | `GET https://cti.api.crowdsec.net/v2/smoke/<ip>` con `x-api-key` | 3 días; `SOC_PORTAL_CROWDSEC_DAILY_LIMIT` al día y, si se declara, `SOC_PORTAL_CROWDSEC_MONTHLY_LIMIT` al mes | Las prioritarias dentro del cupo |

Cada fuente guarda sus campos con su propia fecha y caducidad (`listed`, `list_*`, `lists_*_at` y `cti_found`, reputación, `cti_*_at`); actualizar una no borra la otra. En cada ejecución se consultan primero las listas y después la CTI, que ordena así: tráfico permitido, IPs que ya figuran en una lista, nivel más alto y repetición. Un problema de una fuente (cupo, clave, motor caído) no detiene la otra; el error se muestra en «Salud del SOC» y en la página «Reputación CrowdSec», que también muestra el consumo del cupo CTI del día y del mes. Para un plan mensual, fijar `SOC_PORTAL_CROWDSEC_MONTHLY_LIMIT` al cupo contratado y `SOC_PORTAL_CROWDSEC_DAILY_LIMIT` a ese cupo entre 31 (por ejemplo, 5000 y 160), para repartirlo durante el mes.

- **Qué IPs se consultan (ambas fuentes):** solo orígenes **públicos** de evidencias de los últimos 7 días cuyo destino es una red interna o una IP pública de un cliente. Nunca IPs internas, IPs de clientes o del SOC (orígenes Syslog, propiedad de fuentes, transporte HTTPS, IP pública Syslog) ni destinos de conexiones salientes. Orden: tráfico permitido, nivel más alto y repetición.
- **Listas:** el motor recibe la lista comunitaria (origen `CAPI`) y hasta tres listas de la consola del plan gratuito (origen `lists`). Una IP figura si tiene alguna decisión vigente, también por rango; se muestra «En lista de bloqueo» con las listas de origen, los escenarios y el rango. Sin decisiones se muestra «No figura en las listas», que **no** significa que sea benigna. 401/403 (clave) pausa seis horas; motor caído o puerto cerrado se anota en «Salud del SOC» y se reintenta en la siguiente ejecución. La URL debe ser HTTP hacia el propio equipo o HTTPS: la clave no viaja en claro por la red.
- **API CTI:** la API responde 429 a consultas casi seguidas (comprobado en la VM), así que cada ejecución envía un lote pequeño (`SOC_PORTAL_CROWDSEC_CTI_PER_RUN`, 2 por defecto) separado 15 s; cada 15 minutos da capacidad de sobra para el cupo diario. Un 429 (límite de ritmo o cupo) pausa lo que indique `Retry-After` o, si no lo indica, 15 min, 1 h y después 6 h mientras se repita; una consulta correcta reinicia la escala. 401/403 (clave) pausa seis horas; 404 se guarda como «sin datos». Se guardan reputación, confianza, ruido de fondo, puntuaciones generales, comportamientos, clasificaciones, posibles falsos positivos, ASN, país y fechas de la comunidad.
- **En ambas:** un fallo de una IP no detiene el resto; la clave nunca se guarda ni se muestra; solo se guarda el resumen mostrado, con la fecha del dato; se purga a los 90 días.
- **Dónde se ve:** «Investigar IP» y «Detecciones prioritarias», solo personal del SOC. No se muestra a clientes ni se usa en informes. La etiqueta muestra la reputación CTI si existe y la lista como complemento. En «Detecciones prioritarias», un aviso cuenta los grupos de tráfico **permitido** cuyo origen está en una lista o tiene reputación CTI maliciosa o sospechosa, y el filtro «Reputación CrowdSec» muestra esos orígenes, solo los permitidos, o **oculta el ruido de fondo** (CTI con ruido de fondo alto o posible falso positivo). El filtro actúa sobre los 500 grupos de mayor prioridad y no cambia prioridad, motivos ni orden.
- **Página «Reputación CrowdSec»** (Detección e investigación, `core/reputation_views.py`): modo y estado del trabajo; recuento por origen de las listas del motor (comunitaria, consola, detección local, manual) con sus principales motivos, que el trabajo calcula cada hora leyendo `/v1/decisions?origins=` por bloques, con memoria acotada y un máximo de 64 MiB por origen; y las IPs de origen en lista del periodo con listas, motivo, rango, clientes, detecciones y permitidas. Las detecciones se filtran con el ámbito de cliente del usuario; la web solo lee la caché y el estado, nunca consulta al motor.
- **Qué no hace:** no crea incidencias, no cambia acción, prioridad ni motivos de una detección y no bloquea nada. Estar en una lista o «ruido de fondo» alto no prueba un ataque dirigido al cliente.

## Listas de bloqueo del SOC (7A/C2, fase 1)

El SOC hace de puente entre CrowdSec y los firewalls de cada cliente (`core/blocklist.py`, «Detección e investigación → Listas de bloqueo», permiso `manage_operations`). Se activa cliente a cliente; empezar con un piloto.

1. **Qué entra en la lista:** IPs que han atacado a **algún cliente del SOC** en los últimos 7 días y que CrowdSec tiene en una lista (dato de menos de 24 h) o la CTI califica de **maliciosas** (dato vigente). «Sospechosa» no basta.
   - **Nunca entran:** el ruido de fondo y los posibles falsos positivos según la CTI, las direcciones no públicas, las IPs de clientes y del SOC (las mismas que protege la reputación) ni las **excepciones del cliente** (IPs o CIDR, una por línea).
   - **Orden y tope:** primero las que atacaron a este cliente, luego las que atacaron a más clientes (protección preventiva) y luego las de más detecciones, con un máximo configurable (2000 por defecto).
   - El trabajo `blocklists` la recalcula cada 15 minutos. Con excepciones no válidas conserva la última lista buena y lo avisa.
2. **Observación:** sin tocar el firewall, la página calcula qué habría bloqueado con las detecciones reales del cliente: IPs, detecciones y, sobre todo, cuántas fueron **permitidas** (tráfico malicioso que hoy entra).
3. **Publicación:** `GET /feeds/bloqueo/<cliente>/<token>/` devuelve una IP por línea (`text/plain`). Funciona sin sesión, porque la llama el firewall. El token es propio del cliente, se guarda cifrado y como hash, y se rota desde la página (permiso `manage_connections` y MFA reciente). Un token incorrecto da 404. La URL usa `SOC_PUBLIC_ORIGIN`: el firewall debe poder alcanzarla por HTTPS.
4. **Freno de emergencia:** «vaciar la lista» hace que la URL sirva una lista vacía y el firewall deja de bloquear en su siguiente descarga (aprox. 1 h). Para no retrasar una emergencia, detener no exige repetir el MFA; reanudar sí. Revertir la regla desde el control de cambios la retira del todo.
5. **Bloqueo en OPNsense (plantilla «Bloqueo CrowdSec del SOC»):** desde la página del cliente, con `manage_connections`, se crea un plan en «Plantillas y cambios» con:
   - un alias `SOC_CROWDSEC_<plan>` de tipo URL table que descarga la lista (actualización aprox. cada hora);
   - una regla `block` de entrada en WAN, IPv4 e IPv6, con registro, creada **desactivada**.

   Activarla sigue el flujo existente: aprobación con MFA y nombre del equipo, savepoint, verificación del acceso de gestión y confirmación, o reversión automática. El plan no guarda el token. Revertir con borrado elimina primero la regla y después el alias, y nunca reutiliza un alias con el mismo nombre que no sea suyo.

Para otros fabricantes no hay plantilla: se puede configurar a mano una tabla de IPs por URL con la misma dirección. Pendiente de fases siguientes: bloqueos manuales del analista con caducidad, bloqueo saliente (C2), UniFi y Hillstone, y la medición de eficacia con los registros de la regla. Antes de usar las listas de CrowdSec para proteger redes de terceros, revisar sus condiciones de uso para proveedores de servicios.

## Listas de CrowdSec guiadas por los ataques reales (Service API)

`core/crowdsec_catalog.py` y la página «Detección e investigación → Listas de CrowdSec» (permiso `manage_operations`; altas y bajas con `manage_connections` y MFA reciente). El trabajo protegido `crowdsec_lists` (cada 5 minutos) usa `SOC_PORTAL_CROWDSEC_SERVICE_KEY` contra `https://admin.api.crowdsec.net/v1` con la cabecera `x-api-key`.

1. **Catálogo diario:** `GET /blocklists?include_filter=all` (paginado) y, con `subscribed_only=true`, las listas que ya tiene la organización. Las Service API Keys no ofrecen permiso sobre motores (`GET /engines` da 403, comprobado con una clave real con todos los permisos de la consola), así que por defecto se suscribe la **organización** (`entity_type: org`), equivalente con un único motor; si la clave puede ver motores o se fija `SOC_PORTAL_CROWDSEC_ENGINE_ID`, se suscribe ese motor. La baja retira las suscripciones que liste `GET …/subscribers`.
2. **Evaluación con los ataques reales, sin descargas:** CrowdSec no deja descargar listas no suscritas (403) y las suscritas devolvieron 204 en la VM, así que cada hora se mide en local con datos ya obtenidos, contra los orígenes públicos de tráfico entrante de los clientes en 30 días:
   - **Listas suscritas — exacto (motor):** las decisiones del motor llevan como motivo el nombre de la lista (`crowdsec_wordpress`, `firehol_greensnow`…). Su aporte son los atacantes que solo cubre esa lista (ni la comunitaria ni otra).
   - **Resto — estimado (CTI):** la API CTI indica en `references` (`list:<nombre>`) en qué listas está cada IP consultada, también las no suscritas. Su aporte son los atacantes de la muestra que hoy no cubre ninguna lista. La página indica sobre cuántos atacantes consultados se estima; la muestra crece con las consultas CTI priorizadas.
   - **Puntuación:** aporte + 4 × atacantes con tráfico permitido + 0,5 × clientes, y 0 si CrowdSec declara más de un 1 % de falsos positivos.
   - No hay llamadas externas en la evaluación ni se envían IPs de clientes por esta vía.
3. **Recomendadas:** listas gratuitas o premium sin suscribir que aportan al menos 3 atacantes y tienen puntuación > 0. Las platino no se proponen.
4. **Suscripción:** «Suscribir» o «Dar de baja» deja la petición en cola. El trabajo la ejecuta (`POST /blocklists/{id}/subscribers` con `remediation: ban`, o `DELETE …/subscribers/{entidad}`) y lo audita con el usuario que la pidió.
5. **Modo automático** (`SOC_PORTAL_CROWDSEC_AUTO_SUBSCRIBE=N`, 0 por defecto): el SOC suscribe por su cuenta las mejores recomendadas hasta N listas, marcadas «Suscrita por el SOC» y auditadas. Nunca da de baja por su cuenta.

Las listas suscritas llegan al motor local (origen `lists`) y, desde ahí, a la reputación y a las listas de bloqueo de los clientes, que solo incluyen IPs que han atacado a algún cliente. Probado con una Service API simulada según su especificación OpenAPI. Comprobado en la VM: clave inválida → 403, catálogo y suscripciones con la clave real, nombres de lista en las decisiones del motor y en `references` de la CTI.

### Instalar el motor local (modo gratuito)

En la VM del portal (o en otra, con HTTPS), según la documentación oficial de CrowdSec:

```sh
curl -s https://install.crowdsec.net | sudo sh   # repositorio oficial de paquetes
sudo apt install crowdsec
sudo cscli console enroll <clave-de-inscripción>   # cuenta de la consola; aceptar en app.crowdsec.net
sudo systemctl restart crowdsec
sudo cscli bouncers add soc-portal                  # muestra la clave UNA vez
```

Guardar la clave como `SOC_PORTAL_CROWDSEC_LAPI_KEY=` en `/etc/soc-portal/portal.env` (nunca en el repositorio ni en el chat) y reiniciar `soc-portal`. Comprobar con `sudo cscli decisions list --origin CAPI | head` que llega la lista comunitaria (puede tardar hasta dos horas tras el primer arranque) y, en la consola, suscribir el motor a las listas gratuitas deseadas.

- **Lista completa o «Lite»:** CrowdSec entrega la lista comunitaria completa solo a motores que comparten señales de sus propias detecciones; si no comparten, reciben la versión reducida. Compartir señales envía a CrowdSec las IPs que el motor detecta atacando a la VM (con escenario y hora), no los eventos de los clientes. Es una decisión del responsable del SOC; documentarla.
- **Este motor no bloquea nada:** sin bouncer de firewall instalado, sus decisiones solo se consultan. Bloquear es la fase 7A/C2.
- Puerto: la API local escucha en `127.0.0.1:8080` por defecto. Si choca con otro servicio, cambiar `api.server.listen_uri` en `/etc/crowdsec/config.yaml` y ajustar `SOC_PORTAL_CROWDSEC_LAPI_URL`.

Comprobado contra un motor CrowdSec real: respuestas `null` sin decisiones, decisión de la lista comunitaria y por rango, 403 con clave inválida y puerto cerrado. La API CTI de pago solo se ha comprobado con clave inválida (403); el resto de su contrato está probado con respuestas simuladas.

## Archivos

- OPNsense: `opnsense_api.py`, `provisioning.py`, `ssh_connection.py`, `protection.py`, `network_coverage.py`, `configuration_archives.py`.
- UniFi: `unifi_cloud.py`, `unifi_flow.py`, `unifi_zone_scope.py`, `unifi_policy_details.py`, `unifi_policy_history.py`.
- Hillstone: `hillstone_api.py`, `hillstone_views.py`, `hillstone_events.py`, XML en `deploy/wazuh/`.
- GCC/GDMS: `gdms_api.py`, `gdms_views.py`, `device_identity.py`, `device_inventory.py` y templates de instrucciones.
- Zenarmor: `zenarmor_export.py`, `zenarmor_scope.py`, `zenarmor_bypass.py` y decoder/rules.

## Añadir un conector

1. Acreditar modelo, versión, permisos, API y log reales/documentados en laboratorio.
2. Separar lectura/inventario de escritura/provisioning; timeouts, respuestas acotadas, hosts y redirecciones controlados.
3. Cifrar secretos; pin SSH o CA. No persistir tokens OAuth temporales/respuestas crudas en inventario.
4. Vincular dispositivo/MAC al cliente; probar conflictos, selección y reasignación.
5. Muestra anonimizada y pruebas de parser/acción/propiedad/informe. Mantener desconocido sin evidencia.
6. Wizard, guía, matriz y validación. Leer después de escribir; comprobar llegada e interpretación separadamente.

No aplicar políticas de protección nuevas como efecto secundario de un alta ni extender una configuración piloto a todos los clientes.

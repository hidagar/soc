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
- **API CTI:** 429 (cupo) o 401/403 (clave) pausan seis horas; 404 se guarda como «sin datos». Se guardan reputación, confianza, ruido de fondo, puntuaciones generales, comportamientos, clasificaciones, posibles falsos positivos, ASN, país y fechas de la comunidad.
- **En ambas:** un fallo de una IP no detiene el resto; la clave nunca se guarda ni se muestra; solo se guarda el resumen mostrado, con la fecha del dato; se purga a los 90 días.
- **Dónde se ve:** «Investigar IP» y «Detecciones prioritarias», solo personal del SOC. No se muestra a clientes ni se usa en informes. La etiqueta muestra la reputación CTI si existe y la lista como complemento. En «Detecciones prioritarias», un aviso cuenta los grupos de tráfico **permitido** cuyo origen está en una lista o tiene reputación CTI maliciosa o sospechosa, y el filtro «Reputación CrowdSec» muestra esos orígenes, solo los permitidos, o **oculta el ruido de fondo** (CTI con ruido de fondo alto o posible falso positivo). El filtro actúa sobre los 500 grupos de mayor prioridad y no cambia prioridad, motivos ni orden.
- **Página «Reputación CrowdSec»** (Detección e investigación, `core/reputation_views.py`): modo y estado del trabajo; recuento por origen de las listas del motor (comunitaria, consola, detección local, manual) con sus principales motivos, que el trabajo calcula cada hora leyendo `/v1/decisions?origins=` por bloques, con memoria acotada y un máximo de 64 MiB por origen; y las IPs de origen en lista del periodo con listas, motivo, rango, clientes, detecciones y permitidas. Las detecciones se filtran con el ámbito de cliente del usuario; la web solo lee la caché y el estado, nunca consulta al motor.
- **Qué no hace:** no crea incidencias, no cambia acción, prioridad ni motivos de una detección y no bloquea nada. Estar en una lista o «ruido de fondo» alto no prueba un ataque dirigido al cliente.

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

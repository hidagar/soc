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

## Reputación CrowdSec (CTI, solo lectura)

Contexto de reputación de IPs externas (hoja de ruta 4A/C1), en `core/reputation.py`. El trabajo protegido `reputation` (cada 15 minutos) consulta `GET https://cti.api.crowdsec.net/v2/smoke/<ip>` con la cabecera `x-api-key`; la web solo lee la caché `IpReputation`.

- **Qué IPs se consultan:** solo orígenes **públicos** de evidencias de los últimos 7 días cuyo destino es una red interna o una IP pública de un cliente. Nunca IPs internas, IPs de clientes o del SOC (orígenes Syslog, propiedad de fuentes, transporte HTTPS, IP pública Syslog) ni destinos de conexiones salientes, que revelarían la navegación de los clientes. Orden: tráfico permitido, nivel más alto y repetición.
- **Cupo:** `SOC_PORTAL_CROWDSEC_DAILY_LIMIT` consultas al día (30 por defecto; ajustar al plan). Cada respuesta vale 3 días. 429 (cupo) o 401/403 (clave) pausan seis horas y quedan en «Salud del SOC» sin exponer la clave. Un fallo de una IP no detiene el resto. 404 se guarda como «sin datos».
- **Qué se guarda:** reputación, confianza, ruido de fondo, puntuaciones generales, comportamientos, clasificaciones, posibles falsos positivos, ASN, país y fechas de la comunidad, con la fecha del dato. Nada más de la respuesta. Se purga a los 90 días.
- **Dónde se ve:** «Investigar IP» y «Detecciones prioritarias», solo personal del SOC. No se muestra a clientes ni se usa en informes.
- **Qué no hace:** no crea incidencias, no cambia acción, prioridad ni motivos de una detección y no bloquea nada. «Ruido de fondo» alto indica escaneo masivo de Internet, no un ataque dirigido.

Sin `SOC_PORTAL_CROWDSEC_KEY` el trabajo no consulta nada. Comprobado contra la API real que una clave inválida devuelve 403; el resto del contrato está probado con respuestas simuladas según la documentación de CrowdSec y debe confirmarse con la clave real.

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

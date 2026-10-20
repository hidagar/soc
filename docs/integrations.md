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

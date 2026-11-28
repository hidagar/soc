# Trabajo pendiente

Lista única de lo que falta, actualizada el **20/11/2026**. Reúne los «Pendiente» de la [hoja de ruta](roadmap.md), del [traspaso](handoff.md) y de cada entrega del [registro de cambios](changelog.md).

**Cómo se mantiene:** cada entrega quita aquí lo que cierra y añade lo que deja pendiente, en el mismo pull request (AGENTS.md, «Antes de terminar»). Cada punto indica quién puede hacerlo:
- **Usuario:** requiere producción, credenciales, equipos de clientes o una decisión de negocio. No se hace desde el código.
- **Código:** desarrollo en el repositorio.

## Acciones del usuario fuera del código

| Pendiente | Origen | Notas |
|---|---|---|
| **Probar la fase 2 de las políticas en un firewall propio** antes de usarla con clientes | 13/11 | Desplegada, pero sin validar en un OPNsense real: preparar un plan en un equipo de ib-red, revisar el alias y la regla desactivada en su consola, activarlo y comprobar el acceso desde un origen autorizado y desde otro. |
| Activar los plazos de las solicitudes | 13/11 | Desplegados. Se activan en «Plazos de atención»; revisar antes los valores (8 h y 5 días; urgentes, 1 h y 1 día). |
| Configurar el horario laboral | 13/11 | Desplegado. Indicar jornada, días y festivos de Baleares del año, y decidir si se aplica a urgentes y a incidencias medias y bajas. |
| Decidir si se activa la pausa de las incidencias | 13/11 | Desplegada (migración 0077). Casilla en «Plazos de atención», desactivada por defecto. |
| Contratar el plan de pago de Q-Feeds para el SOC (plan A) | Q-Feeds, 20/11 | Q-Feeds confirmó el 20/11 que el uso central cabe en el plan normal. Antes de elegir entre Plus y Premium: mirar «Evolución» unos días y probar Premium 7 días (cambiando `SOC_PORTAL_QFEEDS_KEY`). Tras contratar, añadir a `SOC_PORTAL_QFEEDS_FEEDS` las listas nuevas que muestre «Listas que ofrece tu licencia». |
| Activar Q-Feeds en la lista de bloqueo de los clientes | Q-Feeds, 20/11 | Las listas que ya existían la tienen desmarcada. Empezar por un cliente piloto (Pollença): marcar «IPs en listas de Q-Feeds», revisar «Q-Feeds en esta lista» y extender al resto desde «Q-Feeds en los clientes» (activación masiva con vista previa). La lista de salida con Q-Feeds es opcional. |
| Aprobar las actualizaciones de plantilla 1.1 | Propagación, 30/11 | En «Listas de bloqueo › Propagación a los firewalls», cada regla activa anterior tiene preparada su «Actualización a 1.1» (tabla cada ~15 minutos): revisarla, crear el borrador, activarla con MFA y confirmar que el firewall sigue descargando. |
| Permitir la lectura de las vulnerabilidades de los equipos: `sudo deploy/wazuh/permitir_vulnerabilidades.sh --aplicar` | Vulnerabilidades de equipos, 28/11 | Después, `--ver` debe indicar el permiso concedido, filas en el índice y la detección activa en el gestor. En una hora aparecen en «Vulnerabilidades de equipos». |
| Añadir la vigilancia en tiempo real a los grupos de clientes: `sudo deploy/wazuh/configurar_defender.sh --grupo CODIGO` | Integridad de archivos, 28/11 | Repetirlo en cada grupo ya creado: añade solo el bloque nuevo y guarda copia. Después, `--ver` debe indicar «vigila en tiempo real». Comprobar en un equipo propio: crear un acceso directo en la carpeta Inicio (Windows) o un archivo en `/etc/cron.d` (Linux) y ver que aparece en «Integridad de archivos» en un minuto. |
| Comprobar la configuración segura con un equipo propio | Configuración de equipos, 28/11 | Instalar el agente en un equipo nuevo y asignarlo: en unas 12 horas como máximo debe aparecer en «Configuración de equipos» con su guía CIS y su porcentaje. Si no, comprobar en el gestor que el agente tiene SCA activo (`/var/ossec/etc/ossec.conf` del agente, bloque `<sca>`). |
| Comprobar los accesos fallidos con un equipo propio | Accesos a equipos, 28/11 | En un equipo asignado con agente Wazuh, equivocar la contraseña 5 veces (en Windows, también por escritorio remoto) y entrar después: en unos segundos debe aparecer en «Accesos a equipos» como «Acceso correcto tras los fallos» y, desde la red interna, sin aviso al cliente. Si no aparece nada, comprobar en el equipo que la auditoría de inicio de sesión registra los errores (`auditpol /get /subcategory:"Logon"`). |
| Dejar el motor CrowdSec sin compartir señales: `sudo deploy/configurar_crowdsec_privado.sh --aplicar` | CrowdSec, 28/11 | Decisión del usuario. La lista comunitaria pasa a la versión reducida; comprobar después que sigue llegando (`sudo cscli decisions list --origin CAPI \| head`). [Despliegue](deployment.md#crowdsec-sin-compartir-señales). |
| Limitar la clave de Q-Feeds a la IP pública del SOC | Q-Feeds, 30/11 | En el portal de Q-Feeds, restringir la clave a la IP de salida de la VM. Si se limitan también los programas, incluir `ib-red-SOC/1`. «Inteligencia Q-Feeds» muestra si ya está limitada. |
| Confirmar con Q-Feeds que el acuerdo cubre la lista completa y los dominios | Q-Feeds para los clientes, 23/11 | La lista preventiva reparte todas las IPs de Q-Feeds (no solo las vistas en detecciones) y la de DNS, sus dominios. Conservar la confirmación junto al contrato antes de activarlas en clientes. |
| Lista preventiva de Q-Feeds en el piloto | Q-Feeds para los clientes, 23/11 | Activarla en un cliente, preparar la regla de entrada con el control de cambios y comprobar «IPs cargadas» tras la primera medición. Si el firewall carga menos de lo publicado, subir «Máximo de entradas de tablas» en OPNsense o bajar el máximo de la lista. Revisar excepciones con el cliente (proveedores, nube). |
| Dominios de Q-Feeds por DNS en el piloto | Q-Feeds para los clientes, 23/11; plantilla 27/11 | Activar «dominios para el DNS» y, en un OPNsense 25.7 o posterior con API, «Preparar bloqueo DNS» (crear borrador, activar, probar y confirmar en 10 minutos). En versiones anteriores, añadir la URL a mano. Comprobar que los equipos del cliente usan ese DNS. Para medir lo bloqueado, activar la recogida local de estadísticas de Unbound («Informes › Ajustes»). No validado aún en un OPNsense real. |
| Dominios de Q-Feeds en una consola UniFi real | UniFi, 28/11 | En un cliente piloto con UniFi Network 10.1 o posterior: marcar «dominios para el DNS», en «Bloqueo en UniFi» crear «Dominios Q-Feeds», revisar en UniFi la política creada (desactivada) y su orden, activarla y comprobar que un dominio de la lista no abre y uno normal sí. Confirmar si UniFi admite los 1.000 dominios. |
| Probar las listas por URL en un Hillstone | Hillstone, 28/11 | En un equipo con StoneOS 5.5R9 o posterior: importar la URL de la lista de entrada en la lista negra del Perimeter Traffic Filtering (y, en 5.5R12, una External Dynamic List con la de salida). Comprobar en la lista del cliente que aparece «Descarga comprobada» y que el formato se acepta. Indicar si pide la licencia de reputación IP. |
| Descargar la «RESTful API User Guide» de un Hillstone | Hillstone, 28/11 | La ofrece el propio equipo (información del sistema › API). Con ella se puede pasar a automático: libretas de direcciones, políticas, contadores y la lista antibotnet (dominios). No incluye credenciales; compartirla como archivo. |
| Instalar el DNS del SOC: `sudo deploy/configurar_dns_soc.sh --instalar` | DNS del SOC, 29/11 | Necesita la VPN de sedes activa en la VM y salida DNS a Internet. Sin esto, «DNS del SOC» no responde a ninguna sede. [Despliegue](deployment.md#dns-del-soc-por-la-vpn-de-sedes). |
| Piloto del DNS del SOC con un GCC | DNS del SOC, 29/11 | Preparar la VPN de la sede, conectarla desde el GCC (WireGuard), activar «DNS del SOC» y los dominios de Q-Feeds en su lista, poner 10.255.251.1 como DNS del GCC y comprobar que un dominio de la lista no resuelve y uno normal sí. La lista del cliente muestra cada paso como «Correcto», «Falta» o «Pendiente»; el último («Bloqueo visto desde una sede») confirma también el formato del diario. Decidir si se deja un DNS alternativo público (más disponibilidad, menos bloqueo). |
| Confirmar los plazos de conservación de los registros operativos | Mantenimiento, 20/11 | Propuestos: avisos por chat 1 año, caídas de Internet 400 días, solicitudes resueltas 2 años, propuestas «Ya no aplica» 180 días, consultas de Q-Feeds 90 días. [Operación](operations.md#conservación-de-datos). |
| Instalar ClamAV en la VM: `sudo deploy/configurar_antivirus.sh` | Antivirus, 23/11 | Necesita unos 1,5 GB de memoria libre y salida a `database.clamav.net`. Hasta entonces los adjuntos quedan «sin analizar». [Despliegue](deployment.md#antivirus-de-los-adjuntos-clamav). |
| Antivirus de equipos: preparar Wazuh y los primeros agentes | Antivirus de equipos, 23/11 | `sudo deploy/wazuh/configurar_defender.sh --reglas` y `--grupo CODIGO` por cliente. Decidir cómo llegan los agentes al gestor (VPN de la sede o publicación limitada). Instalar el agente en un equipo propio primero y asignarlo en el portal. [Despliegue](deployment.md#antivirus-de-equipos-agentes-wazuh-con-microsoft-defender). |
| «Correo de operaciones» activo en «Copias y recuperación» | 11/11 | Para recibir las solicitudes y las decisiones de los clientes. |
| Comprobar si algún equipo usa firma SSH `ssh-rsa` (SHA-1) antes de subir `paramiko` a 5.x | Auditoría 11/11 | Las páginas de conexión SSH y de copias SFTP lo avisan al obtener la huella. Si ninguno lo usa, la subida es segura. |
| Ejecutar `sudo deploy/configurar_registros.sh` | Auditoría 29/10 | Registros de Nginx y gunicorn sin URL secretas. [Despliegue](deployment.md#registros-sin-secretos-de-url). |
| `X-Forwarded-For` en el Nginx público y `deploy/configurar_ip_real.sh` | Continuidad 29/10 | Sin esto, el límite de login por IP ve la IP del proxy. |
| Configurar `SOC_PORTAL_HEARTBEAT_URL` (monitor exterior) | Bloque 8 | Implementado, falta la URL del servicio de monitorización. |
| Ensayo completo de recuperación de la VM | Bloque 8 | Restaurar en una VM aislada y medir pérdida de datos y tiempo. |
| Activar los plazos de atención (SLA) | Bloque 5, 30/10 | Desactivados hasta activarlos en «Plazos de atención». |
| Lista de bloqueo en observación para Pollença | Bloqueo, 27/10 | Piloto acordado; también Conservas Roselló. |
| Activar la política BCM | Conversación 05/11 | Pendiente de decisión del usuario. |
| Bot de Telegram del SOC (`SOC_PORTAL_TELEGRAM_BOT_TOKEN`) y primer cliente con Teams | Avisos por chat, 06/11 | [Guía](reports-and-mail.md#avisos-urgentes-por-teams-y-telegram). |
| `SOC_PORTAL_NVD_KEY` (opcional) y activar «Avisos de vulnerabilidad» por cliente | Vulnerabilidades, 06/11 | Revisar la primera tanda en «Vulnerabilidades». |
| `SOC_PORTAL_AUDIT_ANCHOR_EMAIL` (opcional) | Anclaje, 06/11 | Sin ella, el ancla va al correo de copia de informes. |
| Revisar los valores del índice de seguridad con clientes reales | Índice, 06/11 | Ajustar `WEIGHTS` si algún factor no refleja la realidad. |
| Activar el webhook firmado de SendGrid | Bloque 6 | Hasta entonces, «Aceptado por SendGrid» no confirma la entrega. |
| Primer relay HTTPS real en una sede | Bloque 3/7 | Descartado por ahora por el usuario; no reabrir sin su decisión. |
| Licencia de exportación de Zenarmor (SOHO/Business) | Bloque 7 | Requisito para recibir sus eventos. |
| Confirmar la ruta de menú de Syslog en un GCC real | Traspaso 20/10 | Las pruebas siguen la plantilla actual. |
| Revisar las 12 unidades systemd de la VM que difieren de `deploy/` | Traspaso 20/10 | Formato o ajustes locales. |
| Cerrar en GitHub los PR abiertos que ya están en `main` | Registro de cambios | #4–#24, #26, #27, #29, #31, #48, #54 y #56. |

## Desarrollo pendiente por área

### Políticas de firewall propuestas (fase 1 entregada el 11/11)
- Hecho el 13/11: restringir un servicio en OPNsense con el control de cambios (alias de autorizados y regla propia). Pendiente de validar en un equipo real.
- **Fase 2 · filtro por país en OPNsense:** alias GeoIP con la misma plantilla. Exige comprobar antes que la base GeoIP del firewall carga la tabla; vacía, bloquearía a todo el mundo.
- **Fase 2 · IPv6 y destinos que no son una IP fija** (alias, el propio firewall, varias interfaces): hoy se aplican a mano.
- El control de exposición debería reconocer la regla del SOC y dejar de mostrar el servicio como abierto a cualquier origen.
- **Fase 2 · UniFi por API:** reenvíos de puertos y restricción por región. Hoy es una actuación guiada.
- **Fase 3 · mínimo privilegio:** conocer el tráfico legítimo con resúmenes de Zenarmor por API (aplicaciones y categorías), sin recibir cada conexión. Antes, confirmar qué ofrece su API.

### Solicitudes de clientes
- Hecho el 13/11: plazos de primera respuesta y resolución, con horario laboral. Faltan plazos propios por cliente.
- Hecho el 20/11: adjuntos en las solicitudes. Hecho el 23/11: análisis con ClamAV en la VM.

### Vulnerabilidades
- UniFi Network Application, si se obtiene su versión.
- Productos de Hillstone y Grandstream con datos reales de NVD.

### Avisos y comunicaciones
- Avisos de actuaciones o del informe mensual por Teams o Telegram, si se piden.
- Mostrar al cliente el cumplimiento de los plazos de atención (decidir qué se publica de los casos internos).

### Plazos de atención (SLA)
- Hecho el 13/11: horario laboral (un único horario para todos). Hecha también la pausa de las incidencias mientras se espera al cliente. Faltan jornadas partidas y guardias.

### Conexión a Internet
- Duración de las caídas con el estado de las consolas en la nube de UniFi (requiere comprobarlo en campo).
- Regla de Wazuh para las alarmas de gateway de OPNsense, si se envían.

### Inteligencia y bloqueo
- Hecho el 20/11: Q-Feeds plan A (uso central con un plan de pago): revisión de destinos salientes, bandeja, menú, listas de la licencia y evolución diaria.
- Hecho el 20/11: Q-Feeds en la lista de bloqueo como CrowdSec, y consulta de contexto (IOC Lookup).
- Hecho el 23/11: Q-Feeds para los clientes: lista preventiva (OPNsense y UniFi), dominios para el DNS, medición por fuente (SOC, informes y portal) y activación masiva.
- Hecho el 27/11: plantilla DNS de OPNsense (Unbound 25.7+) y tabla de capacidades por fabricante.
- Hecho el 28/11: medición del DNS con las estadísticas de Unbound (SOC, portal e informes).
- Hecho el 28/11: dominios de Q-Feeds en UniFi (política por dominios del SOC).
- Hecho el 28/11: Hillstone en modo guiado (filtrado perimetral y lista dinámica externa) y comprobación de descargas por equipo para todos los fabricantes.
- Hillstone automático (libretas, políticas, contadores, lista antibotnet) cuando se tenga su guía REST.
- Hecho el 28/11: Grandstream GCC revisado (sin listas por URL ni escritura por API).
- Hecho el 29/11: DNS del SOC por la VPN de sedes para el GCC (y cualquier sede con la VPN).
- Hecho el 28/11: preventiva de Q-Feeds de salida en UniFi.
- Q-Feeds: TAXII 2.1 (hashes) si se contrata Enterprise.
- Hecho el 28/11: reputación propia del SOC en las listas de bloqueo (activada) y reputación de los orígenes en el portal del cliente; decidido que el motor CrowdSec no comparte señales (script).

### Base, despliegue y continuidad (bloques 4 y 8)
- Ensayo con una copia de la base real en staging y restauración completa de la copia cifrada con PostgreSQL.
- Configuración multiambiente y entrega reproducible completa.
- Rotación de `SECRET_KEY` (afecta a sesiones, enlaces firmados y cadena de auditoría): necesita un plan propio.

### Conectores y cobertura (bloque 7)
- Matriz fabricante/versión/capacidades con una muestra real por motor y red (GCC, ClamAV).
- Hillstone en el recorrido API opcional; lectura de Zenarmor cuando exista contrato contrastado.

### Propuestas de la auditoría de noviembre

Auditoría del 11/11/2026: herramientas automáticas (ruff, bandit, pip-audit), recorrido de todas las rutas con administrador y cliente, y revisión manual del código nuevo desde el 30/10. Lo corregido está en el [registro de cambios](changelog.md). Queda propuesto:

**Seguridad y mantenimiento**
- Subir `paramiko` de 4.0.0 a 5.x: corrige el uso de SHA-1 en firmas RSA (PYSEC-2026-2858). La batería completa pasa con 5.1.0, pero un firewall antiguo que solo acepte `ssh-rsa` dejaría de conectar: comprobarlo antes (ver acciones del usuario).

**Usabilidad del SOC**
- Hecho el 12/11: contadores en el menú lateral y buscador global.
- Buscador: añadir usuarios del portal y texto de las conversaciones si se echa en falta.
- Hecho el 12/11: línea de tiempo por cliente. Posible ampliación: versión resumida para el portal del cliente, solo con lo publicado.
- Hecho el 13/11: las cinco páginas de inteligencia y bloqueo comparten una entrada del menú, con pestañas.

- Hecho el 16/11: revisión de la experiencia de usuario de todas las páginas (contraste, mensajes, teclado, móvil). Queda: revisión con un lector de pantalla real y con usuarios; pruebas automáticas del JavaScript; tema oscuro, si se pide; el texto del mapa (10,5 px) se mantiene pequeño a propósito en la vista de presentación.

**Valor para el cliente**
- Hecho el 13/11: el informe mensual incluye vulnerabilidades, solicitudes y cambios.

### Antivirus de equipos
- Hecho el 28/11: vulnerabilidades de los equipos (detección de Wazuh) para el SOC y el portal del cliente.
- Hecho el 28/11: accesos fallidos en los equipos (Windows, SSH, sudo, PAM) con revisión del SOC, aviso urgente por acceso tras fallos desde Internet y sección en el portal.
- Accesos fallidos, límites conocidos: el bloqueo de cuenta solo se reconoce en Windows (4740); en Linux, `faillock`/`pam_tally` quedan como fallos repetidos. La recuperación desde el indexador no trae los accesos correctos sueltos, así que un acceso tras fallos que solo esté en el indexador se ve si Wazuh lo correlacionó (40112). Umbrales fijos (5 intentos, 1 hora, 30 minutos): ajustarlos por cliente si hace falta tras el piloto.
- Hecho el 28/11: configuración segura (SCA de Wazuh) para el SOC y el portal del cliente.
- Configuración segura, mejoras propuestas: leer el estado completo por la API del gestor de Wazuh (`/sca/{agente}`) con un usuario de solo lectura, para los equipos cuyo primer análisis no llegó; excepciones aceptadas por el cliente (que no cuenten en la puntuación); puntuación en el índice de seguridad y en el informe mensual.
- Hecho el 28/11: integridad de archivos (FIM) en los equipos, con revisión de los cambios sensibles, resumen del resto y sección en el portal; plantilla de vigilancia en tiempo real por grupo.
- Integridad de archivos, mejoras propuestas: activar `whodata` en servidores para saber quién hizo cada cambio (requiere la auditoría de Windows o auditd y probar su carga); excepciones por ruta y cliente (programas de gestión que cambian el registro a diario); cruce del SHA-256 de los binarios nuevos con la reputación de Q-Feeds o VirusTotal.
- Siguiente, acordado el 28/11: agentes Linux y evidencias de cumplimiento NIS2/ENS (las comprobaciones SCA ya guardan sus referencias CIS, PCI DSS y NIST).
- Hecho el 23/11: estado del antivirus en el portal del cliente (opción por cliente).
- Hecho el 23/11: avisos urgentes al cliente por detecciones «permitidas» o «sin poder actuar».
- Hecho el 23/11: recuperación de los eventos de Defender desde el indexador.

### Ideas propuestas sin empezar
- Evidencias para NIS2/ENS.
- Aviso de equipos nuevos en la red.
- Credenciales filtradas del dominio del cliente.

# Configuración

## Regla general

Los servicios leen el entorno, normalmente mediante `EnvironmentFile=/etc/soc-portal/portal.env`. Django no interpreta archivos `.env`. [.env.example](../.env.example) es una plantilla sin secretos; los valores reales pertenecen al gestor de secretos/archivo protegido del entorno y a registros cifrados del panel.

## Variables por finalidad

| Variable | Uso / formato | Observación |
|---|---|---|
| SOC_PORTAL_DEBUG | `1` solo en desarrollo | Modifica cookies seguras y redirección HTTPS. Ausente/otro valor mantiene comportamiento de producción. |
| SOC_PORTAL_SECRET_KEY | Secreto persistente de Django | Obligatorio fuera de DEBUG; también deriva bóveda operativa y firma de auditoría. No rotar sin migración. |
| SOC_PORTAL_ALLOWED_HOSTS | Hosts separados por comas | Sin esquema, rutas ni `*` como solución genérica. |
| SOC_PORTAL_CSRF_ORIGINS | Orígenes HTTPS separados por comas | Incluir esquema y puerto si procede; no desactivar CSRF. |
| SOC_PUBLIC_ORIGIN | Origen HTTPS público sin ruta | Invitaciones y recursos de correo; mantenerlo coherente con el proxy. |
| SOC_PORTAL_MFA_REQUIRED | `1` normal; `0` únicamente en pruebas aisladas | No modificar en producción para arreglar un login. |
| SOC_PORTAL_VAULT_KEYS | Claves Fernet «nueva,anterior» de la bóveda operativa | Opcional. Vacío: solo la clave derivada de SECRET_KEY (comportamiento previo). Ver rotación en [seguridad](security.md). |
| SOC_PORTAL_UNIFI_KEY | Clave Fernet (o «nueva,anterior» para rotar) | Cifra la clave API UniFi; no es una API key del fabricante. |
| SOC_PORTAL_OPNSENSE_KEY | Clave Fernet | Cifra credenciales OPNsense. |
| SOC_PORTAL_SSH_KEY | Clave Fernet | Cifra SSH y credenciales reutilizadas por conectores Hillstone/GDMS. |
| SOC_PORTAL_MAIL_KEY | Clave Fernet | Cifra la API key SendGrid. |
| SOC_PORTAL_RECEIVER_IP / SOC_PORTAL_RECEIVER_PORT | IPv4 y puerto UDP del receptor Syslog de Wazuh en la VM | Por defecto `172.20.10.20` y `5514` (instalación actual). Se usan en el aprovisionamiento, el asistente, el reenvío HTTPS→UDP, la regla nftables de la VPN y la búsqueda del bloque `<remote>` en Wazuh. Un valor no válido detiene el arranque. Cambiarlos no reconfigura Wazuh, Nginx ni el DNAT ni los equipos ya configurados. |
| SOC_PORTAL_PUBLIC_SYSLOG_IP | IPv4 pública de destino | Distinguir destino de envío de IP de origen del firewall. |
| SOC_PORTAL_EXTRA_SYSLOG_IPS | IPs adicionales separadas por comas | Opciones de transición, no reconocimiento automático de clientes. |
| SOC_INDEXER_READER_FILE | Ruta JSON privada | `username` y `password` del reader, fuera de Git. |
| SOC_INDEXER_CA | Ruta a CA privada del indexador | Se exige validación del servidor. |
| SOC_PORTAL_TRUSTED_PROXIES | IPs de proxies separadas por comas | Por defecto `127.0.0.1,::1`. Solo desde ellas se acepta `X-Real-IP` para el límite de login por IP. |
| SOC_PORTAL_LOGIN_IP_LIMIT | Entero | Fallos de contraseña por IP en 15 minutos (30 por defecto). |
| SOC_PORTAL_HEARTBEAT_URL | URL HTTPS sin credenciales | Latido saliente para un monitor exterior (p. ej. Healthchecks.io): cada 5 minutos si el SOC está sano y `<URL>/fail` si no. Vacía, sin latido. Véase [operación](operations.md#monitor-exterior). |
| SOC_PORTAL_HSTS_SECONDS | Entero | Duración de HSTS en segundos (86400 por defecto; 0 lo desactiva). Subir a 31536000 tras comprobar que el nombre del portal solo se usa con HTTPS. |
| SOC_WAZUH_PROXY_KEY | Secreto interno de autorización del proxy | El navegador no decide identidad/rol por cabeceras. |
| SOC_GEOIP_DATABASE / SOC_ASN_DATABASE | Rutas a bases MMDB | Geografía/reputación de red son contexto aproximado, no atribución personal. |
| SOC_REPORT_EMAIL_BACKEND | Backend de correo Django | No sustituye MailSettings ni bloquea el envío directo SendGrid. |
| SOC_PORTAL_DB_ENGINE | `sqlite` (por defecto) o `postgresql` | Cambiarlo no traslada datos: seguir [base de datos](database.md). Otro valor detiene el arranque. |
| SOC_PORTAL_DB_NAME / _USER / _PASSWORD / _HOST / _PORT / _SSLMODE | Conexión PostgreSQL | Solo con `postgresql`. Contraseña en el archivo protegido; `_SSLMODE` por defecto `prefer` (usar `require` o superior fuera del host local). |
| SOC_PORTAL_SQLITE_PATH | Ruta del archivo SQLite | Por defecto `data/portal.sqlite3`. Para staging y pruebas; en producción no cambiarla sin mover la base y las copias. |
| SOC_PORTAL_DB_TEST_NAME | Ruta de base SQLite de archivo para pruebas | Solo para los ensayos de concurrencia; nunca la base real. |
| SOC_PORTAL_CROWDSEC_LAPI_KEY | Clave de bouncer del motor CrowdSec local | Opcional; modo gratuito y preferente (lista comunitaria y listas de la consola). Secreto: solo en el archivo protegido. Ver [integraciones](integrations.md). |
| SOC_PORTAL_CROWDSEC_LAPI_URL | URL | API local del motor; `http://127.0.0.1:8080` por defecto. HTTP solo hacia el propio equipo; en otro equipo, HTTPS. |
| SOC_PORTAL_CROWDSEC_KEY | Clave de la API CTI de CrowdSec (de pago) | Opcional; se combina con las listas del motor si también hay clave de bouncer. Sin ninguna de las dos no se consulta nada. Secreto. |
| SOC_PORTAL_CROWDSEC_DAILY_LIMIT | Entero | Consultas CTI al día (30 por defecto). Con plan mensual, el cupo mensual entre 31. No aplica al motor local. |
| SOC_PORTAL_CROWDSEC_SERVICE_KEY | Service API Key de la consola de CrowdSec | Opcional; permite medir y suscribir listas. Secreto con capacidad de cambiar suscripciones de la organización: solo en el archivo protegido. |
| SOC_PORTAL_CROWDSEC_ENGINE_ID | Identificador del motor | Solo si la organización tiene más de un motor. |
| SOC_PORTAL_CROWDSEC_AUTO_SUBSCRIBE | Entero (0–50) | Listas que el SOC puede suscribir por su cuenta; 0 = solo recomendar. |
| SOC_PORTAL_CROWDSEC_CTI_PER_RUN | Entero (1–20) | Consultas CTI por ejecución del trabajo, cada 15 minutos (2 por defecto). Subirlo solo si CrowdSec no responde 429. |
| SOC_PORTAL_CROWDSEC_MONTHLY_LIMIT | Entero | Cupo CTI mensual del plan; vacío o 0 = sin tope mensual propio (solo el diario). |
| SOC_NATIVE_ENGINE_GATE | `1` solo para ensayo optativo | Nunca activarlo en servicios de producción. |

La [referencia generada](reference/environment.md) enlaza cada variable a sus lectores reales. Existen rutas fijas y configuración en base de datos que **no** se cambian con estas variables; ver código antes de trasladar la instalación.

## Datos que se configuran en el panel

Credenciales de conectores, selección cloud/sede, CA por dispositivo, SSH con huella confirmada, remitente/región/copia/reply-to SendGrid, URL pública de informes, destinos y permisos de clientes, preferencias de envío, publicación, cobertura y recuperación. No colocar secretos en notas libres.

## Archivos y rutas de la instalación Linux

| Ruta | Propósito |
|---|---|
| `/srv/soc-portal` | Código instalado, root propietario; `data/` para el proceso web. |
| `/srv/soc-portal/data/portal.sqlite3` | Base del portal con SQLite (por defecto), distinta del indexador y DB interna Wazuh. |
| `/opt/soc-portal-venv` | Runtime Python. |
| `/etc/soc-portal` | Entorno, reader, certificados/configuración de aplicación. |
| `/etc/soc-portal/recovery.key` | Clave envolvente de copias; preservar separadamente del archivo que cifra. |
| `/var/ossec` | Manager Wazuh principal y alertas existentes. |
| `/var/lib/soc-wazuh-https/var/ossec` | Perfil, cola, DB y logs del motor HTTPS privado. |
| `/var/lib/soc-recovery` | Copias cifradas y configuraciones de firewall. |

`deploy/install.sh` contiene valores de una instalación concreta (dirección local y puerto, entre otros); el código de la aplicación los toma de `SOC_PORTAL_RECEIVER_IP`/`_PORT`, pero el instalador y los textos de ayuda de la VPN siguen fijos. Revisarlos en staging; cambiar variables no reescribe automáticamente el Nginx generado ni el DNAT de la red.

# Seguridad, permisos y secretos

## Autenticación

Django gestiona contraseña y sesión; `EmailBackend` busca correo normalizado de forma única. Solo dos cuentas históricas explícitas conservan login por nombre cuando no tienen correo. No ampliar esa excepción a cuentas nuevas. Los administradores crean cuentas sin contraseña utilizable y el destinatario la establece mediante invitación de 48 horas. El GET de un escáner de correo no consume el enlace.

Los fallos de contraseña se limitan por identidad intentada (8 en 15 minutos) y por IP del navegador (`SOC_PORTAL_LOGIN_IP_LIMIT`, 30 por defecto, con cualquier usuario), de modo que probar una contraseña contra muchas cuentas también se frena. Un acceso correcto solo limpia el contador de su identidad. La IP se toma de `X-Real-IP` únicamente cuando la petición llega de un proxy de `SOC_PORTAL_TRUSTED_PROXIES` (Nginx local); sin esa cabecera no se aplica el límite por IP, porque aplicarlo a la dirección del proxy bloquearía a todos los usuarios. Nginx debe sustituir la cabecera (`proxy_set_header X-Real-IP $remote_addr;`, como en `install.sh`). El límite por identidad permite que un tercero retrase el acceso de una cuenta concreta durante 15 minutos.

MFA usa TOTP y recuperación de un solo uso, con contador/CAS contra repetición. Los códigos de recuperación (16 hexadecimales) solo se comprueban si la entrada tiene ese formato: un código TOTP erróneo no recorre los diez hashes. `SocSecurityMiddleware` vincula usuario, versión de perfil y sesión, y pide el código otra vez a las 12 horas de verificarlo aunque la sesión siga activa (`MFA_SESSION_MAX`). `mfa_fresh()` (código de menos de 10 minutos) limita operaciones sensibles; el middleware lo exige también, incluidos superusuarios, en los POST de las vistas que guardan credenciales, destinos o borran datos (`FRESH_MFA_VIEWS`: correo y URL pública de informes, UniFi, OPNsense, SSH, Hillstone, GDMS, destino de exportación y borrado de sedes). Desactivar el envío de correo no lo exige: es una parada segura. Las pruebas pueden deshabilitar MFA para un escenario, no la configuración del servicio real; `testing_access.FreshMfaClient` inicia sesión con un MFA recién verificado.

Contraseñas de al menos 12 caracteres (validadores de Django). HSTS con `SOC_PORTAL_HSTS_SECONDS` (un día por defecto; subirlo a un año cuando se confirme que nada más se sirve por HTTP con el mismo nombre). La contraseña SFTP de las copias no se reutiliza si cambia el servidor, el puerto o el usuario: hay que escribirla de nuevo.

## Autorización

| Rol | Alcance conceptual |
|---|---|
| reader | Consulta de los clientes autorizados; sin POST de modificación. |
| operator | Operación permitida por permisos Django y ámbito asignado. No implica gestión global de credenciales. |
| manager | Administración sujeta a permisos/ámbito; operaciones globales requieren acceso global (también crear clientes y cambiar suscripciones de CrowdSec). |
| customer | Exactamente un cliente activo, sin acceso global; portal y respuestas de tareas autorizadas. |
| superuser | Acceso global; sigue sujeto al flujo MFA en las rutas protegidas. |

La tabla resume el diseño, no concede permisos por sí misma. Revisar `roles.py`, middleware y decoradores de cada vista. `core.manage_connections` y `core.manage_operations` son capacidades diferenciadas. Los formularios y querysets de relaciones también deben respetar el ámbito; filtrar únicamente la página inicial no basta.

`ScopedManager` aplica ContextVar. `None` permite consultar sin filtro y es el valor de workers; `[]` no da acceso a clientes. Los endpoints públicos salen del ámbito de sesión y comprueban token, objeto y propietario explícitamente. `_base_manager` se reserva para mantenimiento que necesite ver conflictos globales y no exponga filas a una respuesta.

## Publicación y propiedad

No inferir propiedad histórica desde la relación actual Device→Site→Client. Mantener el ledger temporal y el cliente congelado de la evidencia. Fuentes compartidas/ambiguas no se atribuyen por intuición. En reasignaciones, revocar/recrear las identidades que lo exijan; el ámbito de un canal HTTPS es inmutable.

Para clientes, usar la proyección publicable de `service_development.py`, incluido HTML/PDF/enlaces. Un enlace firmado no convierte toda la información interna en publicable. Los índices de clientes de Wazuh contienen proyección sanitizada, roles/DLS/tenants verificados; no compartir el índice bruto para simular aislamiento.

## Criptografía y transporte

- Claves separadas para UniFi, OPNsense, SSH/conectores y correo. La bóveda operativa (MFA, tokens de canales e invitaciones, lotes HTTPS, copias de cambios) deriva de SECRET_KEY salvo que se configure `SOC_PORTAL_VAULT_KEYS`; la cadena de auditoría y las firmas de enlaces siguen dependiendo de SECRET_KEY.
- **Rotación** (bóveda y conectores): cada variable admite `nueva,anterior`; se cifra con la primera y se descifra con cualquiera. Procedimiento: copia previa (`update.sh` o recuperación); generar la clave (`python -c "from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())"`); ponerla delante en `portal.env` (para la bóveda, `SOC_PORTAL_VAULT_KEYS=nueva`); parar portal y timers y arrancar el portal; `manage.py rotate_encryption_keys` (simulación) hasta que no queden valores «sin descifrar»; `--apply`; comprobar MFA y conectores; retirar la clave anterior de la lista. El comando atribuye cada valor a su clave descifrándolo, comprueba cada valor recifrado antes de escribirlo y no toca lo que no puede descifrar. La clave derivada de SECRET_KEY permanece al final de la bóveda para leer valores antiguos. **Rotar SECRET_KEY sigue sin estar soportado**: invalida sesiones y enlaces de informes y rompe la verificación de la cadena de auditoría existente.
- SSH autentica contra una huella confirmada. No aceptar automáticamente una clave cambiada.
- HTTPS valida cadena y nombre. `indexer_tls.py` relaja únicamente un requisito de perfil de la PKI privada instalada; conserva CERT_REQUIRED y hostname. No generalizar esa excepción.
- Root/mTLS del indexador pertenece al worker protegido; el reader usa una credencial limitada distinta.
- No registrar cuerpos, tokens, credenciales o respuestas completas de fabricante. Auditoría usa una allowlist.

## Terceros con datos de IP

Reputación CrowdSec: en el modo gratuito (motor local) la consulta no sale de la VM; el motor descarga las listas y, si se activa, comparte con CrowdSec las IPs que él mismo detecta atacando a la VM. En el modo CTI de pago, CrowdSec recibe direcciones IP. En ambos solo se consultan orígenes públicos de tráfico entrante hacia clientes; nunca IPs internas, de clientes o del SOC ni destinos de conexiones salientes. Ningún otro dato del evento o del cliente sale del SOC. Limitación conocida: si un motor registra como origen la respuesta de un servidor externo visitado (por ejemplo, una alerta sobre contenido descargado), esa IP puede consultarse. La clave de bouncer solo viaja por HTTP hacia el propio equipo; hacia otro equipo se exige HTTPS.

Vista previa del portal del cliente (`/clients/<id>/customer-view/`): reutiliza los contextos del portal del cliente, de modo que el SOC ve la misma proyección y nunca datos adicionales. Solo GET, limitada al ámbito del usuario mediante `Client.objects`, sin acciones de respuesta y auditada por página. Los usuarios con rol cliente no la alcanzan porque el middleware los limita a `/cliente/`.

Service API de CrowdSec: su clave puede cambiar las suscripciones de toda la organización. Solo la usa el trabajo protegido `crowdsec_lists`; la web deja las altas y bajas en cola (permiso `manage_connections`, acceso global y MFA reciente) y todas quedan auditadas. La evaluación de las listas usa datos ya obtenidos (decisiones del motor y referencias de la CTI): no descarga listas ni envía IPs de clientes a CrowdSec.

Listas de bloqueo para firewalls (`/feeds/bloqueo/`): ruta pública sin sesión, autorizada solo por un token por cliente (guardado como hash y cifrado, comparación en tiempo constante, rotación con `manage_connections` y MFA reciente). Va en la URL porque los alias de OPNsense no admiten cabeceras: no registrar la ruta completa en logs compartidos y rotarlo si se expone. La lista vacía es el estado seguro (desactivada, detenida o cliente inactivo). La regla en el firewall solo se crea y activa con el control de cambios.

## Proxy y SSO Wazuh

Nginx consulta `/security/wazuh/check/` con un secreto interno. El backend comprueba sesión, MFA, permisos y ámbito listo; devuelve identidad/rol controlados. El proxy debe sustituir cabeceras de identidad del navegador y proteger la ruta interna. No es un token administrador reutilizable en el frontend. La configuración viva está fuera de Git.

## Límites conocidos

La cadena HMAC local detecta modificaciones internas, pero no prueba ausencia de truncamiento final sin anclaje externo. La rotación versionada de claves y ese anclaje siguen en roadmap. El canal de logs autentica al emisor configurado; no acredita que todos sus mensajes sean ciertos ni que UDP no pierda datagramas. Probar aislamiento al añadir cada nueva superficie.

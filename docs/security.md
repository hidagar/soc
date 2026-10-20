# Seguridad, permisos y secretos

## Autenticación

Django gestiona contraseña y sesión; `EmailBackend` busca correo normalizado de forma única. Solo dos cuentas históricas explícitas conservan login por nombre cuando no tienen correo. No ampliar esa excepción a cuentas nuevas. Los administradores crean cuentas sin contraseña utilizable y el destinatario la establece mediante invitación de 48 horas. El GET de un escáner de correo no consume el enlace.

MFA usa TOTP y recuperación de un solo uso, con contador/CAS contra repetición. `SocSecurityMiddleware` vincula usuario, versión de perfil y sesión; `mfa_fresh()` limita operaciones sensibles. Las pruebas pueden deshabilitar MFA para un escenario, no la configuración del servicio real.

## Autorización

| Rol | Alcance conceptual |
|---|---|
| reader | Consulta de los clientes autorizados; sin POST de modificación. |
| operator | Operación permitida por permisos Django y ámbito asignado. No implica gestión global de credenciales. |
| manager | Administración sujeta a permisos/ámbito; operaciones globales requieren acceso global. |
| customer | Exactamente un cliente activo, sin acceso global; portal y respuestas de tareas autorizadas. |
| superuser | Acceso global; sigue sujeto al flujo MFA en las rutas protegidas. |

La tabla resume el diseño, no concede permisos por sí misma. Revisar `roles.py`, middleware y decoradores de cada vista. `core.manage_connections` y `core.manage_operations` son capacidades diferenciadas. Los formularios y querysets de relaciones también deben respetar el ámbito; filtrar únicamente la página inicial no basta.

`ScopedManager` aplica ContextVar. `None` permite consultar sin filtro y es el valor de workers; `[]` no da acceso a clientes. Los endpoints públicos salen del ámbito de sesión y comprueban token, objeto y propietario explícitamente. `_base_manager` se reserva para mantenimiento que necesite ver conflictos globales y no exponga filas a una respuesta.

## Publicación y propiedad

No inferir propiedad histórica desde la relación actual Device→Site→Client. Mantener el ledger temporal y el cliente congelado de la evidencia. Fuentes compartidas/ambiguas no se atribuyen por intuición. En reasignaciones, revocar/recrear las identidades que lo exijan; el ámbito de un canal HTTPS es inmutable.

Para clientes, usar la proyección publicable de `service_development.py`, incluido HTML/PDF/enlaces. Un enlace firmado no convierte toda la información interna en publicable. Los índices de clientes de Wazuh contienen proyección sanitizada, roles/DLS/tenants verificados; no compartir el índice bruto para simular aislamiento.

## Criptografía y transporte

- Claves separadas para UniFi, OPNsense, SSH/conectores y correo. La bóveda operativa y la auditoría derivan de SECRET_KEY; rotar sin migración rompe descifrado/verificación.
- SSH autentica contra una huella confirmada. No aceptar automáticamente una clave cambiada.
- HTTPS valida cadena y nombre. `indexer_tls.py` relaja únicamente un requisito de perfil de la PKI privada instalada; conserva CERT_REQUIRED y hostname. No generalizar esa excepción.
- Root/mTLS del indexador pertenece al worker protegido; el reader usa una credencial limitada distinta.
- No registrar cuerpos, tokens, credenciales o respuestas completas de fabricante. Auditoría usa una allowlist.

## Proxy y SSO Wazuh

Nginx consulta `/security/wazuh/check/` con un secreto interno. El backend comprueba sesión, MFA, permisos y ámbito listo; devuelve identidad/rol controlados. El proxy debe sustituir cabeceras de identidad del navegador y proteger la ruta interna. No es un token administrador reutilizable en el frontend. La configuración viva está fuera de Git.

## Límites conocidos

La cadena HMAC local detecta modificaciones internas, pero no prueba ausencia de truncamiento final sin anclaje externo. La rotación versionada de claves y ese anclaje siguen en roadmap. El canal de logs autentica al emisor configurado; no acredita que todos sus mensajes sean ciertos ni que UDP no pierda datagramas. Probar aislamiento al añadir cada nueva superficie.

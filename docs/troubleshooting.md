# Diagnóstico por síntoma

## Código correcto pero CSRF 403

Comprobar URL final, HTTPS público, ALLOWED_HOSTS, CSRF_TRUSTED_ORIGINS, puerto, cookies y Host/X-Forwarded-Proto. Proxy sobrescribe cabeceras no confiables. No mezclar formulario por IP y envío por dominio ni desactivar CSRF. Corregido el entorno, abrir formulario/sesión nuevos. Logger sin cuerpos ni códigos MFA.

## `/admin/` frente a `/login/`

Rutas distintas aunque compartan diseño. Admin requiere gestión global; usuario válido no implica ese permiso. Revisar correo/excepciones históricas, StaffAccess, permisos y MFA. No resetear credenciales sin confirmar problema.

## API o certificado

Separar DNS/ruta/puerto/ACL, TLS y permisos. Reloj, cadena, caducidad y SAN deben corresponder a nombre/IP usada. CA en formulario protegido; los valores de key/secret no incluyen los prefijos `key=`/`secret=` del archivo del fabricante. No usar `verify=False` ni abrir gestión WAN universalmente.

## API correcta, sin logs

Destino/protocolo/categorías, NAT/ruta, origen preservado y allowlist. Configurar, recibir datagrama e interpretar evento son pasos distintos. Generar actividad normal/prueba segura autorizada desde red protegida. Sin equipo, dejar validación real pendiente.

## HTTPS aceptado, sin alerta

Lote/mensaje: guardado → archivo nativo → índice → proyección. Revisar servicios privados, transport, perfil, disco/antigüedad. Desconocido/sin regla puede estar procesado sin alerta: no inventar incidente. Decoder/regla con muestra anonimizada en laboratorio.

## Cola o archivo detenido

No borrar payloads/cursores. Revisar worker, archivo/rotación, disco/perfil. Cambios de binario/reglas exigen sincronizar perfil. v1 ambiguo necesita revisión; v2 conserva UID. Mapeo/pipeline incorrecto conserva alerta cifrada: corregir y reintentar sin cambiar identidad.

## Fabricante muestra ataque, informe no

Comparar semana/zona, fuente/propiedad histórica, recepción/decoder, evento frente a flujo muestreado, parcialidad/cuotas y publicación. Activity Logging no reproduce toda la tabla Flows; Zenarmor exige revisar licencia/exportación/bypass. No corregir cifras copiando una pantalla manualmente.

## Correo no recibido

Activación/destinatario, configuración probada, URL pública, dispatch/proveedor. Webhook pendiente implica ausencia de prueba de entrega. Revisar estado incierto antes de repetir; nunca adjuntar API key a ticket.

## SSO Wazuh 502 / 403

502: servicio/upstream, puerto/base path/proxy. 403: sesión/MFA, secreto de subrequest, rol/cliente/ámbito listo. No forzar identidad desde navegador ni usar token admin compartido.

## Tests con 302 masivos hacia MFA

Configurar MFA solo para batería y respetar overrides de casos específicos. No trasladarlo a producción. 403 esperados en pruebas negativas no implican fallo: revisar resumen.

## SQLite bloqueado / timeout

Trabajo que retiene escritor, reserva temprana y presupuesto. No aumentar timeouts sin medir ni eliminar locks activos. Evidencia/checkpoint en transacción. PostgreSQL está pendiente; `select_for_update` no resuelve por sí solo SQLite.

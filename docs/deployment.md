# Despliegue y reversión

## Estado

Hay integración continua de comprobaciones (`.github/workflows/ci.yml`), pero no despliegue continuo ni reconstrucción de toda la infraestructura demostrada solo con `deploy/install.sh`. Prepara aplicación, venv, entorno, Nginx local y algunos servicios; contiene rutas/direcciones de la instalación original. Wazuh, indexador, SSO/proxy, credenciales, objetos y backups tienen requisitos adicionales. Versionar la entrega completa es bloque 4. Un push no despliega.

## Staging

1. Seleccionar commit/branch y árbol limpio. No desplegar un directorio con datos/cambios sin revisar.
2. Revisar Python/SO y rutas/IP/puertos del instalador. DNS, HTTPS, cabeceras y CA; solo puertos necesarios.
3. Secretos propios del entorno; reader separado de admin mTLS. Código root y escritura web solo en su zona de datos.
4. Pruebas, migraciones `--check`, renders y aislamiento; verificar recuperación de la versión anterior.
5. Manifiesto: commit, dependencias, esquema, reglas, unidades y objetos Wazuh. Aún no se genera completo automáticamente.

## Instalación base

El script root cambia el host: leerlo completo y no usarlo para actualizar (para eso, `update.sh`). Genera clave inicial si falta; recuperarla por canal privado y cambiarla, sin copiar a Git.

```sh
sudo SOC_INSTALL_ADDRESS=10.0.0.5 SOC_INSTALL_PORT=8443 deploy/install.sh /ruta/del/checkout
```

`SOC_INSTALL_ADDRESS` y `SOC_INSTALL_PORT` (por defecto `172.20.10.20` y `8443`, la VM original) fijan la escucha de Nginx, el certificado autofirmado, `ALLOWED_HOSTS` y `CSRF_ORIGINS`; `SOC_INSTALL_PYTHON_PACKAGE` el paquete de venv (`python3.14-venv`). Si el origen es un checkout Git limpio instala exactamente su commit y lo registra en `.deployed-commit`, como `update.sh`; con una carpeta copiada mantiene el comportamiento anterior.

Ensayado en un contenedor limpio (Ubuntu, Python 3.13, systemd simulado, sin Wazuh): instalación en 22 s, login y estáticos por HTTPS a través de Nginx, administrador inicial válido y `update.sh` operativo sobre la instalación nueva. No instala Wazuh, el indexador, el motor HTTPS, el proxy SSO ni las unidades de trabajos si falta `/var/ossec`; tampoco restaura datos.

`deploy/wazuh/install_https_engine.sh` requiere entorno protegido, Wazuh/indexador locales y mTLS root. Servicios privados parados antes de sustituir el perfil. No instala todo Wazuh.

## Actualización existente

`deploy/update.sh` automatiza los pasos siguientes para una instalación ya creada con `install.sh`. Se ejecuta como root desde un checkout Git limpio en el servidor:

```sh
cd /ruta/del/checkout && git pull
sudo deploy/update.sh                      # muestra cambios y pide confirmación
sudo deploy/update.sh --rollback /var/backups/soc-portal/<copia>
```

1. Toma el código del commit (`git archive`), nunca de archivos sin commit, y rechaza un checkout con cambios. Avisa si la rama no es `main` o no coincide con `origin`.
2. Antes de tocar producción ejecuta `manage.py check` y `makemigrations --check` sobre ese commit en un directorio temporal. Muestra versión instalada, commits, migraciones nuevas, cambios de dependencias y unidades systemd que difieran de las instaladas.
3. Comprueba que hay espacio para la copia (unas tres veces la base más 300 MiB) antes de parar nada. Para los timers `soc-*` activos, espera a que terminen los trabajos en curso y para `soc-portal`. No para `soc-wazuh-https` ni `soc-wazuh-https-db`.
4. Copia en `/var/backups/soc-portal/<fecha>-<commit>/`: base SQLite con la API backup e `integrity_check`, código instalado, commit, timers activos y huellas SHA-256 de las claves de cifrado (`key-fingerprints.txt`, nunca las claves). Conserva las 10 copias más recientes.
5. Sustituye el código, instala dependencias si cambian, migra, ejecuta collectstatic y `check`, registra el commit en `/srv/soc-portal/.deployed-commit`, rearranca exactamente los timers que estaban activos y comprueba que el login responde HTTP 200.
6. Si falla antes de sustituir el código (espera de trabajos, copia, espacio), vuelve a arrancar el portal y los timers: no ha cambiado nada. Si falla después, se detiene con servicios parados e indica la orden de reversión. `--rollback` comprueba antes de parar nada que la copia es legible (`pg_restore --list` o `integrity_check`) y que las claves con que se hizo siguen configuradas (si falta alguna se niega; `--ignore-keys` lo fuerza), guarda el estado actual y restaura código, base, estáticos y timers de la copia; se pierden los datos escritos después de esa copia. Al terminar comprueba, sin escribir, que los secretos se descifran (`rotate_encryption_keys`).

El archivo de entorno se lee con `deploy/envfile.py`, con las reglas de `EnvironmentFile` de systemd: un `$` o un espacio en una contraseña son texto, como para el portal. `requirements-postgresql.txt` forma parte del código desplegado y se instala con PostgreSQL.

Con `SOC_PORTAL_DB_ENGINE=postgresql` la copia usa `pg_dump` y la reversión restaura la base antes que el código y en una sola transacción ([base de datos](database.md)); requiere `postgresql-client`. El SQL de restauración se genera completo en la carpeta de la copia antes de tocar la base: con una copia truncada, la base queda como estaba (comprobado con PostgreSQL 16; antes, la tubería confirmaba una restauración parcial).

Límites: no instala ni modifica unidades systemd, Nginx, Wazuh, el perfil del motor HTTPS, secretos ni índices; si una entrega los cambia, aplicar los pasos manuales siguientes. La copia no sustituye la copia de VM ni la de `recovery.py`. Probado en una instalación simulada (systemd simulado) con despliegue, migración nueva, migración fallida, commit con error y reversión, y desplegado en la VM el 20/10/2026 (véase [traspaso](handoff.md)). La reversión aún no se ha ensayado en la VM.

Pasos manuales equivalentes o adicionales:

1. Copia consistente SQLite mediante API backup, código/configuración/secretos protegidos y snapshot del índice cuando proceda. No copiar una base viva ignorando WAL/journal.
2. Identificar timers/escritores; detener los afectados y coordinar ventana del portal.
3. Instalar código con permisos; migrar con usuario/entorno adecuados; collectstatic y check.
4. Verificar unidades/perfil incluidos en entrega; daemon-reload; dependencias, servicios y timers.
5. Cotejar archivos/versión, esquema y éxito de tareas. Probar HTTPS/scope; no inyectar amenazas ficticias en clientes.
6. Registrar respaldo privado y aceptación. `active` no acredita recepción.

## IP real detrás de otro proxy

Si el portal se publica a través de otro Nginx (en la instalación actual, el Nginx público 172.20.10.112), el Nginx local ve siempre la IP de ese proxy. Entonces el límite de intentos por IP trata a todo internet como un solo usuario y la auditoría no ve el origen. «Salud del SOC» lo avisa (`platform:real-ip`) cuando todos los accesos de una semana llegan desde una única IP interna.

1. En el proxy público, dentro del bloque que publica el SOC: `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;` y recargar.
2. En la VM del SOC: `sudo deploy/configurar_ip_real.sh 172.20.10.112`. Escribe `/etc/nginx/conf.d/soc-real-ip.conf` (`set_real_ip_from` solo para esa IP), comprueba `nginx -t` y recarga; si la comprobación falla, restaura el archivo anterior. Solo admite IPs o redes privadas de /24 o menos. `--ver` muestra la configuración y `--quitar` la retira.
3. Comprobar que aparecen IPs públicas en `/var/log/nginx/access.log`. El aviso se resuelve con el primer acceso desde una IP pública.

`update.sh` no modifica Nginx: este paso se hace una vez y se conserva entre actualizaciones.

## Registros sin secretos de URL

Una sola vez en las instalaciones anteriores a octubre de 2026, después de desplegar con `update.sh` (que avisa mientras falte):

```sh
sudo deploy/configurar_registros.sh          # --ver muestra el estado; --quitar lo deshace
```

1. Instala `/etc/nginx/conf.d/soc-log-redaction.conf` y añade `access_log /var/log/nginx/access.log soc_redacted;` al servidor del portal. Comprueba `nginx -t`; si falla, restaura lo anterior sin recargar.
2. Añade `/etc/systemd/system/soc-portal.service.d/gunicorn.conf`, que arranca gunicorn con `deploy/gunicorn.conf.py` (sin registro de accesos). Reinicia el portal y comprueba que el login responde; si no, deshace el cambio.

Desde entonces, las opciones de gunicorn viajan con el código y `update.sh` las actualiza. `install.sh` ya instala así las instalaciones nuevas. Motivo y alcance: [seguridad](security.md#secretos-en-url-y-registros).

## Wazuh del SOC por nombre y por IP

El botón «SOC general en Wazuh» (y el panel de cada cliente) lleva a `/wazuh/…` en el mismo host por el que se entró al portal. Nginx debe tener las rutas de Wazuh en **todos** los bloques del portal:
- `/_soc_wazuh_auth`: pregunta al portal la sesión, el doble factor y el ámbito, con el secreto `SOC_WAZUH_PROXY_KEY`;
- `/wazuh` y `/wazuh/`: reenvío al Wazuh Dashboard local (`https://127.0.0.1:5602`) con la identidad devuelta;
- `@soc_wazuh_login`: vuelta a la entrada del portal si no hay sesión.

Sin esas rutas, el portal responde «Not Found» (su 404) a `/wazuh/…`. Así ocurría al entrar por `https://172.20.10.20:8443`, cuyo bloque, el que genera `install.sh`, no las tenía (20/11/2026).

- **VM existente:** `sudo deploy/configurar_wazuh_nginx.sh`.
  - Mueve las rutas del bloque que ya las tiene a `/etc/nginx/snippets/soc-wazuh-rutas.conf` (root, 0600), sin mostrar el secreto. El secreto puede estar escrito en ellas o incluido desde otro archivo, como `snippets/soc-wazuh-auth-key.conf` en la VM, que no se toca.
  - Las incluye en ese bloque y en el del portal por IP (`sites-available/soc-portal`).
  - Guarda copia en `/var/backups/soc-nginx/` y comprueba `nginx -t`; si falla, lo restaura todo sin recargar.
  - `--ver` muestra qué bloques las incluyen.
- **Instalación nueva:** copiar `deploy/nginx/soc-wazuh-rutas.conf.example` a `/etc/nginx/snippets/soc-wazuh-rutas.conf`, poner el valor de `SOC_WAZUH_PROXY_KEY` y dejar el archivo con permisos 0600. El bloque que genera `install.sh` ya lo incluye si existe.

## Antivirus de los adjuntos (ClamAV)

`sudo deploy/configurar_antivirus.sh`:
1. Comprueba la memoria libre; `clamd` necesita unos 1,5 GB.
2. Instala `clamav-daemon` y `clamav-freshclam` y espera a la primera descarga de firmas. Necesita salida a `database.clamav.net`.
3. Arranca el demonio y prueba que detecta el archivo de prueba EICAR por el socket que usa el portal (`/run/clamav/clamd.ctl`).

`--ver` muestra servicios, socket y fecha de las firmas; `--probar` repite la prueba EICAR. El trabajo «Antivirus de adjuntos» (cada minuto) empieza a analizar solo, también los adjuntos anteriores. No hace falta reiniciar el portal ni tocar Nginx.

Si ClamAV deja de responder con adjuntos esperando más de 15 minutos, o sus firmas tienen más de 3 días, aparece «Antivirus de adjuntos» en «Salud del SOC». Otro socket se indica con `SOC_PORTAL_CLAMD_SOCKET`.

## Vulnerabilidades de los equipos

`sudo deploy/wazuh/permitir_vulnerabilidades.sh --aplicar` permite al usuario de solo lectura del SOC leer el índice de vulnerabilidades de Wazuh (rol `soc_vulnerabilities_reader`), con el certificado de administración del indexador de la VM. Del archivo del usuario de lectura solo lee el nombre. `--ver` muestra el permiso, cuántas filas tiene el índice y si la detección de vulnerabilidades está activa en el gestor (`<vulnerability-detection>` en `ossec.conf`, activa por defecto desde Wazuh 4.8). Los agentes envían su inventario sin configuración adicional. [Integraciones](integrations.md#vulnerabilidades-de-los-equipos-28112026).

## Antivirus de equipos: agentes Wazuh con Microsoft Defender

En el gestor de Wazuh del SOC:
1. `sudo deploy/wazuh/configurar_defender.sh --reglas`: instala la regla del informe de salud de Defender y reinicia `wazuh-manager` solo si `wazuh-analysisd -t` la acepta; si no, deja todo como estaba.
2. `sudo deploy/wazuh/configurar_defender.sh --grupo CODIGO`, por cliente (el código del portal): crea el grupo de agentes `soc-CODIGO` con su `agent.conf` (canal de Defender, plantilla `deploy/wazuh/agente_defender.conf.example`) y muestra el comando de instalación del agente. Añade también la vigilancia en tiempo real de la integridad de archivos (`deploy/wazuh/agente_integridad.conf.example`): carpeta Inicio, tareas programadas, archivo hosts y claves Run, RunOnce, Winlogon y Services en Windows; SSH, sudoers, cron, systemd, PAM y claves SSH de root en Linux. Se puede repetir en un grupo ya creado: añade solo lo que falte y guarda una copia del `agent.conf` anterior. Los agentes reciben el cambio en unos minutos, sin reiniciar el gestor.

En cada equipo Windows del cliente se instala el agente con `WAZUH_AGENT_GROUP="soc-CODIGO"`. El agente debe alcanzar el gestor del SOC (puertos 1514 y 1515):
- **Preferible:** por la VPN de la sede con el SOC;
- **Alternativa:** una publicación limitada a las IP de las sedes.

Si el gestor exige contraseña de alta, se pasa con `WAZUH_REGISTRATION_PASSWORD`; no se copia en el chat ni en el repositorio.

**Equipos Linux:** con el repositorio de paquetes de Wazuh añadido (misma versión que el gestor), `WAZUH_MANAGER="…" WAZUH_AGENT_GROUP="soc-CODIGO" apt-get install wazuh-agent` (o `dnf install` en RHEL, Rocky o Alma) y `systemctl enable --now wazuh-agent`; `--grupo` muestra los comandos. Sin configuración adicional el agente envía los accesos (SSH, sudo, PAM) de `/var/log/auth.log` o `/var/log/secure`, la configuración segura (CIS de su distribución), la integridad de archivos y el inventario para las vulnerabilidades. En distribuciones solo con journald (Debian 12 mínimo), instalar `rsyslog` para que exista `/var/log/auth.log`; no añadir además journald al agente, porque cada intento contaría dos veces. En el portal, el equipo aparece como «Sin Defender (Linux)» y, si no llega ningún acceso en un día, «Sin registros de acceso».

Después, en el portal, «Antivirus de equipos › Agentes sin asignar»: marcar los equipos y asignarlos al cliente. El grupo de Wazuh no asigna nada por sí solo. `--ver` muestra si la regla y los grupos están aplicados.

## DNS del SOC por la VPN de sedes

Para bloquear dominios en sedes cuyo firewall no admite listas DNS (Grandstream GCC). `sudo deploy/configurar_dns_soc.sh --instalar`:
1. Comprueba que la VPN de sedes (`wg-soc`, 10.255.251.1) está activa y que nada más escucha en su puerto 53.
2. Instala Unbound y su configuración base (`/etc/unbound/unbound.conf.d/soc-base.conf`): escucha **solo** en 10.255.251.1, rechaza cualquier origen salvo las sedes que autorice el SOC y no registra las consultas resueltas. Si `unbound-checkconf` no la acepta, la retira.
3. Instala y arranca el trabajo `soc-dns` (cada 15 minutos, root), que escribe la configuración de los clientes (`soc-qfeeds.conf`) y sus zonas (`/var/lib/unbound/soc`), la comprueba y recarga Unbound solo si cambió.

Necesita salida DNS (53/UDP y TCP) desde la VM hacia Internet: Unbound resuelve por sí mismo. Las reglas nft de la VPN (`soc-vpn`) solo abren el puerto 53 a las sedes de clientes con «DNS del SOC» activado; sin ninguno, no cambian. `--ver` muestra el estado. Después, en el portal, se activa «DNS del SOC» en la lista de bloqueo del cliente y se configura su firewall con la guía.

## CrowdSec sin compartir señales

`sudo deploy/configurar_crowdsec_privado.sh --aplicar` deja el motor CrowdSec del SOC sin enviar señales ni datos a CrowdSec. Escribe `sharing: false` en `/etc/crowdsec/config.yaml.local` y desactiva las opciones de la consola; si `crowdsec -t` no lo acepta, retira el ajuste. Si `config.yaml.local` ya existe con otros ajustes, se detiene e indica qué añadir a mano. La lista comunitaria pasa a la versión reducida. `--ver` muestra el estado. [Integraciones](integrations.md#instalar-el-motor-local-modo-gratuito).

## Reversión

Detener escritores/timers y servicios nuevos antes de restaurar código/unidades y base compatible. Retirar archivos nuevos ausentes en versión anterior; no dejar migraciones importándose contra un esquema restaurado. Recargar systemd, regenerar estáticos y arrancar componentes previstos.

Recuperar una base anterior puede perder datos posteriores al corte: coordinar tráfico y ventana. Deshacer Git no revierte datos, índices, cambios remotos o secretos. Ensayar rollback y guardar diagnóstico privado.

3B conservó backup previo y verificó servicios/archivos; eso no equivale a reconstruir VM completa desde este repositorio.

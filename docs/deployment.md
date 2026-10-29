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

## Reversión

Detener escritores/timers y servicios nuevos antes de restaurar código/unidades y base compatible. Retirar archivos nuevos ausentes en versión anterior; no dejar migraciones importándose contra un esquema restaurado. Recargar systemd, regenerar estáticos y arrancar componentes previstos.

Recuperar una base anterior puede perder datos posteriores al corte: coordinar tráfico y ventana. Deshacer Git no revierte datos, índices, cambios remotos o secretos. Ensayar rollback y guardar diagnóstico privado.

3B conservó backup previo y verificó servicios/archivos; eso no equivale a reconstruir VM completa desde este repositorio.

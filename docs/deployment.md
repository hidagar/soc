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

El script root cambia el host: adaptarlo y leerlo completo, no usarlo como receta universal de actualización. Genera clave inicial si falta; recuperarla por canal privado y cambiarla, sin copiar a Git.

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
3. Para los timers `soc-*` activos, espera a que terminen los trabajos en curso y para `soc-portal`. No para `soc-wazuh-https` ni `soc-wazuh-https-db`.
4. Copia en `/var/backups/soc-portal/<fecha>-<commit>/`: base SQLite con la API backup e `integrity_check`, código instalado, commit y timers activos. Conserva las 10 copias más recientes.
5. Sustituye el código, instala dependencias si cambian, migra, ejecuta collectstatic y `check`, registra el commit en `/srv/soc-portal/.deployed-commit`, rearranca exactamente los timers que estaban activos y comprueba que el login responde HTTP 200.
6. Si falla, se detiene con servicios parados e indica la orden de reversión. `--rollback` guarda antes el estado actual y restaura código, base, estáticos y timers de la copia; se pierden los datos escritos después de esa copia.

Límites: no instala ni modifica unidades systemd, Nginx, Wazuh, el perfil del motor HTTPS, secretos ni índices; si una entrega los cambia, aplicar los pasos manuales siguientes. La copia no sustituye la copia de VM ni la de `recovery.py`. Probado en una instalación simulada (systemd simulado) con despliegue, migración nueva, migración fallida, commit con error y reversión, y desplegado en la VM el 20/10/2026 (véase [traspaso](handoff.md)). La reversión aún no se ha ensayado en la VM.

Pasos manuales equivalentes o adicionales:

1. Copia consistente SQLite mediante API backup, código/configuración/secretos protegidos y snapshot del índice cuando proceda. No copiar una base viva ignorando WAL/journal.
2. Identificar timers/escritores; detener los afectados y coordinar ventana del portal.
3. Instalar código con permisos; migrar con usuario/entorno adecuados; collectstatic y check.
4. Verificar unidades/perfil incluidos en entrega; daemon-reload; dependencias, servicios y timers.
5. Cotejar archivos/versión, esquema y éxito de tareas. Probar HTTPS/scope; no inyectar amenazas ficticias en clientes.
6. Registrar respaldo privado y aceptación. `active` no acredita recepción.

## Reversión

Detener escritores/timers y servicios nuevos antes de restaurar código/unidades y base compatible. Retirar archivos nuevos ausentes en versión anterior; no dejar migraciones importándose contra un esquema restaurado. Recargar systemd, regenerar estáticos y arrancar componentes previstos.

Recuperar una base anterior puede perder datos posteriores al corte: coordinar tráfico y ventana. Deshacer Git no revierte datos, índices, cambios remotos o secretos. Ensayar rollback y guardar diagnóstico privado.

3B conservó backup previo y verificó servicios/archivos; eso no equivale a reconstruir VM completa desde este repositorio.

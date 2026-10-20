# Despliegue y reversión

## Estado

No hay CI/CD completo ni reconstrucción de toda la infraestructura demostrada solo con `deploy/install.sh`. Prepara aplicación, venv, entorno, Nginx local y algunos servicios; contiene rutas/direcciones de la instalación original. Wazuh, indexador, SSO/proxy, credenciales, objetos y backups tienen requisitos adicionales. Versionar la entrega completa es bloque 4. Un push no despliega.

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

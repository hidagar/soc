# Centro SOC · ib-red empresas

Portal de gestión de seguridad para clientes, sedes y firewalls. Wazuh analiza los eventos; el portal aporta aislamiento por cliente, investigación, seguimiento, informes y operación.

## Continuar el proyecto

**Entrada principal: [documentación del proyecto](docs/README.md).**

- IA: leer [AGENTS.md](AGENTS.md) y [estado/traspaso](docs/handoff.md) antes de cambiar código.
- Desarrollo: [arranque local](docs/development.md), [arquitectura](docs/architecture.md), [modelo de datos](docs/domain-model.md), [contribución](CONTRIBUTING.md).
- Operación: [configuración](docs/configuration.md), [despliegue](docs/deployment.md), [trabajos](docs/operations.md), [recuperación](docs/recovery.md), [diagnóstico](docs/troubleshooting.md).
- Funciones: [integraciones](docs/integrations.md), [ingesta](docs/ingestion.md), [informes/correo](docs/reports-and-mail.md), [interfaz](docs/frontend.md), [guía funcional](docs/user-guide.md).
- Referencia: [módulos](docs/reference/modules.md), [modelos](docs/reference/models.md), [rutas](docs/reference/routes.md), [entorno](docs/reference/environment.md), [trabajos](docs/reference/jobs.md), [migraciones/pruebas](docs/reference/verification.md).
- Planificación: [decisiones](docs/decisions.md) y [hoja de ruta](docs/roadmap.md).

Estado documentado: **20/10/2026**. La parte servidor de 3B está desplegada; la validación del primer relay en sede sigue pendiente. PostgreSQL/CI y otras ampliaciones no se presentan como completadas. `main` contiene la aplicación y es la rama base (la rama de importación `codex/soc-platform-2026-10-20` apunta al mismo commit); comprobar el estado de ramas antes de desarrollar.

## Funcionalidades

- Asistente de conexión y exportación Syslog para OPNsense, UniFi, Hillstone y Grandstream GCC/GDMS, según las capacidades del equipo.
- Usuarios con invitación, establecimiento de contraseña, MFA y permisos por cliente.
- Evidencias e incidencias, mapa geográfico y contexto ASN, tareas y auditoría.
- Informes semanales HTML/PDF, enlaces protegidos y envío mediante SendGrid.
- Comprobaciones de recepción, detección, estado de conectores, copias y trabajos separados por systemd.
- Canal HTTPS autenticado para IP dinámica, bandeja cifrada y confirmación nativa de Wazuh con deduplicación hasta el portal. La validación en una sede real sigue pendiente.

## Desarrollo local

Python 3.12 o superior; producción verificada en Linux con Python 3.14.

```sh
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
mkdir -p data
export SOC_PORTAL_DEBUG=1
python manage.py migrate
python manage.py createsuperuser --username developer --email developer@example.test
python manage.py runserver
```

En PowerShell, activa `.venv\Scripts\Activate.ps1` y establece `$env:SOC_PORTAL_DEBUG="1"`. Entrar por correo en `http://127.0.0.1:8000/login/`; configurar MFA cuando lo pida. Django no carga `.env` automáticamente. El modo de desarrollo nunca debe usarse en un servicio público.

## Pruebas

```sh
SOC_PORTAL_DEBUG=1 SOC_PORTAL_MFA_REQUIRED=0 python manage.py test
SOC_PORTAL_DEBUG=1 python manage.py makemigrations --check --dry-run
python docs/tools/generate_reference.py --check
python docs/tools/check_docs.py
```

El ajuste MFA anterior solo corresponde al entorno de pruebas. Las pruebas de permisos y MFA establecen sus propios escenarios. Los ensayos nativos e integración requieren un laboratorio Linux separado; no inyectar sus fixtures en índices de producción. [Guía completa de pruebas](docs/testing.md).

## Despliegue

Para actualizar una instalación existente desde Git: `git pull` y `sudo deploy/update.sh` (copia, migración, reinicio, comprobación y `--rollback`); ver [despliegue](docs/deployment.md). `deploy/install.sh` prepara la aplicación y los servicios de la instalación Linux. Revisar rutas, proxy HTTPS, certificados y variables de entorno antes de ejecutarlo. Las credenciales se introducen en el panel o en el archivo protegido de configuración del servidor, fuera de Git.

Para el motor privado del canal HTTPS existe `deploy/wazuh/install_https_engine.sh`, que se ejecuta como root con el entorno protegido del portal cargado. Requiere Wazuh e indexador locales y acceso mTLS administrativo. Detener primero los servicios privados si se actualiza su perfil. Las copias y la reversión deben verificarse antes de migrar una instalación existente.

- [Arquitectura y operación del canal HTTPS](docs/entrega-wazuh-https.md)
- [Hoja de ruta](docs/roadmap.md)

## Contenido del repositorio

`core/`: backend, migraciones y pruebas. `socportal/`: configuración Django. `templates/`, `static/`, `public/`: interfaz y marca. `deploy/`: servicios, reglas/decodificadores y herramientas de instalación.

No se incluyen bases de datos, información de clientes, claves SSH, certificados privados, tokens, logs, copias de seguridad ni entornos virtuales. La publicación de este código no configura automáticamente un servidor ni despliega cambios.

# Desarrollo local

## Requisitos y aislamiento

Python 3.12 o superior para desarrollo; la entrega Linux se comprobó con 3.14. Dependencias fijadas en `requirements.txt`. No se necesita Node ni un bundler para la interfaz actual. Algunos comandos solo funcionan en Linux/root y algunas pruebas necesitan Wazuh real.

Trabajar con una base vacía o fixtures anonimizadas. No copiar `portal.env`, bases ni secretos de producción para hacer funcionar el entorno. No usar el dominio real como destino de pruebas de envío.

## Linux / macOS: aplicación web

Desde la raíz del checkout que contiene `manage.py`:

```sh
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
mkdir -p data
export SOC_PORTAL_DEBUG=1
python manage.py migrate
python manage.py createsuperuser --username developer --email developer@example.test
python manage.py runserver 127.0.0.1:8000
```

Abrir `http://127.0.0.1:8000/login/`. Iniciar sesión con el correo. El primer acceso protegido pedirá configurar MFA si está habilitado. El modo DEBUG permite HTTP local; nunca publicarlo.

## PowerShell

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
New-Item -ItemType Directory -Force data | Out-Null
$env:SOC_PORTAL_DEBUG = "1"
python manage.py migrate
python manage.py createsuperuser --username developer --email developer@example.test
python manage.py runserver 127.0.0.1:8000
```

Si la política de ejecución impide activar el entorno, invocar su `python.exe` directamente; no hace falta cambiar la política global del equipo.

## Configuración local

Django no carga `.env` automáticamente: lee el entorno del proceso. [.env.example](../.env.example) describe una configuración de servidor que debe completarse con valores privados; no se debe importar sin revisar en un entorno de desarrollo.

Para probar conectores se necesitan claves de cifrado específicas de desarrollo y servicios simulados o equipos de laboratorio. Generar claves Fernet nuevas cuando proceda, guardarlas fuera de Git y no confundir la clave de cifrado local con la clave API del fabricante. No activar MailSettings ni importar destinatarios reales. `SOC_REPORT_EMAIL_BACKEND` por sí solo no anula el envío directo por la API de SendGrid.

## Comprobaciones rápidas

```sh
SOC_PORTAL_DEBUG=1 python manage.py check
SOC_PORTAL_DEBUG=1 python manage.py makemigrations --check --dry-run
SOC_PORTAL_DEBUG=1 SOC_PORTAL_MFA_REQUIRED=0 python manage.py test core.test_wazuh_delivery
python docs/tools/generate_reference.py --check
```

En PowerShell usar variables `$env:` y después invocar Python. Para la batería completa y los ensayos separados, ver [testing.md](testing.md).

## Trabajar con datos y migraciones

Crear `data/` antes de migrar; está excluido de Git. No cambiar una migración aplicada. Los nuevos modelos deben quedar importados por `core/models.py` para que Django los registre. Revisar `.clean()`, relaciones, ScopedManager y propiedad histórica además de generar el archivo de migración. Las señales de `core/apps.py` sincronizan roles tras migrar y capturan cambios de propiedad en operaciones de modelos.

No ejecutar los comandos de monitorización de producción para poblar una demo local: pueden llamar servicios, APIs, correo e indexador. Preparar fixtures con propósito explícito y usar mocks en pruebas.

# Pruebas

## Entorno normal

Base vacía, claves de desarrollo y servicios simulados; no cargar el entorno de producción. MFA se ajusta solo para el proceso de pruebas; los casos específicos fijan sus escenarios.

```sh
SOC_PORTAL_DEBUG=1 SOC_PORTAL_MFA_REQUIRED=0 python manage.py test --verbosity 1
SOC_PORTAL_DEBUG=1 python manage.py check
SOC_PORTAL_DEBUG=1 python manage.py makemigrations --check --dry-run
python docs/tools/generate_reference.py --check
```

PowerShell: establecer `$env:SOC_PORTAL_DEBUG="1"` y `$env:SOC_PORTAL_MFA_REQUIRED="0"` antes de invocar Python. No persistir estos valores en un servicio público.

## Integración continua

`.github/workflows/ci.yml` ejecuta en GitHub, en cada push a `main` y en cada pull request, los mismos comandos del apartado anterior (salvo `check`, cubierto por las pruebas), `check_docs.py` y `shellcheck -S warning` sobre los scripts de `deploy/`. Usa Python 3.14 como producción, base de pruebas vacía y ningún secreto. Un segundo trabajo repite la batería sobre PostgreSQL 16, y el primero ejecuta los ensayos de concurrencia con SQLite de archivo. Un resultado verde no acredita despliegue, ensayos nativos ni validación en una sede.

## Selección por cambio

| Área | Grupos que localizar |
|---|---|
| Scope/login/publicación | `test_public_panel`, `test_access_onboarding`, `test_customer*`, `test_*scope*`, `test_*isolation*`, `test_*sso*` |
| Eventos/informes | `test_event*`, `test_operations`, `test_source*`, `test_findings*`, informes y `core.tests` |
| Transporte/workers | `test_durable_operations`, `test_wazuh_delivery` |
| Fabricante | `test_unifi*`, `test_hillstone*`, `test_gdms*`, `test_gcc*`, `test_zenarmor*`, inventario |
| Trabajo/cobertura | `test_work_queue`, pruebas network/coverage/service |

Son patrones para buscar, no labels de Django. Usar los nombres reales del [inventario](reference/verification.md).

## Casos según el área

Cliente A no ve B por HTML/JSON/PDF/enlace/relaciones; notas no publicadas no aparecen. Fuente ambigua/reasignada no transfiere histórico. Consulta parcial conserva informe/checkpoint. Reintento no suma evidencia/contador. Clave revocada y CA/huella cambiada fallan. Motor/índice parado, archivo parcial/rotado y cola llena conservan pendientes. Aceptación de correo no acredita entrega.

## SQLite de archivo

`FileDatabaseConcurrencyTests` y `test_database_concurrency` se omiten en memoria. Requieren archivo TEST exclusivo escribible; varios escritores con conexiones propias prueban el bloqueo real. No sustituir por dos llamadas dentro de una sola transacción TestCase.

Forma corta (la misma que usa CI):

```sh
SOC_PORTAL_DEBUG=1 SOC_PORTAL_MFA_REQUIRED=0 SOC_PORTAL_DB_TEST_NAME=data/concurrency-test.sqlite3 \
  python manage.py test core.test_durable_operations.FileDatabaseConcurrencyTests core.test_database_concurrency
```

## PostgreSQL

Con un PostgreSQL desechable y `pip install -r requirements-postgresql.txt`:

```sh
SOC_PORTAL_DEBUG=1 SOC_PORTAL_MFA_REQUIRED=0 SOC_PORTAL_DB_ENGINE=postgresql SOC_PORTAL_DB_HOST=127.0.0.1 \
  SOC_PORTAL_DB_PASSWORD=... python manage.py test
```

El usuario necesita `CREATEDB` para la base `test_*`. Las pruebas de `test_database_concurrency` sí se ejecutan aquí. Los identificadores no se reinician entre pruebas: no construir IP u otros valores a partir de `pk`.

Alternativa con runner propio desde la raíz de un checkout aislado:

```python
import os
os.environ['SOC_PORTAL_DEBUG'] = '1'
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'socportal.settings')
from django.conf import settings
settings.DATABASES['default']['TEST'] = {
    'NAME': str(settings.BASE_DIR / 'data' / 'concurrency-test.sqlite3')}
import django
django.setup()
from django.test.utils import get_runner
result = get_runner(settings)(interactive=False).run_tests(
    ['core.test_durable_operations.FileDatabaseConcurrencyTests'])
raise SystemExit(bool(result))
```

El runner crea/destruye ese archivo. Nunca seleccionar la base real del portal ni guardar esto en un módulo que se ejecute durante imports normales.

## Ensayo nativo optativo

`core.test_native_pipeline.NativePipelineGate`: activar `SOC_NATIVE_ENGINE_GATE=1` antes de importar el módulo. Requiere Linux/root, Wazuh/indexador, certificado administrativo y `/var/lib/soc-wazuh-https-lab` preparado con `deploy/wazuh/prepare_https_engine.py`. Usar TEST de archivo aislado como arriba y seleccionar ese label.

Procesos nativos reales y prefijos únicos con las plantillas instaladas; simula fallos/repetición y verifica cuatro evidencias. Limpia índice/pipeline/template temporales. Si se interrumpe, revisar restos por prefijo exacto; nunca borrar `wazuh-alerts-*` para limpiar. No ejecutarlo rutinariamente sobre clientes sin aislamiento/autorización de laboratorio.

El ensayo systemd con restricciones se hizo en 3B; no forma parte del runner estándar. Instalación completa, carga sostenida, TLS/red de sede y recuperación VM exigen ensayos propios.

## Evidencia histórica

3B registró 595 pruebas completas antes del último ajuste del lector, 73 dirigidas después y ensayos separados SQLite/nativo/systemd. Es resultado fechado, no conteo fijo esperado. Mensajes 403/CSRF de casos negativos no implican fallo: revisar el resumen del runner.

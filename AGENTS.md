# Instrucciones para agentes y desarrolladores

Este repositorio contiene el Centro SOC de ib-red empresas. Antes de cambiar código, leer [docs/README.md](docs/README.md), [estado y traspaso](docs/handoff.md), [arquitectura](docs/architecture.md) y [seguridad](docs/security.md). La hoja de ruta está en [docs/roadmap.md](docs/roadmap.md). El código prevalece ante una nota histórica; documentar las divergencias.

## Forma de trabajar

- Usar una rama de trabajo y conservar el historial. La importación inicial del proyecto está en `codex/soc-platform-2026-10-20`; desde el 20/10/2026 `main` apunta al mismo commit y es la rama base. Comprobar la rama base real antes de crear otra.
- El checkout Git es la fuente para las nuevas entregas. No continuar a ciegas en una copia de trabajo antigua ni copiar una VM completa sobre el repositorio.
- No hay despliegue automático desde GitHub. Una modificación de código o documentación no autoriza cambios en firewalls, envío de correo, migraciones o reinicios de producción por sí sola. Respetar la autorización concreta de la tarea y el procedimiento de [despliegue](docs/deployment.md).
- Nunca añadir `.env`, claves SSH, certificados privados, bases, ZIP de relay, credenciales, logs o datos reales de clientes. Usar fixtures anonimizadas. No imprimir respuestas crudas de fabricantes o secretos en diagnóstico.
- Mantener la marca `ib-red` en minúsculas y los logos de empresas existentes. Interfaz y documentación operativa en español.
- Antes de terminar: explicar cambios, pruebas ejecutadas, límites y trabajo pendiente. No confundir implementación, prueba aislada, despliegue y validación en una sede.

## Invariantes que no se deben romper

1. El ámbito de cliente vive en `scope.py`/`security.py`. `None` significa sin filtro, **no** sin acceso. Un contexto vacío deniega datos de clientes. Las vistas públicas deben autorizar y delimitar explícitamente sus datos.
2. La propiedad histórica de una fuente o evidencia no se deduce de la ficha actual del equipo. Mantener `SourceOwnership`, `client_scope_id` y las comprobaciones de ambigüedad.
3. El cliente recibe una proyección explícita de datos publicables; usar `service_development.customer_report_context` en portal, enlace y PDF del cliente. No pasar notas internas, logs crudos o incidentes no publicados.
4. Una API accesible no acredita logs recibidos; un log recibido no acredita detección; una detección permitida no prueba compromiso. Mantener acción `unknown` cuando falte evidencia. Centralizar interpretación en `operations.normalize` y `event_contract`.
5. Una consulta incompleta del indexador no puede sustituir el último informe válido ni avanzar un cursor como si hubiera terminado.
6. No confirmar entrega por el resultado de `send()` o un HTTP 202 aislado. Conservar bandeja y UUID; v2 exige recibo nativo y verificación del documento. Repetir no puede inflar evidencias/contadores. No prometer ejecución exactamente una vez dentro de Wazuh ni en el salto UDP.
7. Mantener las reservas tempranas del escritor y transacciones de evidencias/checkpoints en SQLite. `select_for_update()` por sí solo no proporciona el mismo bloqueo en SQLite.
8. Root/mTLS administrativo y operaciones del sistema pertenecen a servicios protegidos. No exponer un ejecutor genérico de comandos en una vista ni aceptar nombres de unidades arbitrarios.
9. No desactivar CSRF, MFA, verificación TLS o comprobación de huella SSH para resolver una integración. Existe una excepción limitada de perfil X.509 del indexador en `indexer_tls.py`; no equivale a aceptar certificados arbitrarios.
10. No rotar las claves actuales sin un plan de recifrado y recuperación. No ejecutar pruebas de amenazas en índices de clientes.

## Dónde hacer cada cambio

Consultar [mapa de módulos](docs/reference/modules.md), [modelo de datos](docs/domain-model.md) y [guía de contribución](CONTRIBUTING.md). Los modelos se reparten en varios archivos importados por `core/models.py`; las migraciones permanecen en `core/migrations/`.

## Verificación habitual

En un entorno de desarrollo aislado:

```sh
SOC_PORTAL_DEBUG=1 SOC_PORTAL_MFA_REQUIRED=0 python manage.py test
SOC_PORTAL_DEBUG=1 python manage.py makemigrations --check --dry-run
python docs/tools/generate_reference.py --check
```

El ajuste MFA es solo del proceso de pruebas; no guardarlo en configuración pública. Para cambios pequeños, elegir primero pruebas dirigidas relevantes; ejecutar la batería completa cuando el alcance o la entrega lo requiera. Los ensayos SQLite de archivo y nativos tienen requisitos propios: [pruebas](docs/testing.md). Actualizar las referencias generadas cuando cambien rutas, modelos o configuración.

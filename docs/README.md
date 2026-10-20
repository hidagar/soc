# Documentación del proyecto

Guía técnica del código incluido en este repositorio. Estado de referencia: **20 de octubre de 2026**. Los datos de instalación y verificaciones de esa fecha no son una comprobación permanente del servicio.

## Empieza aquí

| Perfil | Lectura recomendada |
|---|---|
| IA o nuevo desarrollador | [AGENTS.md](../AGENTS.md) → [traspaso](handoff.md) → [arquitectura](architecture.md) → [desarrollo](development.md) |
| Backend | [modelo de datos](domain-model.md), [ingesta](ingestion.md), [seguridad](security.md), [pruebas](testing.md) |
| Integraciones | [conectores](integrations.md), [configuración](configuration.md), [operación](operations.md) |
| Frontend e informes | [interfaz y marca](frontend.md), [informes y correo](reports-and-mail.md) |
| Operación / NOC | [operación](operations.md), [diagnóstico](troubleshooting.md), [despliegue](deployment.md), [recuperación](recovery.md) |
| Planificación | [estado y pendientes](handoff.md), [hoja de ruta](roadmap.md), [decisiones](decisions.md) |

## Referencias del código

- [Módulos y símbolos](reference/modules.md).
- [Modelos y campos](reference/models.md).
- [Rutas y handlers](reference/routes.md): inventario, no contrato REST ni declaración de permisos.
- [Variables de entorno](reference/environment.md).
- [Comandos y trabajos](reference/jobs.md).
- [Migraciones y pruebas](reference/verification.md).

Estas referencias se generan por análisis estático con `python docs/tools/generate_reference.py`. Se comprueban con `--check`; no conectan a fabricantes ni a una base de datos.

`python docs/tools/check_docs.py` comprueba además enlaces locales y caracteres de control. No verifica URLs externas, anclas ni renderizado visual. Al cambiar el código, regenerar referencias y revisar la guía narrativa del dominio afectado.

## Alcance y fuentes de verdad

El código describe la implementación; las migraciones describen la evolución del esquema; las pruebas acreditan solo sus escenarios; el traspaso registra la evidencia histórica de despliegue. Configuración viva, credenciales, bases y políticas reales de clientes están fuera de Git. El instalador no reconstruye por sí solo toda la infraestructura ni demuestra una restauración completa.

La [nota de entrega 3B](entrega-wazuh-https.md) conserva evidencias de esa entrega. Los procedimientos de este índice deben usarse para continuar el trabajo; las cifras antiguas no son métricas en tiempo real.

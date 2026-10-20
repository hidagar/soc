# Contribuir al Centro SOC

## Antes de modificar

1. Leer [AGENTS.md](AGENTS.md) y el [traspaso](docs/handoff.md).
2. Comprobar `git status`, rama y remoto; obtener los cambios remotos. Crear la rama a partir de la versión que realmente contiene el proyecto.
3. Reproducir el problema con datos anonimizados en desarrollo. Identificar el ámbito: permisos, eventos, conectores, comunicaciones, operación o interfaz.
4. Describir el criterio de aceptación y los efectos sobre datos existentes. No incorporar una funcionalidad futura como si estuviera desplegada.

## Durante el cambio

- Seguir la estructura existente; no sustituir el framework ni añadir infraestructura sin una necesidad de la tarea.
- Cambios de esquema: modificar modelos, generar una migración nueva, revisar defaults/constraints e investigar su efecto sobre registros históricos. No editar migraciones ya aplicadas.
- Nuevos parsers: añadir muestra anonimizada, probar acciones, severidad, familia, propiedad y coherencia entre evidencia/informe/mapa/aviso.
- Nuevas vistas/JSON/descargas: comprobar usuario sin permiso, cliente ajeno, rol de consulta, MFA y objetos relacionados de otro cliente. Un enlace oculto no constituye autorización.
- Nuevos procesos: timeout, límite de respuesta, reintento, idempotencia, checkpoint durable, estado visible y datos sensibles redactados.
- Frontend: conservar navegación, marca, accesibilidad y comportamiento de movimiento reducido. No introducir datos técnicos en un flujo de cliente sin necesidad.

## Antes del commit

Ejecutar las pruebas relevantes de [testing.md](docs/testing.md); comprobar migraciones y `git diff --check`. Regenerar las referencias si procede. Revisar `git diff --cached` y la lista de archivos para excluir datos y secretos. El verificador de documentación no sustituye una revisión de seguridad.

## Entrega

Subir la rama sin `--force`. La descripción debe incluir motivo, cambios, pruebas con resultados reales, migraciones, reversión y límites. El repositorio aún no tiene CI/CD completo; no afirmar que una comprobación fue automática si se ejecutó manualmente. Publicar código no implica desplegarlo. Mantener [handoff.md](docs/handoff.md) y la hoja de ruta al cerrar una entrega.

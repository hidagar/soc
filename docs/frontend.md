# Interfaz, mapa y marca

Templates Django, CSS y JavaScript de navegador; no SPA ni compilación Node. `templates/base.html` organiza navegación y recursos. `customer_report_base.html` y templates públicos separan la superficie de cliente. Escapar datos de fabricante/usuario; usar `json_script` para datos embebidos.

## Entradas

| Área | Archivos |
|---|---|
| Gestión | `templates/dashboard.html`, listas/detalles/formularios, `static/css/portal.css` |
| Asistente | `core/onboarding.py`, `templates/onboarding.html`, parciales `onboarding_*` y `static/js/onboarding.js` |
| Seguridad/cuentas | `login.html`, `security_mfa.html`, `activate_account.html` |
| Mapa | `core/threat_map.py`, `core/asn.py`, `threat_map.html`, `static/js/threat-map.js`, `static/css/threat-map.css` |
| Comunicaciones | `report_email.*`, `welcome_email.*`, `urgent_email.*`, `core/report_pdf.py` |

Localizar el nombre real con [rutas](reference/routes.md) y `render()`; no generar una pantalla paralela por suponer otra arquitectura.

## Marca

Logos en `static/brand/`: empresas color, blanco y adaptación dashboard. Texto `ib-red` en minúsculas. Paleta: `#00A82D`, `#0B612D`, fondos `#D7EAD9`, `#ECF4E8`, `#FCFBE9`, gris `#C6C6C6`. La lámina original tenía una muestra oscura con etiqueta contradictoria; conservar el diseño implementado y no inventar otro color desde esa etiqueta.

Mantener contraste, foco, etiquetas y mensajes claros. Verde de marca no convierte una alerta permitida en estado correcto. Correo requiere HTML compatible y texto; cambios de layout PDF requieren verificación visual.

## Mapa NOC

SVG con `static/maps/world.json` y datos agregados del backend: presentación/pantalla completa, actualización/fallback, indicador de atraso y `prefers-reduced-motion`. Distingue dirección y blocked/allowed/unknown. Las animaciones no inventan eventos: identidad/antigüedad salen del payload.

El acceso de cliente es opcional y acotado; no reutilizar un JSON global en `/cliente/mapa/data/`. Geografía/ASN describen infraestructura aproximada, no autoría personal. Conservar atribución/licencias de las fuentes.

Mejoras del 13/11/2026 (`static/js/threat-map.js`, sin dependencias externas):
- **Líneas de ataque:** un arco de cada país a la zona de las sedes (`SOC_PORTAL_MAP_HOME`), o al revés si predominan las conexiones salientes. El grosor indica el volumen y la línea se anima si hubo actividad en los últimos 15 minutos. Son ilustrativas, y la leyenda lo dice.
- **Color por volumen:** cada país se colorea en escala logarítmica según sus detecciones.
- **Proporción de permitidas:** un arco naranja en el marcador de cada país.
- **Zoom:** botones «+», «−», «Europa» y «Mundo», doble clic, y Ctrl + rueda (la rueda sola solo en pantalla completa o presentación, para no secuestrar el desplazamiento de la página). Con zoom se arrastra para moverse.
- **Disposición:** el mapa recorta la Antártida; «Evolución» y «Motores» pasan debajo del mapa y la lista de países muestra 12.

El portal del cliente usa la misma página con sus datos agregados; las líneas no añaden ningún dato nuevo (país, volumen y acción ya se mostraban).

## Reglas de experiencia de usuario

Revisión del 16/11/2026 sobre las 204 páginas (SOC y portal del cliente, a 1366 y 390 px), con un recorrido automático en Chromium que medía desbordes horizontales, campos sin nombre accesible, contraste, texto diminuto y controles táctiles pequeños. Resultado: desbordes 1 → 0; campos sin nombre 17 → 0; combinaciones de color con contraste insuficiente 49 → 1 (un botón del mapa, en el límite de 4,5:1); controles táctiles pequeños: de 31 tipos a solo las casillas de la tabla de servicios (22 px), ampliadas después a 24 px sin repetir la medición. El recorrido fue una herramienta temporal y no está en el repositorio; `core/test_ux.py` conserva las reglas comprobables sin navegador.

Reglas que deben mantenerse al añadir páginas:

- **Contraste:** el texto secundario usa los grises oscurecidos de `ui.css` (mínimo 4,5:1 sobre blanco). No introducir grises más claros para texto.
- **Mensajes:** `class="message {{ message.tags }}"`. Error, aviso e información tienen color e icono distintos; nunca mostrar un error con el aspecto de una confirmación.
- **Teclado:** foco visible (`:focus-visible`) y enlace «Saltar al contenido» hacia `<main id="contenido">` en las dos bases (`base.html` y `customer_report_base.html`).
- **Campos:** todo campo tiene `<label>` o `aria-label`, también los de tablas y filtros.
- **Móvil:** botones y campos de 42 px de alto como mínimo, casillas de 24 px; toda tabla ancha dentro de `.table-wrap` o con la clase `stacked`.
- **Formularios:** `static/js/forms.js` marca el botón como ocupado al enviar para evitar el doble envío; se libera a los 8 s y al volver atrás. No sustituye la idempotencia del servidor.
- Al cambiar CSS o JS, actualizar el sufijo `?v=` en las plantillas.

Límites: no se ha probado con un lector de pantalla real ni con usuarios; el JavaScript no tiene pruebas unitarias; los textos de 10,5 px del mapa son intencionados (vista de presentación).

## Portal del cliente: de un vistazo (23/11/2026)

El portal lo usan personas sin perfil técnico. Reglas al añadir o cambiar páginas del portal:
- **El inicio responde primero a dos preguntas:** ¿está todo bien? y ¿tengo que hacer algo?
  - El bloque «Estado de vuestra seguridad» (`service_development.portal_attention`) dice «Todo en orden» o lista cada cosa pendiente con su enlace: actuaciones, cambios propuestos, solicitudes que esperan respuesta, malware sin eliminar, antivirus sin protección, vulnerabilidades e índice bajo.
  - Algo nuevo que pida acción al cliente se añade ahí, no como una tarjeta suelta.
  - Solo con datos que el portal ya publica (invariante 3).
- **Cifras con frase:** las cifras se acompañan de una frase en lenguaje llano («vuestros firewalls registraron 50 intentos y bloquearon 35»). Un indicador a cero que no aporta («sin saber si se bloquearon») no se muestra.
- **Ayuda:** «Ayuda» (`/cliente/ayuda/`) explica qué hace el SOC, qué hay en cada página y un glosario. Un término nuevo de cara al cliente se añade al glosario.
- **Móvil:**
  - el menú del portal es una línea que se desliza y se centra en la página actual;
  - toda tabla dentro de `.table-wrap` se convierte en tarjetas en pantallas estrechas (`static/js/forms.js`, con el nombre de cada columna);
  - una tabla que deba seguir como tabla lleva `data-table-keep` en su contenedor.
- **Celdas vacías:** solo se ocultan en el móvil; en escritorio descolocaban las columnas de las tablas apiladas.

## Revisión visual

Login/MFA, lista/detalle, wizard, mapa normal/presentación/sin datos/atrasado, móvil, impresión/PDF y correo según alcance. Documentar qué se comprobó realmente; esta documentación no acredita una nueva revisión visual completa.

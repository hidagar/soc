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

## Revisión visual

Login/MFA, lista/detalle, wizard, mapa normal/presentación/sin datos/atrasado, móvil, impresión/PDF y correo según alcance. Documentar qué se comprobó realmente; esta documentación no acredita una nueva revisión visual completa.

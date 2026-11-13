"""Menú lateral del portal agrupado por áreas de trabajo.

Cada entrada declara qué rutas la marcan como activa (incluidas las fichas de
detalle) y qué permiso la muestra. Solo controla visibilidad del menú: cada
vista sigue autorizando por su cuenta.
"""
from django.urls import reverse


# Pestañas de «Inteligencia y bloqueo»: (ruta, etiqueta, permiso o '', rutas de detalle que la marcan activa).
INTEL_TABS = [
    ("crowdsec_overview", "Reputación CrowdSec", "", ()),
    ("crowdsec_lists", "Listas de CrowdSec", "core.manage_operations", ("crowdsec_list_action",)),
    ("blocklists", "Listas de bloqueo", "core.manage_operations", ("blocklist_detail",)),
    ("threat_intel", "Q-Feeds", "core.manage_operations", ()),
    ("soc_reputation", "Reputación propia", "core.manage_operations", ()),
]


def intel_tabs(request):
    """Pestañas visibles para el usuario si la página actual es una de ellas; si no, lista vacía."""
    match = getattr(request, "resolver_match", None)
    current = match.url_name if match else ""
    if not any(current == name or current in extra for name, _, _, extra in INTEL_TABS):
        return []
    return [{"label": label, "href": reverse(name), "current": current == name or current in extra}
            for name, label, permission, extra in INTEL_TABS if not permission or request.user.has_perm(permission)]


def _item(label, url_name, active=(), *, href=None, external=False, visible=True):
    return {"label": label, "url_name": url_name, "href": href, "external": external,
            "active": {url_name, *active}, "visible": visible}


def _staff_groups(user, global_access):
    perm = user.has_perm
    access = getattr(user, "soc_access", None)
    wazuh_general = user.is_superuser or bool(getattr(access, "all_clients", False))
    return [
        ("inicio", "", [
            _item("Resumen", "dashboard", ["dashboard_legacy"]),
            _item("Bandeja de trabajo", "work_queue", ["claim_incident"]),
        ]),
        ("respuesta", "Respuesta", [
            _item("Incidencias", "incident_list", ["incident_new", "incident_detail", "incident_edit",
                  "incident_note", "runbook", "customer_task_new", "customer_task_edit"]),
            _item("Solicitudes de clientes", "requests", ["request_detail"]),
            _item("Avisos urgentes", "urgent_alert_list", ["acknowledge_alert"]),
            _item("Acciones y seguimiento", "action_list", ["action_new", "action_edit"]),
            _item("Entrega y atención", "delivery_status", ["delivery_settings"]),
        ]),
        ("deteccion", "Detección e investigación", [
            _item("Detecciones prioritarias", "intelligence"),
            _item("Investigar IP y eventos", "security_explore", ["ip_investigation"]),
            _item("Ataques a varios clientes", "campaign_list"),
            _item("Mapa de detecciones", "threat_map"),
            # Cinco páginas en una entrada: se cambia entre ellas con las pestañas de `intel_tabs`.
            _item("Inteligencia y bloqueo", "crowdsec_overview", [name for name, _, _, extra in INTEL_TABS for name in (name, *extra)]),
            _item("Seguridad VPN", "vpn_security"),
            _item("SOC general en Wazuh", "wazuh_sso_enter", external=True, visible=wazuh_general),
        ]),
        ("cobertura", "Cobertura y salud", [
            _item("Salud del SOC", "health_list", ["health_device"]),
            _item("Estado de protección", "protection_list", ["protection_device"]),
            _item("Cobertura por red", "network_coverage", ["device_coverage", "network_requirements",
                  "advanced_coverage"]),
            _item("Vulnerabilidades", "vulnerabilities"),
            _item("Políticas propuestas", "policies"),
            _item("Control de exposición", "exposure_list", ["exposure_detail", "exposure_interfaces",
                  "exposure_recheck", "unifi_policies"]),
        ]),
        ("clientes", "Clientes e infraestructura", [
            _item("Clientes y sedes", "client_list", ["client_new", "client_detail", "client_edit",
                  "client_trends", "client_timeline", "weekly_report", "monthly_summary", "customer_publish",
                  "manage_report_link", "site_new", "site_detail", "site_edit", "site_delete",
                  "device_new", "device_detail", "device_edit", "device_history", "device_onboarding",
                  "onboarding_add_device", "onboarding_status", "export_destination", "unifi_cloud",
                  "opnsense_api", "hillstone_api", "gdms_cloud", "ssh_connection", "secure_log_setup",
                  "validations", "configuration_archives"]),
            _item("Inventario", "inventory", ["asset_edit", "refresh_device_inventory"]),
            _item("Conexiones", "api_connections"),
            _item("VPN de sedes", "vpn_sites", ["vpn_download"], visible=perm("core.manage_connections")),
            _item("Plantillas y cambios", "changes", ["change_detail"], visible=perm("core.manage_operations")),
        ]),
        ("ayuda", "Ayuda", [
            _item("Guía de conexión", "connection_guide"),
            _item("Guía de operación", "operations_help"),
        ]),
        ("admin", "Administración", [
            _item("Usuarios y permisos", "staff", ["staff_edit", "mfa_reset"],
                  visible=global_access and perm("core.manage_security")),
            _item("Auditoría", "audit_log", visible=global_access and perm("core.manage_security")),
            _item("Plazos de atención", "sla_settings", visible=global_access and perm("core.manage_operations")),
            _item("Correo del SOC", "mail_settings", ["verify_public_reports"],
                  visible=global_access and perm("core.manage_connections")),
            _item("Copias y recuperación", "recovery", visible=global_access and perm("core.manage_recovery")),
            _item("Administración técnica", "", href="/admin/", visible=user.is_superuser),
        ]),
    ]


def badges():
    """Trabajo pendiente por entrada del menú: {url_name: (número, urgente)}. Con el ámbito del usuario.

    Son pocas consultas de recuento por página; si algo falla, el menú se muestra sin contadores.
    """
    from .models import CustomerRequest, DeviceExposure, PolicyProposal
    requests = CustomerRequest.objects.filter(status__in=("new", "in_progress"))
    exposures = DeviceExposure.objects.filter(resolved_at__isnull=True, dismissed_at__isnull=True, advisory__isnull=True,
                                              device__active=True)
    policies = PolicyProposal.objects.filter(status__in=("proposed", "approved", "not_effective"))
    return {
        "requests": (requests.count(), requests.filter(urgent=True).exists()),
        "vulnerabilities": (exposures.values("device").distinct().count(), exposures.filter(record__kev_added__isnull=False).exists()),
        "policies": (policies.count(), policies.filter(status="approved").exists()),
    }


def _customer_groups():
    return [("inicio", "", [
        _item("Mi empresa", "customer_home", ["customer_weekly", "customer_map", "customer_task_reply"]),
        _item("Dashboard de seguridad", "wazuh_sso_enter", external=True),
    ])]


def build_navigation(request, global_access):
    user = request.user
    match = getattr(request, "resolver_match", None)
    current = match.url_name if match else ""
    access = getattr(user, "soc_access", None)
    is_customer = getattr(access, "role", "") == "customer"
    counts = {}
    if not is_customer:
        try:
            counts = badges()
        except Exception:  # el menú no puede romper una página
            import logging
            logging.getLogger(__name__).exception("No se pudieron calcular los contadores del menú")
    groups = []
    for key, title, items in (_customer_groups() if is_customer else _staff_groups(user, global_access)):
        entries = []
        for item in items:
            if not item["visible"]:
                continue
            count, urgent = counts.get(item["url_name"], (0, False))
            entries.append({"label": item["label"], "href": item["href"] or reverse(item["url_name"]),
                            "external": item["external"], "current": bool(current) and current in item["active"],
                            "count": count, "urgent": urgent})
        if entries:
            groups.append({"key": key, "title": title, "items": entries,
                           "current": any(entry["current"] for entry in entries),
                           "count": sum(entry["count"] for entry in entries),
                           "urgent": any(entry["urgent"] for entry in entries)})
    return groups

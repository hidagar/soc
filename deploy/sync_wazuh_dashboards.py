"""Create and maintain internal SOC dashboards in Wazuh.

The portal remains the source of truth for client/source-IP ownership. This
script only manages saved objects with the ``soc-`` ID prefix. It never grants
customer access to Wazuh.
"""

import base64
import ipaddress
import json
import re
import sqlite3
import ssl
import tarfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


DATABASE = Path("/srv/soc-portal/data/portal.sqlite3")
ARCHIVE = Path("/home/deploy/soc-setup/wazuh-install-files.tar")
BASE = "https://127.0.0.1"
INDEX_PATTERN = "wazuh-alerts-*"


def credentials():
    with tarfile.open(ARCHIVE) as archive:
        member = archive.extractfile("wazuh-install-files/wazuh-passwords.txt")
        if member is None:
            raise RuntimeError("No se encontró el archivo de contraseñas Wazuh.")
        source = member.read().decode()
    match = re.search(r"indexer_username: 'admin'\s+indexer_password: '([^']+)'", source)
    if not match:
        raise RuntimeError("No se encontró la credencial admin de Wazuh.")
    return base64.b64encode(("admin:" + match.group(1)).encode()).decode()


def request(path, auth, method="GET", body=None, *, tenant=None):
    headers = {"Authorization": "Basic " + auth, "osd-xsrf": "true"}
    headers['securitytenant']='global'
    if tenant is not None:
        if not re.fullmatch(r'soc_customer_[1-9][0-9]*',tenant):raise ValueError('Invalid tenant')
        headers['securitytenant']=tenant
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(
        BASE + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers=headers,
        method=method,
    )
    try:
        context=ssl.create_default_context(cafile='/etc/wazuh-dashboard/certs/root-ca.pem')
        # Wazuh installer's legacy CA has no keyUsage; keep chain/time/hostname checks.
        context.verify_flags &= ~ssl.VERIFY_X509_STRICT
        with urllib.request.urlopen(req, context=context, timeout=20) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return 404, None
        detail = exc.read().decode(errors="replace")[:800]
        raise RuntimeError(f"Wazuh rechazó {method} {path}: HTTP {exc.code}: {detail}") from exc


def portal_database_engine(env_file=Path("/etc/soc-portal/portal.env")):
    # Se ejecuta sin Django ni EnvironmentFile: leer solo el motor del entorno protegido.
    try:
        lines = env_file.read_text(encoding="utf-8").splitlines()
    except OSError:
        return "sqlite"
    values = [line.split("=", 1)[1].strip() for line in lines if line.startswith("SOC_PORTAL_DB_ENGINE=")]
    return values[-1] if values else "sqlite"


def clients_and_sources():
    if portal_database_engine() != "sqlite":
        # Leer el SQLite abandonado publicaría clientes y fuentes obsoletos.
        raise RuntimeError("El portal no usa SQLite: esta sincronización aún no admite PostgreSQL.")
    db = sqlite3.connect(f"file:{DATABASE}?mode=ro", uri=True)
    try:
        clients = [dict(code=code, name=name, sources=set()) for code, name in db.execute(
            "SELECT code, name FROM core_client WHERE active=1 ORDER BY name"
        )]
        by_code = {client["code"]: client for client in clients}
        owners = {}
        for code, source in db.execute("""
            SELECT c.code, e.source_ip FROM core_exportconfiguration e
            JOIN core_device d ON d.id=e.device_id
            JOIN core_site s ON s.id=d.site_id
            JOIN core_client c ON c.id=s.client_id
            WHERE c.active=1 AND s.active=1 AND d.active=1
              AND e.source_ip IS NOT NULL AND e.receiver_ready=1
        """):
            source = str(ipaddress.ip_address(source))
            if source in owners and owners[source] != code:
                raise RuntimeError(f"Origen {source} asignado a dos clientes; no se crean paneles ambiguos.")
            owners[source] = code
            by_code[code]["sources"].add(source)
        return clients
    finally:
        db.close()


def query(sources):
    # Source addresses are normalized through ipaddress; the no-source token
    # deliberately cannot occur in a real syslog location.
    if not sources:
        return 'location: "__soc_sin_origen__" and rule.level >= 8'
    clauses = " or ".join(f'location: "{ip}"' for ip in sorted(sources))
    return f"({clauses}) and rule.level >= 8"


def search_source(filter_query, with_index=True):
    source = {"query": {"query": filter_query, "language": "kuery"}, "filter": []}
    if with_index:
        source["indexRefName"] = "kibanaSavedObjectMeta.searchSourceJSON.index"
        source["highlightAll"] = True
        source["version"] = True
    return json.dumps(source, ensure_ascii=False, separators=(",", ":"))


def index_reference():
    return [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": INDEX_PATTERN}]


def search_object(title, filter_query):
    return {
        "attributes": {
            "title": title,
            "description": "Alertas de prioridad 8 o superior de los equipos gestionados.",
            "hits": 0,
            "columns": ["timestamp", "rule.level", "rule.description", "predecoder.hostname", "data.unifi.ips_signature", "data.unifi.action", "location"],
            "sort": [["timestamp", "desc"]],
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": search_source(filter_query)},
        },
        "references": index_reference(),
    }


def metric_object(title, filter_query):
    state = {
        "title": title,
        "type": "metric",
        "params": {
            "addTooltip": True,
            "addLegend": False,
            "type": "metric",
            "metric": {
                "percentageMode": False,
                "useRanges": False,
                "colorSchema": "Green to Red",
                "metricColorMode": "None",
                "colorsRange": [{"from": 0, "to": 10000}],
                "labels": {"show": False},
                "invertColors": False,
                "style": {"bgFill": "#000", "bgColor": False, "labelColor": False, "subText": "", "fontSize": 36},
            },
        },
        "aggs": [{"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {"customLabel": "Alertas"}}],
    }
    return {
        "attributes": {
            "title": title,
            "description": "Alertas de prioridad 8 o superior en los últimos siete días.",
            "visState": json.dumps(state, ensure_ascii=False, separators=(",", ":")),
            "uiStateJSON": "{}",
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": search_source(filter_query)},
        },
        "references": index_reference(),
    }


def dashboard_object(title, description, filter_query, metric_id, search_id, extra_metrics=()):
    panels = []
    references = []
    for position, current_metric in enumerate([metric_id, *extra_metrics]):
        panel_index = str(position + 1)
        panels.append({
            "panelIndex": panel_index,
            "gridData": {"x": (position % 3) * 16, "y": (position // 3) * 12, "w": 16, "h": 12, "i": panel_index},
            "embeddableConfig": {},
            "panelRefName": f"panel_{position}",
            "version": "7.10.0",
        })
        references.append({"name": f"panel_{position}", "type": "visualization", "id": current_metric})
    search_position = len(panels)
    search_index = str(search_position + 1)
    panels.append({
        "panelIndex": search_index,
        "gridData": {"x": 0, "y": ((search_position + 2) // 3) * 12, "w": 48, "h": 25, "i": search_index},
        "embeddableConfig": {},
        "panelRefName": f"panel_{search_position}",
        "version": "7.10.0",
    })
    references.append({"name": f"panel_{search_position}", "type": "search", "id": search_id})
    return {
        "attributes": {
            "title": title,
            "description": description,
            "hits": 0,
            "panelsJSON": json.dumps(panels, separators=(",", ":")),
            "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}),
            "version": 1,
            "timeRestore": True,
            "timeFrom": "now-7d",
            "timeTo": "now",
            "kibanaSavedObjectMeta": {"searchSourceJSON": search_source(filter_query, with_index=False)},
        },
        "references": references,
    }


def upsert(auth, kind, object_id, body, managed_fields):
    path = f"/api/saved_objects/{kind}/{urllib.parse.quote(object_id, safe='')}"
    status, current = request(path, auth)
    if status == 404:
        request(path + "?overwrite=false", auth, "POST", body)
        return "created"
    if status != 200:
        raise RuntimeError(f"No se pudo leer {kind}/{object_id}.")
    attrs = current.get("attributes", {})
    desired = body["attributes"]
    changes = {field: desired[field] for field in managed_fields if attrs.get(field) != desired[field]}
    refs_changed = current.get("references", []) != body["references"]
    if changes or refs_changed:
        update = {"attributes": changes}
        if refs_changed:
            update["references"] = body["references"]
        request(path, auth, "PUT", update)
        return "updated"
    return "unchanged"


def sync_scope(auth, slug, title, sources, description, extra_metrics=()):
    filter_query = query(sources)
    search_id = f"soc-alerts-{slug}"
    metric_id = f"soc-count-{slug}"
    dashboard_id = f"soc-{slug}"
    search_body = search_object(f"SOC · {title} · Eventos", filter_query)
    metric_body = metric_object(f"SOC · {title} · Alertas", filter_query)
    dashboard_body = dashboard_object(f"SOC · {title}", description, filter_query, metric_id, search_id, extra_metrics)
    objects = (
        ("search", search_id, search_body, ["title", "kibanaSavedObjectMeta"]),
        ("visualization", metric_id, metric_body, ["title", "kibanaSavedObjectMeta"]),
        ("dashboard", dashboard_id, dashboard_body, ["title", "description", "kibanaSavedObjectMeta", "panelsJSON"] if extra_metrics else ["title", "description", "kibanaSavedObjectMeta"]),
    )
    for kind, object_id, body, fields in objects:
        result = upsert(auth, kind, object_id, body, fields)
        print(f"{kind}/{object_id}: {result}")


def main():
    import sys
    from soc_dashboard_design import sync
    return sync(sys.modules[__name__])


def legacy_main():
    clients = clients_and_sources()
    auth = credentials()
    status, _ = request(f"/api/saved_objects/index-pattern/{urllib.parse.quote(INDEX_PATTERN, safe='')}", auth)
    if status != 200:
        raise RuntimeError("Falta el patrón de índices wazuh-alerts-*.")
    for client in clients:
        description = (
            f"Alertas SIEM de {client['name']} · {len(client['sources'])} origen(es). UniFi Traffic Flows puede mostrar sesiones adicionales."
            if client["sources"] else f"{client['name']}: pendiente de recibir eventos de equipos."
        )
        sync_scope(auth, f"client-{client['code']}", client["name"], client["sources"], description)
    all_sources = set().union(*(client["sources"] for client in clients)) if clients else set()
    client_metrics = [f"soc-count-client-{client['code']}" for client in clients]
    sync_scope(auth, "general", "General", all_sources, "Alertas SIEM recibidas de los clientes conectados. UniFi Traffic Flows puede mostrar sesiones adicionales.", client_metrics)


if __name__ == "__main__":
    main()

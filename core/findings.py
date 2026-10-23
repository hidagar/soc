"""Turn indexed firewall alerts into evidence-backed customer findings."""

from collections import defaultdict
from datetime import datetime
import ipaddress

from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from .models import Device, ExportConfiguration
from .unifi_cloud import UnifiCloudError, connector_json, decrypt_api_key


def _clean_ip(value):
    try:
        return str(ipaddress.ip_address(value))
    except (ValueError, TypeError):
        return ""


def _contains_port(specification, port):
    if not port or not specification:
        return False
    try:
        number = int(port)
        for part in str(specification).split(","):
            bounds = part.strip().split("-")
            if len(bounds) == 1 and int(bounds[0]) == number:
                return True
            if len(bounds) == 2 and int(bounds[0]) <= number <= int(bounds[1]):
                return True
    except ValueError:
        return False
    return False


def _unifi_inventory(device):
    try:
        connection = device.unifi_cloud
        if not connection.last_ok or not connection.remote_host_id:
            return {}, []
        key = decrypt_api_key(connection.encrypted_api_key)
        host_rows = []
        for path in ("/network/api/s/default/rest/user", "/network/api/s/default/stat/sta"):
            result = connector_json(key, connection.remote_host_id, path)
            if isinstance(result.get("data"), list):
                host_rows.extend(result["data"])
        result = connector_json(key, connection.remote_host_id, "/network/api/s/default/rest/portforward")
        forwards = result.get("data", []) if isinstance(result.get("data"), list) else []
    except (UnifiCloudError, ObjectDoesNotExist):
        return {}, []
    hosts = {}
    for row in host_rows:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name") or row.get("hostname") or "").strip()[:120]
        if not name:
            continue
        for key in ("fixed_ip", "ip"):
            ip = _clean_ip(row.get(key))
            if ip:
                hosts[ip] = name
    return hosts, [row for row in forwards if isinstance(row, dict) and row.get("enabled") is not False]


def inventories_for_sources(client, sources, events=None):
    configs = ExportConfiguration.objects.filter(
        device__site__client=client, source_ip__in=sources, device__active=True,
    ).select_related("device__site__client", "device__unifi_cloud", "device__attribution_catalog")
    by_source = defaultdict(list)
    for config in configs:
        by_source[config.source_ip].append(config.device)
    from .secure_logs import active_channels
    for channel in active_channels().filter(client_scope_id=client.pk,source_identity__in=sources).select_related('device__site'):
        if not any(d.pk==channel.device_id for d in by_source[channel.source_identity]):by_source[channel.source_identity].append(channel.device)
    result = {}
    for source, devices in by_source.items():
        if len(devices) != 1:
            continue
        device = devices[0]
        hosts, forwards = _unifi_inventory(device) if device.vendor == Device.Vendor.UNIFI else ({}, [])
        for asset in device.assets.all():
            if asset.name or asset.discovered_name:
                hosts[asset.ip] = asset.label
        identities={};contexts={}
        evidence_rows=device.security_events.filter(client_scope_id=client.pk).exclude(wazuh_id='').order_by('-observed_at')
        if events is not None:
            ids={str(e['id']) for e in events if e.get('id') and e.get('location')==source}
            evidence_rows=evidence_rows.filter(wazuh_id__in=ids) if ids else evidence_rows.none()
        else:evidence_rows=evidence_rows[:10000]
        for evidence in evidence_rows:
            key=(evidence.wazuh_id,evidence.observed_at.isoformat())
            identities[key]=evidence.identity
            contexts[key]=evidence.interpretation
        result[source] = {"device_name": device.name, "site_name": device.site.name,
                          "hosts": hosts, "forwards": forwards,'identities':identities,'contexts':contexts,'device_id':device.pk,'site_id':device.site_id,
                          'client_scope_id':client.pk,'context':getattr(device,'attribution_catalog',None)}
    if events:
        from .models import SecurityEvidence
        ids={str(e.get('id') or '') for e in events if e.get('id')}
        # A moved device's event-time owner/identity must survive its current
        # inventory disappearing from the old client's source list.
        rows=SecurityEvidence.objects.filter(client_scope_id=client.pk,wazuh_id__in=ids,interpretation__source_identity__in=sources)
        observed={}
        for evidence in rows:
            source=evidence.interpretation.get('source_identity')
            key=(source,evidence.wazuh_id,evidence.observed_at.isoformat())
            observed.setdefault(key,[]).append(evidence)
        for (source,event_id,stamp),matches in observed.items():
            if len(matches)!=1:continue
            evidence=matches[0]
            inventory=result.setdefault(source,{'identities':{},'contexts':{},'hosts':{},'forwards':[]})
            inventory['identities'][(event_id,stamp)]=evidence.identity
            inventory['contexts'][(event_id,stamp)]=evidence.interpretation
    return result


def _time(value):
    try:
        parsed = datetime.strptime(str(value), "%Y-%m-%dT%H:%M:%S.%f%z")
        return timezone.localtime(parsed).strftime("%d/%m/%Y %H:%M")
    except ValueError:
        return str(value)[:32]


def _event_type(item):
    from .operations import normalize
    event = normalize(item)
    if event['security']:
        return 'policy' if event['category']=='application_policy' else 'security'
    unifi = item.get("data", {}).get("unifi", {})
    if unifi.get("category") == "Security":
        return "security"
    if unifi.get("event_name") == "Internet Down":
        return "availability"
    return "other"


def _event_description(item):
    from .operations import normalize
    event=normalize(item)
    if event['security']:
        return event['signature']
    unifi = item.get("data", {}).get("unifi", {})
    return str(unifi.get("ips_signature") or item.get("rule", {}).get("description") or unifi.get("event_name") or "Alerta")[:180]


def _action(value):
    raw = str(value or "").lower()
    return {"allowed": "permitida", "blocked": "bloqueada", "unknown":"sin confirmar"}.get(raw, raw or "no informada")[:40]


def _asset(item, inventories):
    source = str(item.get("location") or "")
    inventory = inventories.get(source, {})
    kind = _event_type(item)
    from .operations import normalize
    event=normalize(item)
    ip = event['affected_ip'] or _clean_ip(event['destination_ip'])
    if kind == "availability":
        return {"name": inventory.get("device_name") or "Puerta de enlace", "ip": "",
                "site": inventory.get("site_name") or "", "confirmed": bool(inventory.get("device_name")),
                "forwarded": False, "published_ports": ""}
    hosts = inventory.get("hosts", {})
    name = hosts.get(ip, "")
    try:stamp=parse_datetime(str(item.get('timestamp') or ''))
    except ValueError:stamp=None
    key=(str(item.get('id') or ''),stamp.isoformat() if stamp else '')
    identity=inventory.get('identities',{}).get(key)
    context=inventory.get('contexts',{}).get(key,{})
    if key not in inventory.get('identities',{}) and item.get('id') and stamp and inventory.get('device_id') and inventory.get('client_scope_id'):
        from .models import SecurityEvidence
        matches=list(SecurityEvidence.objects.filter(device_id=inventory['device_id'],client_scope_id=inventory['client_scope_id'],wazuh_id=key[0],observed_at=stamp)[:2])
        if len(matches)==1:
            evidence=matches[0]
            identity=evidence.identity
            context=evidence.interpretation
    confirmed=bool(identity and identity.get('confidence') in ('manual','recent'))
    if identity is not None:name=identity.get('label') if confirmed else ''
    elif name:name+=' (identificación actual; confirmar)'
    port = event['destination_port']
    forward = next((row for row in inventory.get("forwards", [])
                    if _clean_ip(row.get("fwd")) == ip and _contains_port(row.get("fwd_port") or row.get("dst_port"), port)), None)
    from .asset_context import review,describe,flow_projection
    context_note=describe(review(inventory.get('context'),event['source_ip'],event['destination_ip'],event['destination_port'],flow_projection(item))) if kind=='security' and inventory.get('context') and not event['affected_ip'] else ''
    return {"name": name or ("Destino por identificar" if ip else "Destino no informado"),
            "ip": ip, "site": context.get("site_name") or inventory.get("site_name") or "", "confirmed": confirmed,
            "identity_key": (identity or {}).get("mac", "") + "|" + (name or ""),
            "forwarded": bool(forward), "published_ports": str(forward.get("fwd_port") or "")[:80] if forward else "",'context_note':context_note}


def _recommendations(finding):
    name = finding["asset_name"]
    ports = ", ".join(finding["ports"]) or "el servicio afectado"
    if finding["type"] == "availability":
        return ["Comprobar en el gateway el estado de las líneas WAN y el cambio a la conexión de respaldo durante la hora indicada.",
                "Si el corte se repite o afectó al servicio, abrir incidencia con el operador y registrar duración e impacto."]
    if finding["type"] != "security":
        return ["Revisar el registro detallado del equipo y confirmar la causa y el impacto con el responsable de la sede."]
    if finding.get('engine')=='clamav':
        return ['Identificar en el registro ClamAV el archivo analizado y el equipo que originó la transferencia; la alerta puede no incluir su IP.',
            'Comprobar si el proxy/ICAP bloqueó la transferencia. Una detección del antivirus no confirma por sí sola un bloqueo ni una infección del equipo.',
            'Conservar la evidencia y analizar el equipo con antivirus/EDR si procede; documentar el resultado antes de cerrar.']
    if not finding["asset_ip"]:
        return [
            "Abrir la detección en el firewall a la hora indicada y recuperar la IP y el puerto que faltan en el evento exportado.",
            "Identificar el equipo destinatario y revisar sus registros antes de proponer cambios de acceso.",
        ]
    actions = []
    if not finding["asset_confirmed"]:
        actions.append(f"Confirmar qué equipo utiliza la IP {finding['asset_ip']} antes de aplicar cambios.")
    if finding["forwarded"] and finding["action"] == "permitida":
        actions.extend([
            f"Confirmar con el proveedor de {name} si necesita acceso desde Internet a {ports} y desde qué IP públicas se conecta.",
            "Restringir los orígenes de la redirección a los autorizados o estudiar acceso por VPN. Coordinar el cambio para no interrumpir el servicio.",
            f"Revisar los registros de {name} en las horas indicadas y descartar accesos no autorizados; comprobar versión y actualizaciones con el fabricante.",
        ])
    elif finding["action"] == "permitida":
        actions.extend([
            f"Revisar por qué se permitió el tráfico hacia {name} en {ports} y si el servicio debe estar accesible desde esa red.",
            f"Examinar los registros de {name} en las horas indicadas para descartar accesos no autorizados.",
        ])
    elif finding["action"] == "bloqueada":
        actions.append(f"Verificar el bloqueo informado por el motor hacia {name} en {ports} y revisar si los intentos se repiten.")
        if finding["forwarded"]:
            actions.append(f"Confirmar con el proveedor de {name} si la publicación de {ports} sigue siendo necesaria y qué orígenes deben poder acceder.")
            actions.append("Valorar restringir los orígenes autorizados o usar VPN, coordinando el cambio para no interrumpir el servicio.")
    else:
        actions.append(f"Comprobar en el firewall la acción aplicada al tráfico hacia {name} en {ports} y revisar los registros del equipo.")
    return actions


def build_findings(hits, inventories):
    from .operations import normalize, recommendation
    grouped = {}
    notable = []
    for hit in hits:
        item = hit.get("_source", {})
        kind = _event_type(item)
        description = _event_description(item)
        event=normalize(item)
        asset = _asset(item, inventories)
        action = _action(event['action'])
        port = event['destination_port'][:12]
        src_ip = _clean_ip(event['source_ip'])
        date = _time(item.get("timestamp", ""))
        key = (kind, str(item.get("location") or ""), asset["site"], event["engine"], event["category"],
               event["signature"], event["soc_priority"], event["vendor_severity"], asset["ip"] or asset["name"],
               asset.get("identity_key", ""), action, asset["forwarded"],asset.get("context_note",""))
        if key not in grouped:
            grouped[key] = {
                "type": kind, "description": description, "asset_name": asset["name"],
                'engine':event['engine'], 'category':event['category'], 'contract_version':event['contract_version'],
                'soc_priority':event['soc_priority'], 'priority_label':event['priority_label'], 'vendor_severity':event['vendor_severity'], 'wazuh_level':event['level'],
                'specific_action':recommendation(event) if kind=='security' and asset['ip'] else '',
                "asset_ip": asset["ip"], "asset_confirmed": asset["confirmed"],
                "site": asset["site"], "forwarded": asset["forwarded"],
                "published_ports": asset["published_ports"], "action": action,
                'context_note':asset.get('context_note',''),
                "count": 0, "ports": set(), "source_ips": set(), "signatures": set(),
                "first_seen": date, "last_seen": date,
                "_first_ts": str(item.get("timestamp", "")), "_last_ts": str(item.get("timestamp", "")),
            }
        finding = grouped[key]
        finding["count"] += 1
        finding["wazuh_level"] = max(finding["wazuh_level"], event["level"])
        finding["signatures"].add(description)
        if port:
            finding["ports"].add(port)
        if src_ip:
            finding["source_ips"].add(src_ip)
        raw_ts = str(item.get("timestamp", ""))
        if raw_ts < finding["_first_ts"]:
            finding["first_seen"] = date
            finding["_first_ts"] = raw_ts
        if raw_ts > finding["_last_ts"]:
            finding["last_seen"] = date
            finding["_last_ts"] = raw_ts
        if len(notable) < 12:
            notable.append({"timestamp": date, "description": description, "action": action,
                            "risk": event["vendor_severity"] or "no informado", "soc_priority":event["soc_priority"], "wazuh_level":event["level"], "engine":event["engine"], "contract_version":event["contract_version"],
                            "asset": asset["name"], "destination": asset["ip"],
                            "port": port, "type": kind})
    findings = []
    for finding in grouped.values():
        finding.pop("_first_ts")
        finding.pop("_last_ts")
        finding["ports"] = sorted(finding["ports"], key=lambda value: int(value) if value.isdigit() else 0)
        finding["source_count"] = len(finding["source_ips"])
        finding["source_ips"] = sorted(finding["source_ips"])[:5]
        finding["signature_count"] = len(finding["signatures"])
        finding["signatures"] = sorted(finding["signatures"])[:5]
        finding["priority"] = "alta" if finding["type"] == "security" and finding["soc_priority"] in ("high","critical") else "media"
        finding["recommendations"] = _recommendations(finding)
        if finding.get('specific_action'):
            finding['recommendations'].insert(0,finding['specific_action'])
        if finding.get('context_note'):
            finding['recommendations'].insert(0,finding['context_note'])
        findings.append(finding)
    findings.sort(key=lambda row: (row["priority"] != "alta", -row["count"], row["asset_name"]))
    return findings[:30], notable

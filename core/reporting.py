"""Weekly customer reporting from indexed Wazuh alerts.

UniFi Activity Logging is incomplete relative to Insights > Flows. These
counts intentionally describe alerts received by Wazuh, not all UDM threats.
"""

import base64
from datetime import datetime, time, timedelta
import ipaddress
import json
import ssl
import urllib.request
import os
from pathlib import Path
from django.db.models import Q

from django.template.loader import render_to_string
from django.utils import timezone

from .findings import build_findings, inventories_for_sources
from .mail_delivery import MailConfigurationError, send_report_email
from .models import Client, Device, ExportConfiguration, WeeklyReport


INDEXER_URL = "https://127.0.0.1:9200/wazuh-alerts-*/_search"
def indexer_authorization():
    credentials=json.loads(Path(os.environ.get('SOC_INDEXER_READER_FILE','/etc/soc-portal/indexer-reader.json')).read_text())
    return 'Basic '+base64.b64encode((credentials['username']+':'+credentials['password']).encode()).decode()


def _search(body, authorization):
    req = urllib.request.Request(INDEXER_URL, json.dumps(body).encode(), {
        "Authorization": authorization, "Content-Type": "application/json",
    })
    from .indexer_tls import context as tls_context
    context=tls_context(cafile=os.environ.get('SOC_INDEXER_CA','/etc/wazuh-indexer/certs/root-ca.pem'))
    with urllib.request.urlopen(req, context=context, timeout=20) as response:
        return json.load(response)


def report_sources(client):
    rows = ExportConfiguration.objects.filter(
        device__site__client=client, device__site__active=True, device__active=True,
        receiver_ready=True, source_ip__isnull=False,
    ).values_list("source_ip", flat=True)
    from .secure_logs import active_channels
    return sorted({str(ipaddress.ip_address(ip)) for ip in rows}|set(active_channels().filter(receiver_ready=True,client_scope_id=client.pk).values_list('source_identity',flat=True)))


def _source_owner_check(clients):
    owners = {}
    for client in clients:
        for source in report_sources(client):
            previous = owners.setdefault(source, client.pk)
            if previous != client.pk:
                raise RuntimeError(f"La IP de origen {source} corresponde a más de un cliente.")


def _range_filter(week_start):
    start = timezone.make_aware(datetime.combine(week_start, time.min))
    end = start + timedelta(days=7)
    return {"range": {"timestamp": {"gte": start.isoformat(), "lt": end.isoformat()}}}

def security_filter():
    from .event_contract import security_filter as indexed_security
    return indexed_security()

def action_filter(action):
    from .event_contract import action_filter as indexed_action
    return indexed_action(action)

def coverage_for_week(client,week_start):
    from .models import FeedBucket,SecurityEvidence,OperationalIssue
    start=timezone.make_aware(datetime.combine(week_start,time.min))
    end=start+timedelta(days=7)
    devices=[]
    for d in Device.objects.filter(site__client=client,active=True,site__active=True):
        buckets=FeedBucket.objects.filter(device=d,hour__gte=start,hour__lt=end)
        feeds=list(buckets.values_list('kind',flat=True).distinct())
        threats=list(SecurityEvidence.objects.filter(device=d,observed_at__gte=start,observed_at__lt=end).exclude(category='application_policy').values_list('engine',flat=True).distinct())
        issues=list(OperationalIssue.objects.filter(device=d,opened_at__lt=end).filter(Q(resolved_at__gte=start)|Q(resolved_at__isnull=True)).values_list('title',flat=True))
        devices.append({'name':d.name,'site':d.site.name,'feeds':feeds,'security_feeds':threats,
            'hours_observed':buckets.values('hour').distinct().count(),'issues':issues,
            'expected':['unifi'] if d.vendor=='unifi' else ['hillstone'] if d.vendor=='hillstone' else ['system']+(['zenarmor'] if d.zenarmor_enabled else [])})
    return {'devices':devices,'observed_devices':sum(bool(d['feeds']) for d in devices),
        'notice':'Se indican motores y horas con mensajes recibidos. Un flujo de alertas puede permanecer en silencio; estas observaciones no garantizan cobertura continua ni ausencia de ataques.'}


def collect_client_week(client, week_start, authorization):
    from .source_ownership import report_scope,coverage_metadata
    from .indexer_results import complete,count,total,hits as checked_hits
    sources,ownership,ownership_fingerprint = report_scope(client,week_start)
    if not sources:
        return {"sources": [], "wazuh_alert_count": 0, "security_count": 0,
                "availability_count": 0, "other_high_count": 0,
                "allowed_count": 0, "blocked_count": 0, "notable_alerts": [],
                "findings": [], "details_limited": False,'coverage':{**coverage_for_week(client,week_start),**coverage_metadata(client,week_start),'normalization_version':1,'collection_schema':2,'ownership_fingerprint':ownership_fingerprint}}
    filters = [{"terms": {"location": sources}}, _range_filter(week_start),ownership]
    high = {"range": {"rule.level": {"gte": 8}}}
    security = security_filter()
    availability = {"term": {"data.unifi.event_name": "Internet Down"}}
    body = {
        "size": 0, "track_total_hits": True,
        "query": {"bool": {"filter": filters}},
        "aggs": {
            "high": {"filter": high},
            "availability": {"filter": availability},
            "security": {"filter": security, "aggs": {
                "allowed": {"filter": action_filter('allowed')},
                "blocked": {"filter": action_filter('blocked')},
            }},
        },
    }
    result = complete(_search(body, authorization))
    aggregations = result.get("aggregations", {})
    metrics = aggregations.get("security", {})
    security_count=count(metrics.get('doc_count'))
    allowed=count(metrics.get('allowed',{}).get('doc_count'));blocked=count(metrics.get('blocked',{}).get('doc_count'))
    high_count = count(aggregations.get("high", {}).get("doc_count"))
    availability_count = count(aggregations.get("availability", {}).get("doc_count"))
    alert_count=total(result)
    details = complete(_search({
        "size": 2000,
        "query": {"bool": {"filter": filters + [{'bool':{'should':[high,security],'minimum_should_match':1}}]}},
        "sort": [{"timestamp": "desc"}],
        "track_total_hits":True,
        "_source": ['id','timestamp','location','rule','decoder','data'],
    }, authorization))
    hits = checked_hits(details)
    detail_count=total(details)
    findings, notable = build_findings(hits, inventories_for_sources(client, sources, events=[hit.get("_source", {}) for hit in hits]))
    if report_scope(client,week_start)[2]!=ownership_fingerprint:
        raise ValueError('La propiedad de las fuentes cambió durante la recopilación.')
    return {
        "sources": sources,
        "wazuh_alert_count": alert_count,
        "security_count": security_count,
        "availability_count": availability_count,
        "other_high_count": max(0, high_count - security_count - availability_count),
        "allowed_count": allowed,
        "blocked_count": blocked,
        "notable_alerts": notable,
        "findings": findings,
        "details_limited": detail_count > len(hits),
        'coverage':{**coverage_for_week(client,week_start),**coverage_metadata(client,week_start),'normalization_version':1,'collection_schema':2,'ownership_fingerprint':ownership_fingerprint},
    }


def refresh_week(week_start):
    if week_start.weekday() != 0:
        raise ValueError("La semana debe comenzar en lunes.")
    clients = list(Client.objects.filter(active=True))
    _source_owner_check(clients)
    authorization = indexer_authorization()
    reports = []
    for client in clients:
        existing = WeeklyReport.objects.filter(client=client, week_start=week_start).first()
        if existing and existing.sent_at:
            reports.append(existing)
            continue
        values = collect_client_week(client, week_start, authorization)
        report, _ = WeeklyReport.objects.update_or_create(
            client=client, week_start=week_start,
            defaults={**values, "collected_at": timezone.now()},
        )
        reports.append(report)
    return reports


def refresh_current_reports(now=None, limit=3):
    """Protected worker refreshes drafts; web requests never need indexer keys."""
    from .operations import set_issue
    from .models import OperationalIssue
    now = now or timezone.now()
    today = timezone.localdate(now)
    monday = today - timedelta(days=today.weekday())
    clients = list(Client.objects.filter(active=True).order_by('pk'))
    _source_owner_check(clients)
    drafts = {r.client_id:r for r in WeeklyReport.objects.filter(week_start=monday)}
    due = [c for c in clients if report_sources(c) and
           (c.pk not in drafts or (not drafts[c.pk].sent_at and now-drafts[c.pk].collected_at >= timedelta(minutes=10)))]
    due.sort(key=lambda c: drafts[c.pk].collected_at if c.pk in drafts else now-timedelta(days=365))
    if not due:
        return 0
    authorization = indexer_authorization()
    updated = 0
    for client in due[:limit]:
        key = f'platform:report-refresh:{client.pk}'
        try:
            values = collect_client_week(client, monday, authorization)
            # Recheck sent_at under the lock: a shared/sent snapshot stays unchanged.
            from django.db import transaction
            with transaction.atomic():
                report, _ = WeeklyReport.objects.get_or_create(client=client,week_start=monday)
                if report.sent_at:
                    continue
                for field,value in values.items():
                    setattr(report,field,value)
                report.collected_at = now
                report.save(update_fields=[*values,'collected_at'])
            OperationalIssue.objects.filter(key=key,active=True).update(active=False,resolved_at=now)
            updated += 1
        except Exception:
            set_issue(key,'Informe provisional pendiente de actualizar',details='Revisar la consulta protegida a Wazuh; se conservan los últimos datos recopilados.',now=now)
    return updated


def report_context(report):
    client = report.client
    start = timezone.make_aware(datetime.combine(report.week_start, time.min))
    end = start + timedelta(days=7)
    incidents = client.incidents.filter(observed_at__gte=start, observed_at__lt=end).select_related("site", "device")
    if not report.sources:
        summary_title = "Visibilidad pendiente"
        summary_text = "No hay una fuente de eventos verificada para este cliente. No podemos valorar esta semana a partir de Wazuh."
    elif report.allowed_count:
        summary_title = "Revisión prioritaria"
        summary_text = f"Se registraron {report.allowed_count} detecciones de seguridad permitidas. Conviene revisar los equipos y accesos afectados."
    elif report.blocked_count:
        summary_title = "Bloqueos registrados"
        summary_text = f"El firewall registró {report.blocked_count} detecciones bloqueadas. Revisa si los intentos se repiten y si los servicios publicados son necesarios."
    elif report.security_count:
        summary_title = "Detecciones con acción sin confirmar"
        detection_text = "Se recibió una detección de seguridad." if report.security_count == 1 else f"Se recibieron {report.security_count} detecciones de seguridad."
        summary_text = detection_text + " Los registros no permiten confirmar si el tráfico fue bloqueado o permitido; revisa la evidencia en el firewall."
    elif report.availability_count:
        summary_title = "Revisar disponibilidad"
        summary_text = f"Se registraron {report.availability_count} avisos de disponibilidad. Comprueba si afectaron al servicio."
    else:
        summary_title = "Sin detecciones recibidas"
        summary_text = "Wazuh no recibió detecciones de seguridad para este cliente durante la semana. Esto no confirma que no hubiera actividad."
    unknown_actions = max(0, report.security_count - report.allowed_count - report.blocked_count)
    if unknown_actions and (report.allowed_count or report.blocked_count):
        summary_text += " Además, hay " + ("una detección" if unknown_actions == 1 else f"{unknown_actions} detecciones") + " con la acción sin confirmar; revisa la evidencia."
    if report.coverage.get('ownership_pending'):
        summary_title='Histórico pendiente de revisión'
        summary_text='Existen evidencias anteriores al periodo de propiedad acreditado para estas fuentes. Se conservan en el SOC, pero este borrador no resume todo el histórico. No debe interpretarse un recuento cero como ausencia de detecciones ni enviarse hasta revisar la atribución.'
    elif report.coverage.get('ownership_limited'):
        summary_text+=' La atribución de las fuentes solo está acreditada durante parte de esta semana; los recuentos se limitan a ese periodo.'
    priority_actions = [
        {"asset": finding.get("asset_name", "Equipo por identificar"), "action": finding["recommendations"][0]}
        for finding in report.findings if finding.get("recommendations")
    ][:3]
    return {
        "client": client, "report": report, "monday": report.week_start,
        "sunday": report.week_start + timedelta(days=6),
        "incidents": incidents,
        "incident_count": incidents.count(),
        "resolved_count": incidents.filter(status="resolved").count(),
        "open_count": incidents.exclude(status="resolved").count(),
        "site_count": client.sites.filter(active=True).count(),
        "device_count": Device.objects.filter(site__client=client, active=True).count(),
        "connected_count": Device.objects.filter(site__client=client, active=True, integration=Device.Integration.CONNECTED).count(),
        "coverage_ok": bool(report.coverage.get('observed_devices')),
        'coverage':report.coverage,
        "summary_title": summary_title, "summary_text": summary_text,
        "priority_actions": priority_actions,
        "provisional": report.week_start + timedelta(days=7) > timezone.localdate(),
        "report_stale": not report.sent_at and timezone.now()-report.collected_at > timedelta(minutes=15),
    }


def send_report(report):
    client = report.client
    if report.sent_at or not client.active or not client.weekly_reports_enabled or not client.report_email:
        return False
    if not report.sources:
        report.last_send_error = "No hay una fuente de eventos verificada para este cliente."
        report.save(update_fields=["last_send_error"])
        return False
    from .source_ownership import report_scope
    try:
        _,_,fingerprint=report_scope(client,report.week_start)
        if report.coverage.get('collection_schema')!=2 or report.coverage.get('ownership_fingerprint')!=fingerprint or report.coverage.get('ownership_pending'):
            raise ValueError('Actualizar el informe antes de enviarlo.')
        from .models import OperationalIssue
        if timezone.now()-report.collected_at>timedelta(minutes=15) or OperationalIssue.objects.filter(key=f'platform:report-refresh:{client.pk}',active=True).exists():
            raise ValueError('La última recopilación no está vigente.')
    except ValueError:
        report.last_send_error='Requiere una recopilación completa con propiedad histórica verificada antes del envío.'
        report.save(update_fields=['last_send_error']);return False
    from .service_development import customer_report_context
    context = customer_report_context(report)
    subject = f"ib-red · Informe semanal de seguridad y disponibilidad · {client.name} · {report.week_start:%d/%m/%Y}"
    try:
        from .report_sharing import create_report_link
        from .models import MailSettings
        context["report_url"] = create_report_link(report)
        config = MailSettings.objects.order_by("pk").first()
        from urllib.parse import urlsplit
        public_origin = urlsplit(config.public_reports_url)
        context["brand_logo_url"] = f"{public_origin.scheme}://{public_origin.netloc}/static/brand/ibred-empresas-color.png"
        context["reply_address"] = config.reply_to_email or config.from_email
        context["link_expires_at"] = report.customer_share.expires_at
        plain = render_to_string("report_email.txt", context)
        html = render_to_string("report_email.html", context)
        provider_message_id = send_report_email(client.report_email, subject, plain, html,report=report)
    except MailConfigurationError as exc:
        report.last_send_error = str(exc)[:250]
        report.save(update_fields=["last_send_error"])
        return False
    except Exception:
        report.last_send_error = "SendGrid rechazó el envío o hubo un error de conexión; revise el registro del servicio."
        report.save(update_fields=["last_send_error"])
        raise
    report.sent_at = timezone.now()
    report.sent_to = client.report_email
    report.provider_message_id = provider_message_id
    report.last_send_error = ""
    report.save(update_fields=["sent_at", "sent_to", "provider_message_id", "last_send_error"])
    try:
        from .report_versions import published_version
        published_version(report)
    except Exception:
        # El correo ya salió: si no se pudo congelar ahora, se congela en la primera consulta del cliente.
        pass
    return True

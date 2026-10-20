"""Customer PDF using the same scoped report context as the browser view."""
from html import escape
from io import BytesIO
from pathlib import Path

import reportlab
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle, Image


def render_report_pdf(report,context_override=None):
    from .reporting import report_context
    context = context_override if context_override is not None else report_context(report)
    if "SOCVera" not in pdfmetrics.getRegisteredFontNames():
        fonts = Path(reportlab.__file__).parent / "fonts"
        pdfmetrics.registerFont(TTFont("SOCVera", str(fonts / "Vera.ttf")))
        pdfmetrics.registerFont(TTFont("SOCVera-Bold", str(fonts / "VeraBd.ttf")))
        pdfmetrics.registerFontFamily("SOCVera", normal="SOCVera", bold="SOCVera-Bold")
    palette = {"ink": colors.HexColor("#063B2B"), "teal": colors.HexColor("#0B612D"), "light": colors.HexColor("#ECF4E8")}
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle("SOCBody", fontName="SOCVera", fontSize=9, leading=12.5, textColor=palette["ink"], spaceAfter=6))
    styles.add(ParagraphStyle("SOCTitle", parent=styles["SOCBody"], fontName="SOCVera-Bold", fontSize=22, leading=26, spaceAfter=9))
    styles.add(ParagraphStyle("SOCHeading", parent=styles["SOCBody"], fontName="SOCVera-Bold", fontSize=12, leading=16, textColor=palette["teal"], spaceBefore=11, spaceAfter=6, keepWithNext=True))
    styles.add(ParagraphStyle("SOCSmall", parent=styles["SOCBody"], fontSize=8, leading=10.5, textColor=colors.HexColor("#526579")))
    def p(text, style="SOCBody"):
        return Paragraph(escape(str(text)).replace("\n", "<br/>"), styles[style])
    stream = BytesIO()
    doc = SimpleDocTemplate(stream, pagesize=A4, leftMargin=20*mm, rightMargin=20*mm, topMargin=18*mm, bottomMargin=20*mm,
                            title=f"Informe semanal - {report.client.name}", author="ib-red - Equipo NOC")
    logo = Path(__file__).resolve().parent.parent / "static/brand/ibred-empresas-color.png"
    brand = Image(str(logo), width=40*mm, height=22.5*mm, hAlign="LEFT")
    story = [brand, Spacer(1, 2*mm), p("ib-red empresas | Servicio de seguridad gestionada", "SOCSmall"), p("Informe semanal", "SOCTitle"),
             p(report.client.name), p(f"Del {context['monday']:%d/%m/%Y} al {context['sunday']:%d/%m/%Y}", "SOCSmall"),
             p("Lo más importante", "SOCHeading"), p(context["summary_title"]), p(context["summary_text"])]
    cells = [[p(f"{value}\n{label}") for value, label in (
        (report.security_count, "Detecciones"), (report.blocked_count, "Bloqueadas"),
        (report.allowed_count, "Permitidas"), (report.availability_count, "Disponibilidad"))]]
    metrics = Table(cells, colWidths=[42.5*mm]*4, hAlign="LEFT")
    metrics.setStyle(TableStyle([("BACKGROUND", (0,0),(-1,-1),palette["light"]), ("VALIGN",(0,0),(-1,-1),"TOP"),
                                ("TOPPADDING",(0,0),(-1,-1),9), ("BOTTOMPADDING",(0,0),(-1,-1),6)]))
    story.extend([Spacer(1, 4*mm), metrics, p("Qué hacer ahora", "SOCHeading")])
    for index, action in enumerate(context["priority_actions"], 1):
        story.append(p(f"{index}. {action['asset']}: {action['action']}"))
    if not context["priority_actions"]:
        story.append(p("No hay una acción concreta deducible de las alertas recibidas. Comprueben la cobertura de registros y mantengan la supervisión habitual."))
    story.append(p("Equipos afectados y recomendaciones", "SOCHeading"))
    if report.details_limited:
        story.append(p("El volumen supera el límite de detalle automático. El equipo SOC debe revisar las alertas restantes antes de presentar conclusiones."))
    for finding in report.findings:
        title = finding.get("asset_name", "Equipo por identificar")
        if finding.get("asset_ip"):
            title += " - " + finding["asset_ip"]
        story.append(p(title, "SOCHeading"))
        story.append(p(f"Prioridad: {finding.get('priority', 'por revisar')}. Sede: {finding.get('site') or 'por identificar'}. Eventos: {finding.get('count', 0)}."))
        story.append(p(f"Periodo observado: {finding.get('first_seen', '')} - {finding.get('last_seen', '')}.", "SOCSmall"))
        story.append(p("Evidencia: " + "; ".join(finding.get("signatures", []))))
        if finding.get("action"):
            story.append(p("Acción del firewall: " + finding["action"]))
        if finding.get("ports"):
            story.append(p("Puertos de destino: " + ", ".join(map(str, finding["ports"]))))
        if finding.get("source_ips"):
            story.append(p("Orígenes observados: " + ", ".join(finding["source_ips"])))
        if finding.get("forwarded"):
            story.append(p("Exposición comprobada: redirección WAN activa hacia este equipo, puertos " + finding.get("published_ports", "por confirmar") + "."))
        if not finding.get("asset_confirmed"):
            story.append(p("La identidad del equipo debe confirmarse.", "SOCSmall"))
        for index, recommendation in enumerate(finding.get("recommendations", []), 1):
            story.append(p(f"{index}. {recommendation}"))
    if not report.findings:
        story.append(p("No hay hallazgos concretos con información suficiente en las alertas recibidas."))
    story.append(p('Datos recibidos y cobertura','SOCHeading'))
    coverage=context.get('coverage') or {}
    for device in coverage.get('devices',[]):
        story.append(p(device['site']+' / '+device['name']+': motores con mensajes: '+(', '.join(device['feeds']) or 'sin observaciones')+'. Horas con datos: '+str(device['hours_observed'])+'.'))
        if device.get('issues'): story.append(p('Comprobaciones pendientes: '+'; '.join(device['issues'])))
    story.append(p(coverage.get('notice') or 'No hay observaciones históricas de cobertura para este informe.','SOCSmall'))
    story.append(p("Incidencias del periodo", "SOCHeading"))
    story.append(p(f"{context['incident_count']} registradas, {context['resolved_count']} resueltas y {context['open_count']} pendientes."))
    for incident in context["incidents"]:
        from django.utils import timezone
        story.append(p(f"{timezone.localtime(incident.observed_at):%d/%m/%Y}: {incident.title} - {incident.get_severity_display()} - {incident.get_status_display()}"))
    if report.notable_alerts:
        story.append(p("Detalle técnico para seguimiento", "SOCHeading"))
        rows = [[p(label, "SOCSmall") for label in ("Fecha", "Equipo", "Alerta / acción")]]
        for item in report.notable_alerts:
            rows.append([p(item.get("timestamp", ""), "SOCSmall"), p(item.get("asset", "") + "\n" + item.get("destination", ""), "SOCSmall"),
                         p(item.get("description", "") + "\n" + item.get("action", "") + (" - Puerto " + str(item["port"]) if item.get("port") else ""), "SOCSmall")])
        detail = Table(rows, colWidths=[35*mm, 43*mm, 92*mm], repeatRows=1, hAlign="LEFT")
        detail.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),palette["light"]), ("VALIGN",(0,0),(-1,-1),"TOP"),
                                   ("LINEBELOW",(0,0),(-1,-1),.3, colors.HexColor("#D7EAD9")), ("TOPPADDING",(0,0),(-1,-1),7)]))
        story.append(detail)
    story.extend([p("Alcance y verificación", "SOCHeading"), p("Estas cifras describen los eventos recibidos por Wazuh para las fuentes verificadas del cliente. Un cero no confirma recepción continua ni ausencia de ataques. Una detección aislada no demuestra un compromiso. En UniFi, el flujo SIEM puede contener menos detalle que Traffic Flows."),
                  p("Próximo paso: confirmar las medidas acordadas y revisar si las alertas se repiten durante la siguiente semana."),
                  p("Para consultas y aclaraciones: noc@ibred.es", "SOCSmall")])
    def footer(canvas, document):
        canvas.saveState()
        canvas.setFont("SOCVera", 8)
        canvas.setFillColor(colors.HexColor("#526579"))
        canvas.drawString(20*mm, 12*mm, "ib-red | Informe confidencial")
        canvas.drawRightString(190*mm, 12*mm, f"Página {document.page}")
        canvas.restoreState()
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return stream.getvalue()

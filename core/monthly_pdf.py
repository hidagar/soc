"""PDF del informe mensual para dirección, con el mismo contexto (y la misma marca) que la página."""
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
from reportlab.platypus import Image, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def render_monthly_pdf(context):
    if 'SOCVera' not in pdfmetrics.getRegisteredFontNames():
        fonts = Path(reportlab.__file__).parent / 'fonts'
        pdfmetrics.registerFont(TTFont('SOCVera', str(fonts / 'Vera.ttf')))
        pdfmetrics.registerFont(TTFont('SOCVera-Bold', str(fonts / 'VeraBd.ttf')))
        pdfmetrics.registerFontFamily('SOCVera', normal='SOCVera', bold='SOCVera-Bold')
    palette = {'ink': colors.HexColor('#063B2B'), 'teal': colors.HexColor('#0B612D'), 'light': colors.HexColor('#ECF4E8')}
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle('SOCBody', fontName='SOCVera', fontSize=9, leading=12.5, textColor=palette['ink'], spaceAfter=6))
    styles.add(ParagraphStyle('SOCTitle', parent=styles['SOCBody'], fontName='SOCVera-Bold', fontSize=22, leading=26, spaceAfter=9))
    styles.add(ParagraphStyle('SOCHeading', parent=styles['SOCBody'], fontName='SOCVera-Bold', fontSize=12, leading=16,
                              textColor=palette['teal'], spaceBefore=11, spaceAfter=6, keepWithNext=True))
    styles.add(ParagraphStyle('SOCSmall', parent=styles['SOCBody'], fontSize=8, leading=10.5, textColor=colors.HexColor('#526579')))

    def p(text, style='SOCBody'):
        return Paragraph(escape(str(text)).replace('\n', '<br/>'), styles[style])

    def table(rows, widths):
        result = Table(rows, colWidths=widths, repeatRows=1, hAlign='LEFT')
        result.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), palette['light']), ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                                    ('LINEBELOW', (0, 0), (-1, -1), .3, colors.HexColor('#D7EAD9')), ('TOPPADDING', (0, 0), (-1, -1), 6)]))
        return result

    client, totals, previous = context['client'], context['totals'], context['previous']
    stream = BytesIO()
    doc = SimpleDocTemplate(stream, pagesize=A4, leftMargin=20*mm, rightMargin=20*mm, topMargin=18*mm, bottomMargin=20*mm,
                            title=f"Informe mensual - {client.name}", author='ib-red - Equipo NOC')
    logo = Path(__file__).resolve().parent.parent / 'static/brand/ibred-empresas-color.png'
    story = [Image(str(logo), width=40*mm, height=22.5*mm, hAlign='LEFT'), Spacer(1, 2*mm),
             p('ib-red empresas | Servicio de seguridad gestionada', 'SOCSmall'), p('Informe mensual', 'SOCTitle'),
             p(client.name), p(f"{context['month_label'].capitalize()} · semanas del {context['period_start']:%d/%m} al "
                               f"{context['period_end']:%d/%m/%Y}", 'SOCSmall'),
             p('Lo más importante', 'SOCHeading'), p(context['summary_title']), p(context['summary_text'])]
    if context['soc_summary']:
        story.extend([p('Valoración del SOC', 'SOCHeading'), p(context['soc_summary'])])
    metrics = Table([[p(f'{value}\n{label}') for value, label in (
        (totals['security'], 'Detecciones'), (totals['blocked'], 'Bloqueadas'), (totals['allowed'], 'Permitidas'),
        (totals['availability'], 'Disponibilidad'))]], colWidths=[42.5*mm]*4, hAlign='LEFT')
    metrics.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, -1), palette['light']), ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                                 ('TOPPADDING', (0, 0), (-1, -1), 9), ('BOTTOMPADDING', (0, 0), (-1, -1), 6)]))
    story.extend([Spacer(1, 4*mm), metrics])
    if previous:
        story.append(p(f"Mes anterior: {previous['security']} detecciones, {previous['blocked']} bloqueadas y "
                       f"{previous['allowed']} permitidas.", 'SOCSmall'))
    story.append(p('Evolución por semanas', 'SOCHeading'))
    rows = [[p(label, 'SOCSmall') for label in ('Semana', 'Detecciones', 'Bloqueadas', 'Permitidas', 'Sin confirmar', 'Firewalls con datos')]]
    for week in context['weeks']:
        rows.append([p(f"{week['start']:%d/%m} – {week['end']:%d/%m}", 'SOCSmall')] + (
            [p('Sin datos', 'SOCSmall')] + [p('', 'SOCSmall')] * 4 if week['missing'] else
            [p(week[k], 'SOCSmall') for k in ('security', 'blocked', 'allowed', 'unknown')] + [p(f"{week['observed']} de {week['devices']}", 'SOCSmall')]))
    story.append(table(rows, [32*mm, 26*mm, 26*mm, 26*mm, 26*mm, 34*mm]))
    proactive = context.get('proactive') or {}
    if proactive:
        story.append(p('Bloqueo proactivo del SOC', 'SOCHeading'))
        if proactive.get('inbound'):
            item = proactive['inbound']
            story.append(p(f"Lista de {item['entries']} direcciones IP maliciosas en {', '.join(item['firewalls'])}."
                           + (f" Durante el mes bloqueó {item['packets']} paquetes." if item['measured'] else ' La medición está empezando.')))
        if proactive.get('outbound'):
            item = proactive['outbound']
            story.append(p(f"Bloqueo de salida hacia {item['entries']} destinos asociados a malware o control remoto"
                           + (f": {item['packets']} paquetes cortados en el mes." if item['measured'] else '.')))
    story.append(p('Recomendaciones del mes', 'SOCHeading'))
    for index, item in enumerate(context['recommendations'], 1):
        assets = ', '.join(item['assets']) + (f" y {item['more_assets']} más" if item['more_assets'] else '')
        story.append(p(f"{index}. {item['text']} (Equipos: {assets}; {item['weeks']} semana{'s' if item['weeks'] != 1 else ''}.)"))
    if not context['recommendations']:
        story.append(p('No hay recomendaciones concretas en los informes semanales del mes.'))
    story.append(p('Seguimiento y actuaciones', 'SOCHeading'))
    story.append(p(f"Comunicaciones publicadas en el mes: {len(context['publications'])}."))
    for item in context['publications']:
        story.append(p(f"· {item['title']} — {item['status']}"))
    story.append(p(f"Actuaciones validadas en el mes: {len(context['validated_tasks'])}. Pendientes al publicar: {len(context['pending_tasks'])}."))
    for item in context['validated_tasks']:
        story.append(p(f"· Validada: {item['title']}"))
    for item in context['pending_tasks']:
        story.append(p(f"· {item['title']} — {item['status']}" + (f" (fecha acordada {item['due_at']:%d/%m/%Y})" if item['due_at'] else '')))
    story.extend([p('Alcance', 'SOCHeading'),
                  p('Las cifras suman los informes semanales de las semanas que empiezan en el mes, los mismos que recibió cada '
                    'semana. Describen los eventos recibidos por el SOC para las fuentes verificadas: un cero no confirma recepción '
                    'continua ni ausencia de ataques, y una detección aislada no demuestra un compromiso. Más o menos detecciones '
                    'no indica por sí solo más o menos riesgo.'),
                  p('Para consultas y aclaraciones: noc@ibred.es', 'SOCSmall')])

    def footer(canvas, document):
        canvas.saveState()
        canvas.setFont('SOCVera', 8)
        canvas.setFillColor(colors.HexColor('#526579'))
        canvas.drawString(20*mm, 12*mm, 'ib-red | Informe confidencial')
        canvas.drawRightString(190*mm, 12*mm, f'Página {document.page}')
        canvas.restoreState()
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return stream.getvalue()

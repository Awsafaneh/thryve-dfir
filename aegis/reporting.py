from __future__ import annotations

import io
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Image, KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


BRAND = colors.HexColor("#22B968")
INK = colors.HexColor("#07120E")
SLATE = colors.HexColor("#E9EFEC")
MUTED = colors.HexColor("#62716A")
LOGO = Path(__file__).resolve().parents[1] / "static" / "assets" / "thryve-logo.jpg"


def _safe(value: Any) -> str:
    return str(value if value not in (None, "") else "-").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build_pdf_report(overview: dict[str, Any], evidence: dict[str, Any], hostname: str, case_id: int | None) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=16 * mm)
    styles = getSampleStyleSheet()
    title = ParagraphStyle("ReportTitle", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=25, leading=29, textColor=INK, spaceAfter=4)
    subtitle = ParagraphStyle("Subtitle", parent=styles["Normal"], fontName="Helvetica", fontSize=9, leading=14, textColor=MUTED)
    section = ParagraphStyle("Section", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=12, leading=16, textColor=INK, spaceBefore=15, spaceAfter=7)
    body = ParagraphStyle("Body", parent=styles["BodyText"], fontName="Helvetica", fontSize=8.5, leading=12, textColor=INK)
    small = ParagraphStyle("Small", parent=body, fontSize=7.5, leading=10, textColor=MUTED)
    story: list[Any] = []
    logo = Image(str(LOGO), width=16 * mm, height=16 * mm) if LOGO.exists() else Spacer(16 * mm, 16 * mm)
    header = Table([[logo, Paragraph("<b>THRYVE</b><br/><font size=8>SECURITY OPERATIONS</font>", ParagraphStyle("Brand", parent=body, textColor=INK, leading=12)), Paragraph("CONFIDENTIAL - INCIDENT EVIDENCE REPORT", ParagraphStyle("Conf", parent=small, alignment=TA_RIGHT, textColor=BRAND))]], colWidths=[20 * mm, 105 * mm, 50 * mm])
    header.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LINEBELOW", (0, 0), (-1, -1), 1, BRAND), ("BOTTOMPADDING", (0, 0), (-1, -1), 9)]))
    story += [header, Spacer(1, 11 * mm), Paragraph("Incident evidence report", title)]
    generated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    scope = f"Case {case_id}" if case_id else "Endpoint snapshot"
    story += [Paragraph(f"<b>Scope:</b> {_safe(scope)} &nbsp;&nbsp; <b>Host:</b> {_safe(hostname)} &nbsp;&nbsp; <b>Generated:</b> {_safe(generated)}", subtitle)]
    counts = overview.get("counts", {})
    severity = overview.get("alert_severity", {})
    open_alerts = sum(int(severity.get(level, 0)) for level in ("critical", "high", "medium", "low"))
    risk_score = min(100, int(severity.get("critical", 0)) * 28 + int(severity.get("high", 0)) * 14 + int(severity.get("medium", 0)) * 5 + int(severity.get("low", 0)) * 2)
    metrics = [["RISK SCORE", str(risk_score), "OPEN ALERTS", str(open_alerts), "EVENTS", str(counts.get("events", 0))]]
    metric_table = Table(metrics, colWidths=[27 * mm, 31 * mm, 31 * mm, 31 * mm, 22 * mm, 31 * mm])
    metric_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), INK), ("TEXTCOLOR", (0, 0), (-1, -1), colors.white), ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"), ("FONTSIZE", (0, 0), (-1, -1), 8), ("ALIGN", (0, 0), (-1, -1), "CENTER"), ("TOPPADDING", (0, 0), (-1, -1), 10), ("BOTTOMPADDING", (0, 0), (-1, -1), 10)]))
    story += [Spacer(1, 8 * mm), metric_table, Paragraph("Executive summary", section)]
    summary = f"Thryve reviewed local endpoint telemetry for {_safe(hostname)}. The current queue contains {_safe(open_alerts)} alerts: {_safe(severity.get('critical', 0))} critical, {_safe(severity.get('high', 0))} high, {_safe(severity.get('medium', 0))} medium, and {_safe(severity.get('low', 0))} low. Findings below are derived from collected records and require analyst validation."
    story.append(Paragraph(summary, body))
    alerts = evidence.get("alerts", [])[:30]
    story.append(Paragraph("Alert register", section))
    if alerts:
        rows = [[Paragraph("Severity", small), Paragraph("Alert", small), Paragraph("MITRE", small), Paragraph("Status", small), Paragraph("Observed", small)]]
        for alert in alerts:
            rows.append([Paragraph(_safe(alert.get("severity", "info")).upper(), small), Paragraph(_safe(alert.get("title", alert.get("message"))), small), Paragraph(_safe(alert.get("mitre", "-")), small), Paragraph(_safe(alert.get("status", "open")), small), Paragraph(_safe(alert.get("created_at", alert.get("timestamp", "-")))[:19], small)])
        table = Table(rows, colWidths=[20 * mm, 75 * mm, 25 * mm, 24 * mm, 34 * mm], repeatRows=1)
        table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), INK), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("GRID", (0, 0), (-1, -1), .25, colors.HexColor("#C8D6CE")), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("BACKGROUND", (0, 1), (-1, -1), colors.white), ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, SLATE]), ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
        story.append(table)
    else:
        story.append(Paragraph("No alerts were included in the selected evidence scope.", body))
    events = evidence.get("events", [])[:25]
    story.append(Paragraph("Evidence timeline", section))
    if events:
        rows = [[Paragraph("Time", small), Paragraph("Source", small), Paragraph("Evidence", small)]]
        for event in events:
            rows.append([Paragraph(_safe(event.get("timestamp", "-"))[:19], small), Paragraph(_safe(event.get("source", "-")), small), Paragraph(_safe(event.get("message", event.get("event_type", "-"))), small)])
        table = Table(rows, colWidths=[37 * mm, 32 * mm, 109 * mm], repeatRows=1)
        table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), INK), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("GRID", (0, 0), (-1, -1), .25, colors.HexColor("#C8D6CE")), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, SLATE]), ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
        story.append(table)
    else:
        story.append(Paragraph("No event records were included in the selected evidence scope.", body))
    story += [Paragraph("Evidence handling", section), Paragraph("This report is generated from the local Thryve evidence store. Treat it as an analyst work product: preserve the original evidence package, verify its SHA-256 manifest before transfer, and document validation or containment decisions in the linked case.", body)]

    def footer(canvas, _: Any) -> None:
        canvas.saveState()
        canvas.setStrokeColor(BRAND); canvas.setLineWidth(.6); canvas.line(18 * mm, 11 * mm, 192 * mm, 11 * mm)
        canvas.setFillColor(MUTED); canvas.setFont("Helvetica", 7)
        canvas.drawString(18 * mm, 7 * mm, "Thryve - evidence-led report")
        canvas.drawRightString(192 * mm, 7 * mm, f"Page {canvas.getPageNumber()}")
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()

"""
Builds the one-click PDF security report: an executive-summary-style
document over the current Alert table — counts by module/severity, and
the detail list of flagged (malicious) events with their explanations.
This is what the handbook calls for: "a concise project report supported
by screenshots, logs, ... outputs."
"""
import io
import json
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
)
from sqlalchemy.orm import Session

from app.db.models import Alert


SEVERITY_COLORS = {
    "High": colors.HexColor("#D64545"),
    "Medium": colors.HexColor("#E0A030"),
    "Low": colors.HexColor("#4A90D9"),
}


def generate_report_pdf(db: Session) -> bytes:
    alerts = db.query(Alert).order_by(Alert.created_at.desc()).limit(500).all()

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        topMargin=2 * cm, bottomMargin=2 * cm, leftMargin=2 * cm, rightMargin=2 * cm,
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleBig", parent=styles["Title"], fontSize=22, spaceAfter=4)
    subtitle_style = ParagraphStyle("Subtitle", parent=styles["Normal"], fontSize=11, textColor=colors.grey)
    h2 = styles["Heading2"]
    body = styles["BodyText"]

    story = [
        Paragraph("SentinelAI — Security Operations Report", title_style),
        Paragraph(
            f"Generated {datetime.now(timezone.utc).strftime('%d %B %Y, %H:%M UTC')} &nbsp;|&nbsp; "
            f"AI-Powered Security Operations Platform",
            subtitle_style,
        ),
        Spacer(1, 0.6 * cm),
    ]

    # --- Summary counts ---
    total = len(alerts)
    malicious = sum(1 for a in alerts if a.is_malicious)
    by_module: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for a in alerts:
        mod = a.module.value if hasattr(a.module, "value") else str(a.module)
        sev = a.severity.value if hasattr(a.severity, "value") else str(a.severity)
        by_module[mod] = by_module.get(mod, 0) + 1
        by_severity[sev] = by_severity.get(sev, 0) + 1

    story.append(Paragraph("Executive Summary", h2))
    story.append(Paragraph(
        f"This report covers the {total} most recent security events recorded across all "
        f"SentinelAI modules, of which <b>{malicious}</b> were flagged as malicious/high-risk. "
        f"Each flagged event includes the model's confidence and the top factors that drove the "
        f"decision (via SHAP explainability), so findings can be verified by a human analyst "
        f"rather than taken as an unexplained black-box verdict.",
        body,
    ))
    story.append(Spacer(1, 0.4 * cm))

    summary_rows = [["Module", "Events", "Severity breakdown"]]
    for mod, count in sorted(by_module.items()):
        sev_counts = {}
        for a in alerts:
            m = a.module.value if hasattr(a.module, "value") else str(a.module)
            if m == mod:
                s = a.severity.value if hasattr(a.severity, "value") else str(a.severity)
                sev_counts[s] = sev_counts.get(s, 0) + 1
        breakdown = ", ".join(f"{k}: {v}" for k, v in sorted(sev_counts.items()))
        summary_rows.append([mod, str(count), breakdown])

    summary_table = Table(summary_rows, colWidths=[5.5 * cm, 2.5 * cm, 7 * cm])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F2937")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D1D5DB")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F3F4F6")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(summary_table)
    story.append(PageBreak())

    # --- Detailed findings (malicious only, most severe first) ---
    story.append(Paragraph("Detailed Findings", h2))
    flagged = [a for a in alerts if a.is_malicious]
    severity_rank = {"High": 0, "Medium": 1, "Low": 2}
    flagged.sort(key=lambda a: severity_rank.get(
        a.severity.value if hasattr(a.severity, "value") else str(a.severity), 3
    ))

    if not flagged:
        story.append(Paragraph("No malicious events were recorded in this reporting window.", body))
    for a in flagged[:100]:
        sev = a.severity.value if hasattr(a.severity, "value") else str(a.severity)
        mod = a.module.value if hasattr(a.module, "value") else str(a.module)
        sev_color = SEVERITY_COLORS.get(sev, colors.grey)

        header_style = ParagraphStyle(
            "FindingHeader", parent=styles["Heading3"], textColor=sev_color, spaceBefore=10, spaceAfter=2,
        )
        story.append(Paragraph(f"[{sev}] {a.title}", header_style))
        meta = f"Module: {mod} &nbsp;|&nbsp; Confidence: {a.confidence:.0%} &nbsp;|&nbsp; " \
               f"{a.created_at.strftime('%Y-%m-%d %H:%M UTC') if a.created_at else ''}"
        story.append(Paragraph(meta, ParagraphStyle("Meta", parent=styles["Normal"], fontSize=8, textColor=colors.grey)))
        if a.detail:
            story.append(Paragraph(a.detail, body))

        if a.explanation_json:
            try:
                explanation = json.loads(a.explanation_json)
                if explanation and isinstance(explanation, list):
                    exp_rows = [["Factor", "Value", "Impact"]]
                    for item in explanation[:5]:
                        exp_rows.append([
                            str(item.get("feature", item.get("check", ""))),
                            str(item.get("value", item.get("detail", "")))[:50],
                            f"{item.get('impact', 0):+.2f}" if isinstance(item.get("impact"), (int, float)) else "",
                        ])
                    exp_table = Table(exp_rows, colWidths=[4 * cm, 8 * cm, 2 * cm])
                    exp_table.setStyle(TableStyle([
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E5E7EB")),
                        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#D1D5DB")),
                        ("TOPPADDING", (0, 0), (-1, -1), 3),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                    ]))
                    story.append(Spacer(1, 0.15 * cm))
                    story.append(exp_table)
            except (json.JSONDecodeError, TypeError):
                pass

    doc.build(story)
    return buffer.getvalue()

"""
VulnSense — PDF Report Generator
==================================
Produces a properly formatted PDF security report using ReportLab.
Includes: cover page, executive summary, risk breakdown table,
per-finding details with CVE links, and a methodology note.
"""

import os
from datetime import datetime
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.graphics import renderPDF

# ── Colour palette (matches VulnSense dark UI converted to print) ──
C_DARK    = colors.HexColor("#0d1117")
C_SURFACE = colors.HexColor("#161b22")
C_CYAN    = colors.HexColor("#39d0d8")
C_HIGH    = colors.HexColor("#f85149")
C_MED     = colors.HexColor("#e3b341")
C_LOW     = colors.HexColor("#3fb950")
C_MUTED   = colors.HexColor("#8b949e")
C_TEXT    = colors.HexColor("#1a1a2e")
C_WHITE   = colors.white
C_BORDER  = colors.HexColor("#30363d")
C_LIGHT   = colors.HexColor("#f0f4f8")

W, H = A4  # 210 × 297 mm


def _styles():
    base = getSampleStyleSheet()
    custom = {
        "cover_title": ParagraphStyle("cover_title", fontSize=28, fontName="Helvetica-Bold",
            textColor=C_WHITE, leading=34, alignment=TA_CENTER),
        "cover_sub":   ParagraphStyle("cover_sub", fontSize=12, fontName="Helvetica",
            textColor=colors.HexColor("#8b949e"), leading=18, alignment=TA_CENTER),
        "section":     ParagraphStyle("section", fontSize=13, fontName="Helvetica-Bold",
            textColor=C_DARK, leading=18, spaceBefore=14, spaceAfter=6,
            borderPad=4),
        "body":        ParagraphStyle("body", fontSize=9, fontName="Helvetica",
            textColor=C_TEXT, leading=14, spaceAfter=4),
        "small":       ParagraphStyle("small", fontSize=8, fontName="Helvetica",
            textColor=C_MUTED, leading=12),
        "finding_title": ParagraphStyle("finding_title", fontSize=10, fontName="Helvetica-Bold",
            textColor=C_DARK, leading=14),
        "explanation": ParagraphStyle("explanation", fontSize=8.5, fontName="Helvetica",
            textColor=C_TEXT, leading=13, leftIndent=8),
        "mono":        ParagraphStyle("mono", fontSize=8, fontName="Courier",
            textColor=C_TEXT, leading=12),
    }
    return custom


def _risk_color(label):
    return {
        "High":   C_HIGH,
        "Medium": C_MED,
        "Low":    C_LOW,
    }.get(label, C_MUTED)


def _strip_html(text):
    """Very basic HTML tag strip for plain-text cells."""
    import re
    return re.sub(r"<[^>]+>", "", text or "")


def generate_pdf(scan_id: str, host: str, findings: list, analyst: str = "admin") -> bytes:
    """
    Generate a full PDF report for a scan.
    Returns raw PDF bytes.
    """
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        topMargin=18*mm, bottomMargin=18*mm,
        leftMargin=18*mm, rightMargin=18*mm,
        title=f"VulnSense Security Report — {host}",
        author="VulnSense",
        subject="Vulnerability Risk Assessment",
    )

    S = _styles()
    story = []

    high   = [f for f in findings if f.get("risk_label") == "High"]
    medium = [f for f in findings if f.get("risk_label") == "Medium"]
    low    = [f for f in findings if f.get("risk_label") == "Low"]
    total  = len(findings)

    # ── COVER PAGE ──────────────────────────────────────────────
    # Dark header block (simulated with a Table)
    cover_data = [[
        Paragraph("VulnSense", ParagraphStyle("logo", fontSize=32, fontName="Helvetica-Bold",
            textColor=C_CYAN, leading=38, alignment=TA_CENTER)),
    ], [
        Paragraph("Security Vulnerability Assessment Report",
            ParagraphStyle("ct", fontSize=16, fontName="Helvetica",
            textColor=C_WHITE, leading=22, alignment=TA_CENTER)),
    ], [
        Spacer(1, 8*mm),
    ], [
        Paragraph(f"Target Host: <b>{host}</b>",
            ParagraphStyle("meta", fontSize=11, fontName="Helvetica",
            textColor=colors.HexColor("#8b949e"), alignment=TA_CENTER)),
    ], [
        Paragraph(f"Scan ID: {scan_id}",
            ParagraphStyle("meta2", fontSize=10, fontName="Courier",
            textColor=colors.HexColor("#8b949e"), alignment=TA_CENTER)),
    ], [
        Paragraph(f"Generated: {datetime.utcnow().strftime('%d %B %Y, %H:%M UTC')}",
            ParagraphStyle("meta3", fontSize=10, fontName="Helvetica",
            textColor=colors.HexColor("#8b949e"), alignment=TA_CENTER)),
    ], [
        Paragraph(f"Analyst: {analyst}",
            ParagraphStyle("meta4", fontSize=10, fontName="Helvetica",
            textColor=colors.HexColor("#8b949e"), alignment=TA_CENTER)),
    ]]

    cover_table = Table(cover_data, colWidths=[W - 36*mm])
    cover_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C_DARK),
        ("TOPPADDING",    (0, 0), (-1, 0), 20),
        ("BOTTOMPADDING", (0, -1), (-1, -1), 20),
        ("LEFTPADDING",   (0, 0), (-1, -1), 16),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 16),
        ("ROWBACKGROUNDS",(0,0),(-1,-1), [C_DARK]),
    ]))
    story.append(cover_table)
    story.append(Spacer(1, 10*mm))

    # ── Risk summary boxes ─────────────────────────────────────
    summary_data = [[
        Paragraph(f"<b>{len(high)}</b><br/><font size=8>High Risk</font>",
            ParagraphStyle("h", fontSize=22, fontName="Helvetica-Bold",
            textColor=C_HIGH, alignment=TA_CENTER, leading=28)),
        Paragraph(f"<b>{len(medium)}</b><br/><font size=8>Medium Risk</font>",
            ParagraphStyle("m", fontSize=22, fontName="Helvetica-Bold",
            textColor=C_MED, alignment=TA_CENTER, leading=28)),
        Paragraph(f"<b>{len(low)}</b><br/><font size=8>Low Risk</font>",
            ParagraphStyle("l", fontSize=22, fontName="Helvetica-Bold",
            textColor=C_LOW, alignment=TA_CENTER, leading=28)),
        Paragraph(f"<b>{total}</b><br/><font size=8>Total Findings</font>",
            ParagraphStyle("t", fontSize=22, fontName="Helvetica-Bold",
            textColor=C_CYAN, alignment=TA_CENTER, leading=28)),
    ]]
    col_w = (W - 36*mm) / 4
    summary_table = Table(summary_data, colWidths=[col_w]*4)
    summary_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), C_LIGHT),
        ("TOPPADDING",    (0,0), (-1,-1), 10),
        ("BOTTOMPADDING", (0,0), (-1,-1), 10),
        ("BOX",           (0,0), (-1,-1), 0.5, C_BORDER),
        ("INNERGRID",     (0,0), (-1,-1), 0.5, C_BORDER),
        ("ALIGN",         (0,0), (-1,-1), "CENTER"),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ("ROUNDEDCORNERS",(0,0), (-1,-1), [4,4,4,4]),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 8*mm))

    # ── EXECUTIVE SUMMARY ──────────────────────────────────────
    story.append(Paragraph("Executive Summary", S["section"]))
    story.append(HRFlowable(width="100%", thickness=1, color=C_BORDER, spaceAfter=6))

    exec_text = (
        f"This report presents the results of an automated vulnerability assessment performed "
        f"on host <b>{host}</b> using VulnSense, an AI-assisted risk classification and "
        f"reporting platform. A total of <b>{total} findings</b> were identified across "
        f"network services, web endpoints, and host configuration checks. "
        f"The AI classifier (Random Forest, weighted F1 ≈ 0.78) assigned each finding a "
        f"risk label of High, Medium, or Low based on attack vector, complexity, privilege "
        f"requirements, service exposure, and impact dimensions — consistent with "
        f"CVSS v3 methodology and risk-based vulnerability management principles.<br/><br/>"
        f"<b>{len(high)} High-risk</b> findings were identified that pose an immediate threat "
        f"and should be remediated as a priority. "
        f"<b>{len(medium)} Medium-risk</b> findings require attention but have mitigating "
        f"factors. <b>{len(low)} Low-risk</b> findings represent hygiene-level weaknesses "
        f"to address as part of a baseline hardening effort."
    )
    story.append(Paragraph(exec_text, S["body"]))
    story.append(Spacer(1, 6*mm))

    # ── FINDINGS TABLE ─────────────────────────────────────────
    story.append(Paragraph("Findings Overview", S["section"]))
    story.append(HRFlowable(width="100%", thickness=1, color=C_BORDER, spaceAfter=6))

    table_header = ["Risk", "Port", "Service", "Type", "Confidence"]
    tdata = [table_header]
    for f in sorted(findings, key=lambda x: {"High":0,"Medium":1,"Low":2}.get(x.get("risk_label",""),3)):
        label = f.get("risk_label", "—")
        conf  = f"{round((f.get('confidence') or 0) * 100, 1)}%"
        warn  = " ⚠" if f.get("uncertain") else ""
        tdata.append([
            Paragraph(label, ParagraphStyle("rl", fontSize=8, fontName="Helvetica-Bold",
                textColor=_risk_color(label), alignment=TA_CENTER)),
            Paragraph(f"{f.get('port','—')}/{f.get('protocol','tcp')}",
                ParagraphStyle("pr", fontSize=8, fontName="Courier", alignment=TA_CENTER)),
            Paragraph((f.get("service") or "—").upper(),
                ParagraphStyle("sv", fontSize=8, fontName="Helvetica-Bold")),
            Paragraph(f.get("vuln_type","—").replace("_"," "),
                ParagraphStyle("vt", fontSize=8, fontName="Helvetica")),
            Paragraph(f"{conf}{warn}",
                ParagraphStyle("cf", fontSize=8, fontName="Courier", alignment=TA_CENTER)),
        ])

    cw = [22*mm, 22*mm, 30*mm, 55*mm, 25*mm]
    findings_table = Table(tdata, colWidths=cw, repeatRows=1)
    findings_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), C_DARK),
        ("TEXTCOLOR",     (0,0), (-1,0), C_WHITE),
        ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,0), 8),
        ("ALIGN",         (0,0), (-1,0), "CENTER"),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING",   (0,0), (-1,-1), 6),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [C_WHITE, C_LIGHT]),
        ("GRID",          (0,0), (-1,-1), 0.4, C_BORDER),
        ("ALIGN",         (1,1), (1,-1), "CENTER"),
        ("ALIGN",         (4,1), (4,-1), "CENTER"),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
    ]))
    story.append(findings_table)
    story.append(Spacer(1, 8*mm))

    # ── DETAILED FINDINGS ──────────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph("Detailed Findings", S["section"]))
    story.append(HRFlowable(width="100%", thickness=1, color=C_BORDER, spaceAfter=8))

    for idx, f in enumerate(sorted(findings, key=lambda x: {"High":0,"Medium":1,"Low":2}.get(x.get("risk_label",""),3))):
        label   = f.get("risk_label", "Unknown")
        service = (f.get("service") or "unknown").upper()
        port    = f.get("port", "—")
        proto   = f.get("protocol", "tcp")
        vtype   = (f.get("vuln_type") or "—").replace("_", " ")
        conf    = round((f.get("confidence") or 0) * 100, 1)
        explain = _strip_html(f.get("explanation") or "")
        detail  = f.get("detail") or ""
        banner  = f.get("banner") or ""
        cves    = f.get("cves") or []
        uncertain = f.get("uncertain", False)

        rc = _risk_color(label)

        # Finding header row
        hdr_data = [[
            Paragraph(f"#{idx+1}  {service} — Port {port}/{proto}",
                ParagraphStyle("fh", fontSize=10, fontName="Helvetica-Bold",
                textColor=C_WHITE, leading=14)),
            Paragraph(label,
                ParagraphStyle("fl", fontSize=10, fontName="Helvetica-Bold",
                textColor=rc, leading=14, alignment=TA_RIGHT)),
        ]]
        hdr_table = Table(hdr_data, colWidths=[(W-36*mm)*0.75, (W-36*mm)*0.25])
        hdr_table.setStyle(TableStyle([
            ("BACKGROUND", (0,0),(-1,-1), C_SURFACE),
            ("TOPPADDING", (0,0),(-1,-1), 7),
            ("BOTTOMPADDING",(0,0),(-1,-1), 7),
            ("LEFTPADDING",(0,0),(-1,-1), 10),
            ("RIGHTPADDING",(0,0),(-1,-1), 10),
            ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
        ]))

        # Meta row
        meta_items = [
            ("Vuln Type", vtype),
            ("Host", f.get("host","—")),
            ("Confidence", f"{conf}%{'  ⚠ Low confidence' if uncertain else ''}"),
            ("Encrypted", "Yes" if f.get("encrypted") else "No"),
        ]
        meta_text = "    ".join(f"<b>{k}:</b> {v}" for k, v in meta_items)

        body_items = []
        if detail:
            body_items.append(Paragraph(f"<b>Detail:</b> {detail}", S["body"]))
        if banner:
            body_items.append(Paragraph(f"<b>Banner:</b> <font name='Courier' size='8'>{banner[:120]}</font>", S["body"]))
        if explain:
            body_items.append(Paragraph(f"<b>Risk explanation:</b> {explain}", S["explanation"]))
        if cves:
            cve_links = ", ".join(
                f'<u><link href="https://nvd.nist.gov/vuln/detail/{c["id"]}">{c["id"]}</link></u>'
                for c in cves[:4]
            )
            body_items.append(Paragraph(f"<b>Related CVEs:</b> {cve_links}", S["body"]))
        if uncertain:
            body_items.append(Paragraph(
                "⚠ <b>Low confidence prediction</b> — manual review recommended. "
                "This finding sits near a classification boundary.",
                ParagraphStyle("warn", fontSize=8, fontName="Helvetica",
                    textColor=C_MED, leading=12)
            ))

        block = KeepTogether([
            hdr_table,
            Table([[Paragraph(meta_text, S["small"])]], colWidths=[W-36*mm],
                style=[("BACKGROUND",(0,0),(-1,-1),C_LIGHT),
                       ("TOPPADDING",(0,0),(-1,-1),5),
                       ("BOTTOMPADDING",(0,0),(-1,-1),5),
                       ("LEFTPADDING",(0,0),(-1,-1),10),
                       ("GRID",(0,0),(-1,-1),0.3,C_BORDER)]),
            Table([[item] for item in body_items] if body_items else [[Spacer(1,4)]],
                colWidths=[W-36*mm],
                style=[("TOPPADDING",(0,0),(-1,-1),4),
                       ("BOTTOMPADDING",(0,0),(-1,-1),3),
                       ("LEFTPADDING",(0,0),(-1,-1),10),
                       ("RIGHTPADDING",(0,0),(-1,-1),10),
                       ("BOX",(0,0),(-1,-1),0.3,C_BORDER)]),
            Spacer(1, 5*mm),
        ])
        story.append(block)

    # ── METHODOLOGY NOTE ───────────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph("Methodology & Limitations", S["section"]))
    story.append(HRFlowable(width="100%", thickness=1, color=C_BORDER, spaceAfter=6))

    method_text = (
        "VulnSense performs a limited set of automated checks within a controlled lab "
        "environment. The scanning pipeline consists of three modules: (1) a network port "
        "scanner using nmap or a socket-based fallback; (2) a web security checker that "
        "evaluates HTTP/HTTPS behaviour, security headers, and SSL configuration; and "
        "(3) a configuration checker that probes service-level misconfigurations such as "
        "anonymous FTP access, unauthenticated Redis, and default Samba shares.<br/><br/>"
        "Each finding is passed through a feature extraction pipeline and classified using "
        "a trained Random Forest classifier (200 estimators, class_weight=balanced). "
        "The model was trained on an 800-record synthetic dataset whose feature distribution "
        "reflects published NVD/CVSS data (Allodi &amp; Massacci, 2015). Labels were assigned "
        "using an expert-defined rubric inspired by CVSS v3 and risk-based vulnerability "
        "management (RBVM) principles.<br/><br/>"
        "<b>Limitations:</b> This system is a proof-of-concept for educational use. "
        "The dataset is synthetic; real-world performance may differ. Findings should be "
        "reviewed by a qualified security professional before acting on them. VulnSense "
        "is not a replacement for full vulnerability management platforms such as Tenable "
        "Nessus, Qualys, or OpenVAS."
    )
    story.append(Paragraph(method_text, S["body"]))
    story.append(Spacer(1, 6*mm))

    story.append(Paragraph("References", S["section"]))
    refs = [
        "Allodi, L. &amp; Massacci, F. (2015). Comparing Vulnerability Severity and Exploits Using Case-Control Studies. <i>Computers &amp; Security</i>, 53, 18–30.",
        "FIRST (2023). Common Vulnerability Scoring System v4.0. https://www.first.org/cvss/",
        "Mell, P., Scarfone, K., &amp; Romanosky, S. (2007). A Complete Guide to the Common Vulnerability Scoring System Version 2.0. NIST.",
        "Snyk (2025). Risk-Based Vulnerability Management. https://snyk.io/articles/risk-based-vulnerability-management/",
    ]
    for r in refs:
        story.append(Paragraph(f"• {r}", S["small"]))
        story.append(Spacer(1, 2*mm))

    # ── Footer note ────────────────────────────────────────────
    story.append(Spacer(1, 8*mm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER))
    story.append(Paragraph(
        f"VulnSense Security Report  |  CST3590 Final Year Project  |  "
        f"Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}  |  "
        f"FOR EDUCATIONAL USE ONLY",
        ParagraphStyle("foot", fontSize=7, fontName="Helvetica",
            textColor=C_MUTED, alignment=TA_CENTER, leading=10, spaceBefore=4)
    ))

    doc.build(story)
    return buf.getvalue()

from __future__ import annotations

import io
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, HRFlowable
)


# ── Thai font (fallback to Helvetica if not available) ──────────────────────
_THAI_FONT = "Helvetica"
_THAI_FONT_BOLD = "Helvetica-Bold"

try:
    import os
    _font_candidates = [
        r"C:\Windows\Fonts\THSarabunNew.ttf",
        r"C:\Windows\Fonts\THSarabunNew Bold.ttf",
        r"C:\Windows\Fonts\Tahoma.ttf",
    ]
    for _path in _font_candidates:
        if os.path.exists(_path):
            pdfmetrics.registerFont(TTFont("ThaiFont", _path))
            _THAI_FONT = "ThaiFont"
            _THAI_FONT_BOLD = "ThaiFont"
            break
except Exception:
    pass


def _safe(value: Any, default: str = "-") -> str:
    if value is None or value == "" or value == 0:
        return default
    return str(value)


def _checklist_status(value: Any) -> str:
    if value is True or value == "running" or value == "installed":
        return "✓"
    if value is False or value == "stopped" or value == "not_installed":
        return "✗"
    if value == "outdated":
        return "⚠ outdated"
    return _safe(value)


# Keywords ที่บ่งชี้ว่าเป็น runtime/driver/SDK — ตัดทิ้ง
_SKIP_KEYWORDS = [
    "visual c++", "redistributable", "runtime", "webview2",
    "sdk", "winrt", "extension sdk", "wdk", "kits ",
    "driver", "intel(r) me", "intel(r) management",
    "realtek", "chipset", "crt ", "universal crt",
    "vs script", "vs_", "vcpp_", "winapp", "winsdk",
    "windows sdk", "windows desktop extension", "windows iot",
    "windows mobile extension", "windows team extension",
    "windows app certification", "windows subsystem",
    "diagnost", "application verifier", "msi development",
    "click-to-run extensibility", "click-to-run localization",
    "setup configuration", "setup wmi", "installer",
    "python 3." , "python launcher",  # python sub-components
    "node.js",  # keep as notable but not licensed
    "uv", "vcpp",
]

# Keywords ที่ถือว่ามี license จริง
_LICENSED_KEYWORDS = [
    "microsoft office", "office 20",
    "adobe", "acrobat",
    "autocad", "autodesk",
    "cortex xdr", "crowdstrike", "eset", "sophos", "mcafee", "symantec", "kaspersky", "trend micro",
    "sap", "crystal reports",
    "zoom", "teams",
    "softpro",
    "milestone", "xprotect",
    "tightvnc", "anydesk", "teamviewer",
    "winrar",
    "visual studio 20", "visual studio build", "visual studio code",
    "sql server", "oracle",
    "windows 10", "windows 11",
    "smart weight",
    "laragon", "dbeaver",
    "telegram", "line",
    "vlc",
    "notepad++",
    "git ", "git$",
    "cmake",
    "ollama",
    "windsurf",
    "7-zip",
    "python 3",  # top-level Python only
    "node.js",
    "zoom workplace",
]


def _is_licensed(name: str) -> bool:
    n = name.lower()
    if any(k in n for k in _SKIP_KEYWORDS):
        # Exception: keep top-level Python
        if n.startswith("python 3") and not any(x in n for x in ["add to path", "core", "dev", "doc", "exec", "lib", "tcl", "test", "util", "pip", "standard"]):
            return True
        return False
    return any(k in n for k in _LICENSED_KEYWORDS)


# Keywords ที่ถือว่า "สำคัญ" ให้ highlight
_NOTABLE_KEYWORDS = [
    "office", "antivirus", "cortex", "crowdstrike", "defender", "eset", "sophos",
    "vpn", "anydesk", "teamviewer", "vnc", "remote",
    "chrome", "firefox", "edge",
    "adobe", "acrobat",
    "python", "git", "docker", "vscode", "visual studio",
    "zoom", "teams", "line",
    "7-zip", "winrar", "utorrent", "bittorrent",
    "laragon", "xampp", "wamp",
]


def _is_notable(name: str) -> bool:
    n = name.lower()
    return any(k in n for k in _NOTABLE_KEYWORDS)


def _format_software_list(installed: List[str], policy: Dict[str, Any]) -> Dict[str, Any]:
    installed_lower = {s.lower(): s for s in installed}
    required = policy.get("required") or []
    forbidden = policy.get("forbidden") or []

    policy_rows = []
    for req in required:
        found = any(req.lower() in k for k in installed_lower)
        policy_rows.append((req, "✓ ติดตั้งแล้ว" if found else "✗ ไม่พบ", "required"))
    for forb in forbidden:
        found = any(forb.lower() in k for k in installed_lower)
        if found:
            policy_rows.append((forb, "⚠ พบ (ห้ามติดตั้ง)", "forbidden"))

    licensed = [s for s in installed if _is_licensed(s)]
    notable = [s for s in installed if _is_notable(s) and s not in licensed]
    all_sw = ", ".join(installed)

    return {
        "policy_rows": policy_rows,
        "licensed": licensed,
        "notable": notable,
        "all_software": all_sw,
        "count": len(installed),
    }


def generate_pdf(payload: Dict[str, Any], analysis: Dict[str, Any]) -> bytes:
    asset = payload.get("asset") or {}
    checklist = payload.get("checklist") or {}
    metrics = payload.get("metrics") or {}
    installed = payload.get("installed_software") or []
    policy = payload.get("software_policy") or {}

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=15*mm, rightMargin=15*mm,
        topMargin=15*mm, bottomMargin=15*mm,
    )

    styles = getSampleStyleSheet()
    normal = ParagraphStyle("n", fontName=_THAI_FONT, fontSize=9, leading=13)
    bold = ParagraphStyle("b", fontName=_THAI_FONT_BOLD, fontSize=9, leading=13)
    title_style = ParagraphStyle("t", fontName=_THAI_FONT_BOLD, fontSize=11, leading=16, alignment=1)
    section_style = ParagraphStyle("s", fontName=_THAI_FONT_BOLD, fontSize=10, leading=14,
                                   backColor=colors.HexColor("#D9E1F2"), borderPadding=4)

    W = 180*mm
    col1, col2 = W * 0.25, W * 0.25
    col3, col4 = W * 0.25, W * 0.25

    def _tbl(data, col_widths, style_cmds=None):
        base = [
            ("FONTNAME", (0, 0), (-1, -1), _THAI_FONT),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ROWBACKGROUND", (0, 0), (-1, -1), [colors.white, colors.HexColor("#F7F7F7")]),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]
        if style_cmds:
            base += style_cmds
        t = Table(data, colWidths=col_widths)
        t.setStyle(TableStyle(base))
        return t

    story = []

    # ── Header ───────────────────────────────────────────────────────────────
    header_data = [[
        Paragraph("<b>ตรวจสอบเครื่องคอมพิวเตอร์และอุปกรณ์ IT</b>", title_style),
        Paragraph(f"No. KKS-FP-PD02-06\nDev. 1A-14/08/60\nPage 1 / 1", normal),
    ]]
    story.append(_tbl(header_data, [W * 0.7, W * 0.3], [
        ("FONTNAME", (0, 0), (-1, -1), _THAI_FONT_BOLD),
        ("ALIGN", (1, 0), (1, 0), "RIGHT"),
        ("BOX", (0, 0), (-1, -1), 1, colors.black),
        ("INNERGRID", (0, 0), (-1, -1), 0, colors.white),
    ]))
    story.append(Spacer(1, 4*mm))

    # ── Section 1 Header ─────────────────────────────────────────────────────
    story.append(Paragraph("ส่วนที่ 1  รายละเอียดเครื่องคอมพิวเตอร์", section_style))
    story.append(Spacer(1, 2*mm))

    # resolve disk info
    disk_total = _safe(asset.get("disk_total_gb"), "-")
    disk_free = _safe(asset.get("disk_free_gb"), "-")
    disk_str = f"{disk_total} GB (ว่าง {disk_free} GB)" if disk_total != "-" else "-"
    ram_str = f"{_safe(asset.get('ram_gb'), '-')} GB"
    bios = _safe(asset.get("bios_date"), "-")
    collected = _safe(asset.get("last_seen"), "-")[:10]
    compliance = analysis.get("compliance_score", "-")
    status_color = {"healthy": "✓ ปกติ", "warning": "⚠ ควรตรวจสอบ", "critical": "✗ วิกฤต"}.get(
        analysis.get("status", ""), "-"
    )

    part1 = [
        ["IT Code :", "-",                          "ชื่อเครื่อง / รุ่น :", _safe(asset.get("hostname"))],
        ["S/N :", "-",                              "Workgroup :", "-"],
        ["Bios Date :", bios,                       "วันที่เก็บข้อมูล :", collected],
        ["ประเภทเครื่อง :", "Desktop/Laptop",       "Asset Code :", "-"],
        ["แผนก :", _safe(asset.get("role")),        "IP Address :", _safe(asset.get("ip"))],
        ["CPU :", _safe(asset.get("cpu")),          "OS :", _safe(asset.get("os"))],
        ["RAM :", ram_str,                          "Harddisk :", disk_str],
        ["Network Segment :", _safe(asset.get("network_segment")), "Compliance Score :", f"{compliance}/100  {status_color}"],
    ]

    story.append(_tbl(part1, [col1, col2, col3, col4], [
        ("FONTNAME", (0, 0), (0, -1), _THAI_FONT_BOLD),
        ("FONTNAME", (2, 0), (2, -1), _THAI_FONT_BOLD),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EEF2FF")),
        ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#EEF2FF")),
    ]))
    story.append(Spacer(1, 4*mm))

    # ── Section 2 Header ─────────────────────────────────────────────────────
    story.append(Paragraph("ส่วนที่ 2  รายการที่ตรวจสอบ", section_style))
    story.append(Spacer(1, 2*mm))

    def _status_color_cell(val: str):
        if val.startswith("✓"):
            return colors.HexColor("#E2EFDA")
        if val.startswith("✗"):
            return colors.HexColor("#FCE4D6")
        if val.startswith("⚠"):
            return colors.HexColor("#FFF2CC")
        return colors.white

    checklist_rows = [
        ["รายการตรวจสอบ", "ผลการตรวจสอบ", "หมายเหตุ"],
        ["ทำความสะอาดภายในเครื่อง", "-", "ตรวจสอบโดย IT"],
        ["ตรวจสอบโปรแกรมไม่มีลิขสิทธิ์", "-", "ดูส่วน Software ด้านล่าง"],
        ["Disk Cleanup & Defragment",
            "✓" if (metrics.get("disk_usage_percent") or 0) < 85 else "✗ disk เกิน 85%",
            f"ใช้งาน {_safe(metrics.get('disk_usage_percent'), '?')}%"],
        ["Update Antivirus",
            _checklist_status(checklist.get("antivirus")),
            _safe(checklist.get("antivirus"))],
        ["VNC Status",
            _checklist_status(checklist.get("vnc_status")),
            _safe(checklist.get("vnc_status"))],
        ["Remote Desktop (RDP)", "-", "ตรวจสอบจาก scan"],
        ["สิทธิ์ Administrators ของ User",
            "✗ มีสิทธิ์ Admin" if checklist.get("admin_rights") else "✓ ไม่มีสิทธิ์ Admin",
            ""],
        ["สิทธิ์การใช้งาน Internet",
            "✓ ใช้งานได้" if checklist.get("internet_access") else "✗ ใช้งานไม่ได้",
            ""],
        ["Service WMI",
            _checklist_status(checklist.get("wmi_service")),
            _safe(checklist.get("wmi_service"))],
        ["CPU Usage", f"{_safe(metrics.get('cpu_usage'), '?')}%",
            "⚠ สูง" if (metrics.get("cpu_usage") or 0) > 75 else "ปกติ"],
        ["RAM Usage", f"{_safe(metrics.get('ram_usage'), '?')}%",
            "⚠ สูง" if (metrics.get("ram_usage") or 0) > 80 else "ปกติ"],
    ]

    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#D9E1F2")),
        ("FONTNAME", (0, 0), (-1, 0), _THAI_FONT_BOLD),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
    ]
    # Color result cells
    for i, row in enumerate(checklist_rows[1:], 1):
        val = row[1]
        bg = _status_color_cell(val)
        style_cmds.append(("BACKGROUND", (1, i), (1, i), bg))

    story.append(_tbl(checklist_rows, [W * 0.45, W * 0.25, W * 0.30], style_cmds))
    story.append(Spacer(1, 4*mm))

    # ── Section 3: Software ───────────────────────────────────────────────────
    story.append(Paragraph("ส่วนที่ 3  Software ที่ติดตั้ง (ตาม Policy)", section_style))
    story.append(Spacer(1, 2*mm))

    sw_data = _format_software_list(installed, policy)
    policy_rows = sw_data["policy_rows"]
    licensed = sw_data["licensed"]
    notable = sw_data["notable"]
    all_software = sw_data["all_software"]
    sw_count = sw_data["count"]

    # 3a: Policy compliance table
    if policy_rows:
        sw_table_data = [["Software (Policy)", "สถานะ", "ประเภท"]]
        sw_style = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#D9E1F2")),
            ("FONTNAME", (0, 0), (-1, 0), _THAI_FONT_BOLD),
            ("ALIGN", (1, 0), (1, -1), "CENTER"),
            ("ALIGN", (2, 0), (2, -1), "CENTER"),
        ]
        for i, (name, status, kind) in enumerate(policy_rows, 1):
            sw_table_data.append([name, status, kind])
            sw_style.append(("BACKGROUND", (1, i), (1, i), _status_color_cell(status)))
        story.append(_tbl(sw_table_data, [W * 0.55, W * 0.25, W * 0.20], sw_style))
        story.append(Spacer(1, 3*mm))

    # 3b: Licensed software table
    if licensed:
        lic_data = [["Licensed / Commercial Software", "เวอร์ชัน"]]
        lic_style = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#D9E1F2")),
            ("FONTNAME", (0, 0), (-1, 0), _THAI_FONT_BOLD),
        ]
        for name in licensed:
            # extract version from name if present
            import re
            ver_match = re.search(r"(\d[\d\.]+)", name)
            ver = ver_match.group(1) if ver_match else "-"
            lic_data.append([name, ver])
        story.append(_tbl(lic_data, [W * 0.75, W * 0.25], lic_style))
        story.append(Spacer(1, 3*mm))
    else:
        story.append(Paragraph("ไม่พบ Licensed Software", normal))
        story.append(Spacer(1, 3*mm))

    # 3c: All installed (comma-separated, small font)
    story.append(Paragraph(f"<b>Software ทั้งหมด ({sw_count} รายการ):</b>", bold))
    story.append(Paragraph(
        all_software or "-",
        ParagraphStyle("sw_all", fontName=_THAI_FONT, fontSize=7, leading=11, textColor=colors.HexColor("#444444"))
    ))

    story.append(Spacer(1, 4*mm))

    # ── Section 4: Issues from Analysis ──────────────────────────────────────
    issues = analysis.get("issues") or []
    if issues:
        story.append(Paragraph("ส่วนที่ 4  ปัญหาที่ตรวจพบ", section_style))
        story.append(Spacer(1, 2*mm))
        issue_data = [["ประเภท", "ความรุนแรง", "รายละเอียด", "คำแนะนำ"]]
        issue_style = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#D9E1F2")),
            ("FONTNAME", (0, 0), (-1, 0), _THAI_FONT_BOLD),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
        ]
        sev_colors = {
            "critical": colors.HexColor("#FCE4D6"),
            "high": colors.HexColor("#FFF2CC"),
            "medium": colors.HexColor("#EDEDED"),
            "low": colors.white,
        }
        for i, issue in enumerate(issues, 1):
            sev = issue.get("severity", "low")
            issue_data.append([
                issue.get("type", "-"),
                sev,
                Paragraph(issue.get("description", "-"), ParagraphStyle("i", fontName=_THAI_FONT, fontSize=8)),
                Paragraph(issue.get("recommendation", "-"), ParagraphStyle("r", fontName=_THAI_FONT, fontSize=8)),
            ])
            issue_style.append(("BACKGROUND", (0, i), (-1, i), sev_colors.get(sev, colors.white)))
        story.append(_tbl(issue_data, [W*0.12, W*0.12, W*0.40, W*0.36], issue_style))
        story.append(Spacer(1, 4*mm))

    # ── Footer / Signature ────────────────────────────────────────────────────
    story.append(HRFlowable(width=W, thickness=0.5, color=colors.grey))
    story.append(Spacer(1, 3*mm))
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    footer_data = [[
        Paragraph(f"ผู้ตรวจสอบ : ____________________\nวันที่ : ____________________", normal),
        Paragraph(f"ผู้อนุมัติ : ____________________\nวันที่ : ____________________", normal),
        Paragraph(f"Generated by KSL IT Ops\n{generated_at}", normal),
    ]]
    story.append(_tbl(footer_data, [W/3, W/3, W/3], [
        ("INNERGRID", (0, 0), (-1, -1), 0, colors.white),
        ("BOX", (0, 0), (-1, -1), 0, colors.white),
    ]))

    doc.build(story)
    return buf.getvalue()

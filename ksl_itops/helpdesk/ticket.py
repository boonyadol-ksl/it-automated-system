from __future__ import annotations

from typing import Any, Dict, List, Optional


CATEGORIES = [
    "hardware",
    "software",
    "network",
    "account",
    "printer",
    "other",
]

PRIORITIES = ["low", "medium", "high", "critical"]

STATUS_FLOW = {
    "open":        ["assigned", "closed"],
    "assigned":    ["in_progress", "open", "closed"],
    "in_progress": ["resolved", "assigned"],
    "resolved":    ["closed", "in_progress"],
    "closed":      [],
}


def enrich_ticket(ticket: Dict[str, Any], asset_payload: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Attach machine context to ticket automatically."""
    if not asset_payload:
        return ticket

    asset = asset_payload.get("asset") or {}
    checklist = asset_payload.get("checklist") or {}
    metrics = asset_payload.get("metrics") or {}

    ticket["machine_context"] = {
        "os": asset.get("os"),
        "cpu": asset.get("cpu"),
        "ram_gb": asset.get("ram_gb"),
        "disk_free_gb": asset.get("disk_free_gb"),
        "disk_total_gb": asset.get("disk_total_gb"),
        "role": asset.get("role"),
        "network_segment": asset.get("network_segment"),
        "antivirus": checklist.get("antivirus"),
        "admin_rights": checklist.get("admin_rights"),
        "cpu_usage": metrics.get("cpu_usage"),
        "ram_usage": metrics.get("ram_usage"),
        "disk_usage_percent": metrics.get("disk_usage_percent"),
        "last_seen": asset.get("last_seen"),
    }
    return ticket


def auto_suggest_actions(ticket: Dict[str, Any]) -> List[str]:
    """Suggest IT actions based on ticket category + machine context."""
    suggestions = []
    category = ticket.get("category") or ""
    ctx = ticket.get("machine_context") or {}

    if category == "hardware":
        if (ctx.get("ram_gb") or 0) < 4:
            suggestions.append("RAM ต่ำกว่า 4GB — พิจารณาอัปเกรด")
        if (ctx.get("disk_usage_percent") or 0) > 85:
            suggestions.append("Disk เกือบเต็ม — สั่ง clear_temp")

    if category == "software":
        suggestions.append("ตรวจ software ที่ติดตั้ง — สั่ง check_software")
        if ctx.get("antivirus") in ("not_installed", "outdated"):
            suggestions.append("Antivirus มีปัญหา — ตรวจสอบด่วน")

    if category == "network":
        suggestions.append("ตรวจ network segment และ IP ของเครื่อง")

    if (ctx.get("cpu_usage") or 0) > 80:
        suggestions.append("CPU สูงผิดปกติ — สั่ง check_disk หรือ kill_process")

    if (ctx.get("disk_usage_percent") or 0) > 90:
        suggestions.append("Disk วิกฤต — สั่ง clear_temp ทันที")

    return suggestions

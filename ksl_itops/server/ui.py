from __future__ import annotations

import os
from typing import Any, Dict

import yaml
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from ..analysis.engine import analyze_payload
from ..report.generator import _format_software_list, _is_licensed

_TMPL_DIR = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=_TMPL_DIR)

_CONFIG_DIR = "config"


def _read_file(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return ""


def _write_file(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def _parse_env(text: str) -> Dict[str, str]:
    result = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            k, v = line.split("=", 1)
            result[k.strip()] = v.strip()
    return result


def _flatten_agent_config(raw: Dict[str, Any]) -> Dict[str, str]:
    flat = {}
    for section, values in raw.items():
        if isinstance(values, dict):
            for k, v in values.items():
                flat[f"{section}.{k}"] = str(v) if v is not None else ""
        else:
            flat[section] = str(values)
    return flat


def create_ui_router(store: Any, settings: Any) -> APIRouter:
    router = APIRouter()

    # ── Dashboard ─────────────────────────────────────────────────────────────
    @router.get("/", response_class=HTMLResponse)
    def dashboard(request: Request):
        segments = store.list_segments()
        all_tickets = store.list_tickets()
        open_tickets = sum(1 for t in all_tickets if t["status"] in ("open", "assigned", "in_progress"))
        recent_tickets = [t for t in all_tickets if t["status"] != "closed"][:5]
        total_machines = sum(s["total_machines"] for s in segments)

        # Scan summary per segment
        all_scan = store.list_scan_results()
        scan_by_seg: dict = {}
        for r in all_scan:
            seg = r["network_segment"] or "unknown"
            if seg not in scan_by_seg:
                scan_by_seg[seg] = {"online": 0, "offline": 0, "no_hostname": 0, "has_agent": 0}
            if r["status"] == "online":
                scan_by_seg[seg]["online"] += 1
            elif r["status"] == "no_hostname":
                scan_by_seg[seg]["no_hostname"] += 1
            else:
                scan_by_seg[seg]["offline"] += 1

        # Count machines with agent per segment
        for seg_data in segments:
            seg_name = seg_data["network_segment"]
            scan_by_seg.setdefault(seg_name, {"online": 0, "offline": 0, "no_hostname": 0, "has_agent": 0})
            scan_by_seg[seg_name]["has_agent"] = seg_data["total_machines"]

        online_machines = sum(v["online"] for v in scan_by_seg.values())

        # Critical machines
        critical = 0
        for seg_data in segments:
            for p in store.get_latest_payloads_by_segment(seg_data["network_segment"]):
                if analyze_payload(p)["status"] == "critical":
                    critical += 1

        # Merge segments + scan info
        seg_summary = []
        all_seg_names = sorted(set(
            [s["network_segment"] for s in segments] + list(scan_by_seg.keys())
        ))
        for name in all_seg_names:
            sc = scan_by_seg.get(name, {"online": 0, "offline": 0, "no_hostname": 0, "has_agent": 0})
            agent_count = next((s["total_machines"] for s in segments if s["network_segment"] == name), 0)
            seg_summary.append({
                "network_segment": name,
                "online": sc["online"],
                "offline": sc["offline"],
                "no_hostname": sc["no_hostname"],
                "has_agent": agent_count,
                "total_scan": sc["online"] + sc["offline"] + sc["no_hostname"],
            })

        return templates.TemplateResponse("dashboard.html", {
            "request": request,
            "seg_summary": seg_summary,
            "total_machines": total_machines,
            "online_machines": online_machines,
            "open_tickets": open_tickets,
            "critical_machines": critical,
            "recent_tickets": recent_tickets,
        })

    # ── Machines List ─────────────────────────────────────────────────────────
    @router.get("/ui/machines", response_class=HTMLResponse)
    def machines_list(request: Request, segment: str = ""):
        segments_data = store.list_segments()
        segment_names = [s["network_segment"] for s in segments_data]

        # เครื่องที่มี agent data
        agent_machines: Dict[str, Any] = {}
        segs_to_query = [segment] if segment else segment_names
        for seg in segs_to_query:
            for p in store.get_latest_payloads_by_segment(seg):
                asset = p.get("asset") or {}
                analysis = analyze_payload(p)
                hn = asset.get("hostname", "")
                agent_machines[hn] = {
                    "hostname": hn,
                    "ip": asset.get("ip", ""),
                    "segment": asset.get("network_segment", ""),
                    "role": asset.get("role", ""),
                    "os": asset.get("os", ""),
                    "compliance_score": analysis["compliance_score"],
                    "status": analysis["status"],
                    "last_seen": asset.get("last_seen", ""),
                    "has_agent": True,
                }

        # เครื่องจาก scan (online + มี NetBIOS = Windows PC)
        scan_results = store.list_scan_results(segment=segment or None, status="online")
        for r in scan_results:
            hn = r["hostname"]
            if not hn or hn in agent_machines:
                continue
            agent_machines[hn] = {
                "hostname": hn,
                "ip": r["ip"],
                "segment": r["network_segment"],
                "role": "-",
                "os": "-",
                "compliance_score": None,
                "status": "scan_only",
                "last_seen": r["scanned_at"],
                "has_agent": False,
            }

        all_segment_names = sorted(
            set(segment_names) | {r["network_segment"] for r in store.list_scan_results(status="online") if r["hostname"]}
        )
        machines = sorted(agent_machines.values(), key=lambda m: m["hostname"])

        return templates.TemplateResponse("machines.html", {
            "request": request,
            "machines": machines,
            "segments": all_segment_names,
            "selected_segment": segment,
        })

    # ── Machine Detail ────────────────────────────────────────────────────────
    @router.get("/ui/machines/{hostname}", response_class=HTMLResponse)
    def machine_detail(request: Request, hostname: str):
        payload = store.get_latest_by_hostname(hostname)

        if not payload:
            scan_list = store.list_scan_results()
            scan = next((r for r in scan_list if r["hostname"].upper() == hostname.upper()), None)
            if not scan:
                return HTMLResponse(f"<h1 style='font-family:sans-serif;padding:2rem'>Not Found: {hostname}</h1>", status_code=404)
            return templates.TemplateResponse("machine_scan_only.html", {
                "request": request,
                "hostname": scan["hostname"],
                "scan": scan,
                "wmi": store.get_latest_wmi_snapshot(scan["hostname"]),
                "api_key": settings.api_key,
            })

        analysis = analyze_payload(payload)
        asset = payload.get("asset") or {}
        checklist = payload.get("checklist") or {}
        metrics = payload.get("metrics") or {}
        installed = payload.get("installed_software") or []
        licensed = [s for s in installed if _is_licensed(s)]

        return templates.TemplateResponse("machine_detail.html", {
            "request": request,
            "hostname": hostname,
            "asset": asset,
            "checklist": checklist,
            "metrics": metrics,
            "analysis": analysis,
            "licensed_software": licensed,
            "api_key": settings.api_key,
        })

    @router.get("/ui/machines/{hostname}/commands", response_class=HTMLResponse)
    def machine_commands(request: Request, hostname: str):
        commands = store.list_commands(hostname=hostname)[:10]
        return templates.TemplateResponse("partials/commands.html", {
            "request": request,
            "commands": commands,
        })

    # ── Tickets ───────────────────────────────────────────────────────────────
    @router.get("/ui/tickets", response_class=HTMLResponse)
    def tickets_list(request: Request, status: str = ""):
        tickets = store.list_tickets(status=status or None)
        all_tickets = store.list_tickets()
        summary_data = {"by_status": {"open": 0, "assigned": 0, "in_progress": 0, "resolved": 0, "closed": 0},
                        "by_priority": {"low": 0, "medium": 0, "high": 0, "critical": 0}}
        for t in all_tickets:
            summary_data["by_status"][t["status"]] = summary_data["by_status"].get(t["status"], 0) + 1
            summary_data["by_priority"][t["priority"]] = summary_data["by_priority"].get(t["priority"], 0) + 1

        return templates.TemplateResponse("tickets.html", {
            "request": request,
            "tickets": tickets,
            "summary": summary_data,
            "selected_status": status,
        })

    @router.get("/ui/tickets/{ticket_id}", response_class=HTMLResponse)
    def ticket_detail(request: Request, ticket_id: int):
        ticket = store.get_ticket(ticket_id)
        if not ticket:
            return HTMLResponse("<h1>Not Found</h1>", status_code=404)
        ticket["notes"] = store.get_ticket_notes(ticket_id)
        return templates.TemplateResponse("ticket_detail.html", {
            "request": request,
            "ticket": ticket,
            "api_key": settings.api_key,
        })

    # ── Scan ──────────────────────────────────────────────────────────────────
    @router.get("/ui/scan", response_class=HTMLResponse)
    def scan_page(request: Request):
        # Default: show only Windows PCs (online = has NetBIOS + SMB)
        results = store.list_scan_results(status="online")
        all_results = store.list_scan_results()
        summary: dict = {}
        for r in all_results:
            seg = r["network_segment"] or "unknown"
            if seg not in summary:
                summary[seg] = {"network_segment": seg, "total": 0, "online": 0, "offline": 0, "no_hostname": 0, "has_rdp": 0, "has_vnc": 0}
            summary[seg]["total"] += 1
            if r["status"] == "online":
                summary[seg]["online"] += 1
                if 3389 in r["open_ports"]: summary[seg]["has_rdp"] += 1
                if 5900 in r["open_ports"]: summary[seg]["has_vnc"] += 1
            elif r["status"] == "no_hostname":
                summary[seg]["no_hostname"] += 1
            else:
                summary[seg]["offline"] += 1

        return templates.TemplateResponse("scan.html", {
            "request": request,
            "results": results,
            "summary": list(summary.values()),
            "api_key": settings.api_key,
        })

    # ── Settings ──────────────────────────────────────────────────────────────
    @router.get("/ui/settings", response_class=HTMLResponse)
    def settings_page(request: Request):
        server_env = _parse_env(_read_file(f"{_CONFIG_DIR}/server.env"))
        agent_raw = yaml.safe_load(_read_file(f"{_CONFIG_DIR}/agent.yml")) or {}
        agent_flat = _flatten_agent_config(agent_raw)
        policies_raw_text = _read_file(f"{_CONFIG_DIR}/policies.yml")
        policies_data = yaml.safe_load(policies_raw_text) or {}
        segments_raw_text = _read_file(f"{_CONFIG_DIR}/network_segments.yml")

        return templates.TemplateResponse("settings.html", {
            "request": request,
            "server_config": server_env,
            "agent_config": agent_flat,
            "policies": policies_data.get("roles", {}),
            "policies_raw": policies_raw_text,
            "segments_raw": segments_raw_text,
        })

    @router.post("/ui/settings/save/server")
    async def save_server(request: Request):
        data = await request.json()
        lines = [f"{k}={v}" for k, v in data.items()]
        _write_file(f"{_CONFIG_DIR}/server.env", "\n".join(lines) + "\n")
        return JSONResponse({"status": "ok"})

    @router.post("/ui/settings/save/agent")
    async def save_agent(request: Request):
        data = await request.json()
        # rebuild nested yaml
        nested: Dict[str, Any] = {}
        for key, val in data.items():
            if "." in key:
                section, k = key.split(".", 1)
                nested.setdefault(section, {})[k] = val
            else:
                nested[key] = val
        _write_file(f"{_CONFIG_DIR}/agent.yml", yaml.dump(nested, allow_unicode=True, default_flow_style=False))
        return JSONResponse({"status": "ok"})

    @router.post("/ui/settings/save/policies")
    async def save_policies(request: Request):
        data = await request.json()
        _write_file(f"{_CONFIG_DIR}/policies.yml", data.get("yaml", ""))
        return JSONResponse({"status": "ok"})

    @router.post("/ui/settings/save/segments")
    async def save_segments(request: Request):
        data = await request.json()
        _write_file(f"{_CONFIG_DIR}/network_segments.yml", data.get("yaml", ""))
        return JSONResponse({"status": "ok"})

    return router

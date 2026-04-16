from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from ..analysis.engine import analyze_payload, analyze_segment
from ..helpdesk.ticket import enrich_ticket, auto_suggest_actions, STATUS_FLOW
from ..report.generator import generate_pdf
from ..scanner.wmi_collector import collect_remote
from ..scanner.scanner import scan_segments
from .ui import create_ui_router
from .config import ServerSettings
from .db import SqliteStore
from .security import require_api_key

VALID_ACTIONS = {
    "clear_temp",
    "check_software",
    "check_disk",
    "check_antivirus",
    "kill_process",
    "restart_service",
}


class IngestRequest(BaseModel):
    payload: Dict[str, Any]


class TicketCreateRequest(BaseModel):
    title: str
    description: str
    category: str = "other"
    priority: str = "medium"
    reporter_name: str
    reporter_email: Optional[str] = None
    hostname: Optional[str] = None   # ถ้าระบุ จะดึงข้อมูลเครื่องมาแนบอัตโนมัติ


class TicketUpdateRequest(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    priority: Optional[str] = None
    status: Optional[str] = None
    assigned_to: Optional[str] = None


class NoteRequest(BaseModel):
    author: str
    note: str


class WmiCollectRequest(BaseModel):
    ip: str
    user: str
    password: str


class CommandRequest(BaseModel):
    action: str
    params: Dict[str, Any] = {}


class CommandResultRequest(BaseModel):
    success: bool
    result: Dict[str, Any] = {}


def create_app(settings: ServerSettings) -> FastAPI:
    app = FastAPI(title="KSL IT Ops API", version="0.2.0")
    store = SqliteStore(settings.database_url)

    # Mount UI
    ui_router = create_ui_router(store, settings)
    app.include_router(ui_router)

    import os
    static_dir = os.path.join(os.path.dirname(__file__), "static")
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

    def _auth(x_api_key: str | None = Header(default=None)) -> None:
        require_api_key(settings.api_key, x_api_key)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    # ── Ingest ──────────────────────────────────────────────────────────────
    @app.post("/api/v1/ingest", dependencies=[Depends(_auth)])
    def ingest(req: IngestRequest) -> dict[str, str]:
        store.insert_payload(req.payload)
        return {"status": "accepted"}

    # ── Segments ─────────────────────────────────────────────────────────────
    @app.get("/api/v1/segments")
    def segments() -> list[dict[str, Any]]:
        return store.list_segments()

    @app.get("/api/v1/segment/{segment}/machines")
    def segment_machines(segment: str) -> list[dict[str, Any]]:
        return store.list_machines_by_segment(segment)

    @app.get("/api/v1/segment/{segment}/analyze")
    def segment_analyze(segment: str) -> dict[str, Any]:
        payloads = store.get_latest_payloads_by_segment(segment)
        if not payloads:
            raise HTTPException(status_code=404, detail=f"No data for segment: {segment}")
        return analyze_segment(payloads)

    # ── Machine ───────────────────────────────────────────────────────────────
    @app.get("/api/v1/machine/{hostname}/latest")
    def machine_latest(hostname: str) -> dict[str, Any]:
        latest = store.get_latest_by_hostname(hostname)
        if latest is None:
            raise HTTPException(status_code=404, detail=f"No data for hostname: {hostname}")
        return {"hostname": hostname, "latest": latest}

    @app.get("/api/v1/machine/{hostname}/analyze")
    def machine_analyze(hostname: str) -> dict[str, Any]:
        latest = store.get_latest_by_hostname(hostname)
        if latest is None:
            raise HTTPException(status_code=404, detail=f"No data for hostname: {hostname}")
        return analyze_payload(latest)

    @app.post("/api/v1/machine/{hostname}/wmi-collect", dependencies=[Depends(_auth)])
    def wmi_collect(hostname: str, req: WmiCollectRequest) -> dict[str, Any]:
        data = collect_remote(req.ip, hostname, req.user, req.password)
        if not data or data.get("error"):
            raise HTTPException(status_code=502, detail=f"WMI error: {(data or {}).get('error', 'unknown')}")
        store.save_wmi_snapshot(hostname, req.ip, data)
        return {"status": "collected", "hostname": hostname, "data": data}

    @app.get("/api/v1/machine/{hostname}/wmi-snapshot")
    def wmi_snapshot(hostname: str) -> dict[str, Any]:
        snap = store.get_latest_wmi_snapshot(hostname)
        if not snap:
            raise HTTPException(status_code=404, detail=f"No WMI snapshot for: {hostname}")
        return snap

    @app.get("/api/v1/machine/{hostname}/report")
    def machine_report(hostname: str) -> Response:
        latest = store.get_latest_by_hostname(hostname)
        if latest is None:
            raise HTTPException(status_code=404, detail=f"No data for hostname: {hostname}")
        analysis = analyze_payload(latest)
        pdf_bytes = generate_pdf(latest, analysis)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="KKS-FP-PD02-06_{hostname}.pdf"'},
        )

    # ── Commands (IT Admin → Agent) ───────────────────────────────────────────
    @app.post("/api/v1/machine/{hostname}/command", dependencies=[Depends(_auth)])
    def send_command(hostname: str, req: CommandRequest) -> dict[str, Any]:
        if req.action not in VALID_ACTIONS:
            raise HTTPException(status_code=400, detail=f"Unknown action: {req.action}. Valid: {sorted(VALID_ACTIONS)}")
        cmd_id = store.enqueue_command(hostname, req.action, req.params)
        return {"status": "queued", "command_id": cmd_id, "hostname": hostname, "action": req.action}

    @app.post("/api/v1/segment/{segment}/command", dependencies=[Depends(_auth)])
    def send_segment_command(segment: str, req: CommandRequest) -> dict[str, Any]:
        if req.action not in VALID_ACTIONS:
            raise HTTPException(status_code=400, detail=f"Unknown action: {req.action}. Valid: {sorted(VALID_ACTIONS)}")
        ids = store.enqueue_command_segment(segment, req.action, req.params)
        return {"status": "queued", "command_ids": ids, "segment": segment, "action": req.action, "machines": len(ids)}

    @app.get("/api/v1/machine/{hostname}/commands/pending", dependencies=[Depends(_auth)])
    def poll_commands(hostname: str) -> list[dict[str, Any]]:
        return store.pop_pending_commands(hostname)

    @app.post("/api/v1/command/{cmd_id}/result", dependencies=[Depends(_auth)])
    def command_result(cmd_id: int, req: CommandResultRequest) -> dict[str, str]:
        store.complete_command(cmd_id, req.success, req.result)
        return {"status": "recorded"}

    @app.get("/api/v1/commands")
    def list_commands(hostname: Optional[str] = None, status: Optional[str] = None) -> list[dict[str, Any]]:
        return store.list_commands(hostname=hostname, status=status)

    # ── Scan Results ──────────────────────────────────────────────────────────
    _scan_status: dict = {"running": False, "last_run": None, "last_count": 0, "error": None}

    def _run_scan_bg(segments_cfg: list) -> None:
        _scan_status["running"] = True
        _scan_status["error"] = None
        try:
            from datetime import datetime, timezone
            results = scan_segments(segments_cfg)
            for r in results:
                store.upsert_scan_result({
                    "ip": r.ip, "hostname": r.hostname,
                    "network_segment": getattr(r, "network_segment", ""),
                    "status": r.status,
                    "open_ports": r.open_ports,
                    "services": r.services,
                    "scanned_at": r.scanned_at,
                })
            _scan_status["last_count"] = len(results)
            _scan_status["last_run"] = datetime.now(timezone.utc).isoformat()
        except Exception as e:
            _scan_status["error"] = str(e)
        finally:
            _scan_status["running"] = False

    @app.post("/api/v1/scan/start", dependencies=[Depends(_auth)])
    def scan_start(background_tasks: BackgroundTasks) -> dict[str, Any]:
        if _scan_status["running"]:
            return {"status": "already_running"}
        import yaml
        try:
            with open("config/network_segments.yml", "r", encoding="utf-8") as f:
                raw = yaml.safe_load(f) or {}
            segments_cfg = raw.get("segments") or []
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Cannot read segments config: {e}")
        if not segments_cfg:
            raise HTTPException(status_code=400, detail="No segments configured")
        background_tasks.add_task(_run_scan_bg, segments_cfg)
        return {"status": "started", "segments": len(segments_cfg)}

    @app.get("/api/v1/scan/status")
    def scan_status_api() -> dict[str, Any]:
        return _scan_status

    @app.post("/api/v1/scan/report", dependencies=[Depends(_auth)])
    def scan_report(body: Dict[str, Any]) -> dict[str, Any]:
        results = body.get("results") or []
        for r in results:
            store.upsert_scan_result(r)
        return {"status": "accepted", "count": len(results)}

    @app.get("/api/v1/scan/results")
    def scan_results(segment: Optional[str] = None, status: Optional[str] = None) -> list[dict[str, Any]]:
        return store.list_scan_results(segment=segment, status=status)

    @app.get("/api/v1/scan/summary")
    def scan_summary() -> list[dict[str, Any]]:
        all_results = store.list_scan_results()
        summary: dict[str, dict] = {}
        for r in all_results:
            seg = r["network_segment"] or "unknown"
            if seg not in summary:
                summary[seg] = {"network_segment": seg, "total": 0, "online": 0, "offline": 0, "no_hostname": 0, "has_rdp": 0, "has_vnc": 0}
            summary[seg]["total"] += 1
            if r["status"] == "online":
                summary[seg]["online"] += 1
                if 3389 in r["open_ports"]:
                    summary[seg]["has_rdp"] += 1
                if 5900 in r["open_ports"]:
                    summary[seg]["has_vnc"] += 1
            elif r["status"] == "no_hostname":
                summary[seg]["no_hostname"] += 1
            else:
                summary[seg]["offline"] += 1
        return list(summary.values())

    # ── Help Desk Tickets ───────────────────────────────────────────────────
    @app.post("/api/v1/tickets")
    def create_ticket(req: TicketCreateRequest) -> dict[str, Any]:
        data = req.model_dump()
        # Auto-enrich with machine data if hostname provided
        if req.hostname:
            payload = store.get_latest_by_hostname(req.hostname)
            data = enrich_ticket(data, payload)
            data["suggestions"] = auto_suggest_actions(data)
        return store.create_ticket(data)

    @app.get("/api/v1/tickets")
    def list_tickets(
        status: Optional[str] = None,
        priority: Optional[str] = None,
        hostname: Optional[str] = None,
        assigned_to: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        return store.list_tickets(status=status, priority=priority, hostname=hostname, assigned_to=assigned_to)

    @app.get("/api/v1/tickets/summary")
    def tickets_summary() -> dict[str, Any]:
        all_tickets = store.list_tickets()
        summary: dict[str, int] = {"open": 0, "assigned": 0, "in_progress": 0, "resolved": 0, "closed": 0}
        by_priority: dict[str, int] = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for t in all_tickets:
            summary[t["status"]] = summary.get(t["status"], 0) + 1
            by_priority[t["priority"]] = by_priority.get(t["priority"], 0) + 1
        return {"total": len(all_tickets), "by_status": summary, "by_priority": by_priority}

    @app.get("/api/v1/tickets/{ticket_id}")
    def get_ticket(ticket_id: int) -> dict[str, Any]:
        ticket = store.get_ticket(ticket_id)
        if not ticket:
            raise HTTPException(status_code=404, detail=f"Ticket {ticket_id} not found")
        ticket["notes"] = store.get_ticket_notes(ticket_id)
        return ticket

    @app.patch("/api/v1/tickets/{ticket_id}")
    def update_ticket(ticket_id: int, req: TicketUpdateRequest) -> dict[str, Any]:
        ticket = store.get_ticket(ticket_id)
        if not ticket:
            raise HTTPException(status_code=404, detail=f"Ticket {ticket_id} not found")
        updates = {k: v for k, v in req.model_dump().items() if v is not None}
        if "status" in updates:
            allowed = STATUS_FLOW.get(ticket["status"], [])
            if updates["status"] not in allowed:
                raise HTTPException(status_code=400, detail=f"Cannot move from '{ticket['status']}' to '{updates['status']}'. Allowed: {allowed}")
        return store.update_ticket(ticket_id, updates)

    @app.post("/api/v1/tickets/{ticket_id}/notes")
    def add_note(ticket_id: int, req: NoteRequest) -> dict[str, Any]:
        if not store.get_ticket(ticket_id):
            raise HTTPException(status_code=404, detail=f"Ticket {ticket_id} not found")
        return store.add_ticket_note(ticket_id, req.author, req.note)

    @app.delete("/api/v1/tickets/{ticket_id}", dependencies=[Depends(_auth)])
    def delete_ticket(ticket_id: int) -> dict[str, str]:
        if not store.get_ticket(ticket_id):
            raise HTTPException(status_code=404, detail=f"Ticket {ticket_id} not found")
        store.delete_ticket(ticket_id)
        return {"status": "deleted"}

    @app.post("/api/v1/tickets/{ticket_id}/command", dependencies=[Depends(_auth)])
    def ticket_command(ticket_id: int, req: CommandRequest) -> dict[str, Any]:
        """Send a command to the machine linked to a ticket."""
        ticket = store.get_ticket(ticket_id)
        if not ticket:
            raise HTTPException(status_code=404, detail=f"Ticket {ticket_id} not found")
        hostname = ticket.get("hostname")
        if not hostname:
            raise HTTPException(status_code=400, detail="Ticket has no hostname linked")
        if req.action not in VALID_ACTIONS:
            raise HTTPException(status_code=400, detail=f"Unknown action: {req.action}")
        cmd_id = store.enqueue_command(hostname, req.action, req.params)
        store.add_ticket_note(ticket_id, "system", f"Command queued: {req.action} (cmd_id={cmd_id})")
        return {"status": "queued", "command_id": cmd_id, "hostname": hostname, "action": req.action}

    return app

from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional

@dataclass(frozen=True)
class IngestRecord:
    hostname: str
    network_segment: str
    role: str
    received_at: str
    payload_json: str


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class SqliteStore:
    def __init__(self, database_url: str):
        # Expect: sqlite:///./data/file.db
        if not database_url.startswith("sqlite:///"):
            raise ValueError("Only sqlite is supported in this MVP. Use sqlite:///./path.db")
        path = database_url[len("sqlite:///") :]
        self.path = os.path.normpath(path)

        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        self._init()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS ingest (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hostname TEXT NOT NULL,
                    network_segment TEXT NOT NULL,
                    role TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ingest_hostname ON ingest(hostname)")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_ingest_segment ON ingest(network_segment)"
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS commands (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hostname TEXT NOT NULL,
                    action TEXT NOT NULL,
                    params_json TEXT NOT NULL DEFAULT '{}',
                    status TEXT NOT NULL DEFAULT 'pending',
                    created_at TEXT NOT NULL,
                    executed_at TEXT,
                    result_json TEXT
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cmd_hostname ON commands(hostname, status)")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_results (
                    ip TEXT PRIMARY KEY,
                    hostname TEXT,
                    network_segment TEXT,
                    status TEXT,
                    open_ports_json TEXT NOT NULL DEFAULT '[]',
                    services_json TEXT NOT NULL DEFAULT '{}',
                    scanned_at TEXT
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_segment ON scan_results(network_segment)")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS wmi_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hostname TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    snapshot_json TEXT NOT NULL,
                    collected_at TEXT NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_wmi_hostname ON wmi_snapshots(hostname)")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS tickets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    category TEXT NOT NULL DEFAULT 'other',
                    priority TEXT NOT NULL DEFAULT 'medium',
                    status TEXT NOT NULL DEFAULT 'open',
                    reporter_name TEXT NOT NULL,
                    reporter_email TEXT,
                    hostname TEXT,
                    assigned_to TEXT,
                    machine_context_json TEXT,
                    suggestions_json TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ticket_status ON tickets(status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ticket_hostname ON tickets(hostname)")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS ticket_notes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ticket_id INTEGER NOT NULL,
                    author TEXT NOT NULL,
                    note TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(ticket_id) REFERENCES tickets(id)
                )
                """
            )

    def insert_payload(self, payload: Dict[str, Any]) -> None:
        asset = payload.get("asset") or {}
        hostname = str(asset.get("hostname") or "unknown")
        network_segment = str(asset.get("network_segment") or "unknown")
        role = str(asset.get("role") or "unknown")

        record = IngestRecord(
            hostname=hostname,
            network_segment=network_segment,
            role=role,
            received_at=_utc_now_iso(),
            payload_json=json.dumps(payload, ensure_ascii=False),
        )

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO ingest (hostname, network_segment, role, received_at, payload_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    record.hostname,
                    record.network_segment,
                    record.role,
                    record.received_at,
                    record.payload_json,
                ),
            )

    def get_latest_by_hostname(self, hostname: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT payload_json
                FROM ingest
                WHERE hostname = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (hostname,),
            ).fetchone()
        if not row:
            return None
        return json.loads(row["payload_json"])

    # ── Ticket methods ────────────────────────────────────────────────────
    def create_ticket(self, data: Dict[str, Any]) -> Dict[str, Any]:
        now = _utc_now_iso()
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO tickets
                (title, description, category, priority, status, reporter_name, reporter_email,
                 hostname, assigned_to, machine_context_json, suggestions_json, created_at, updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    data["title"], data["description"], data.get("category", "other"),
                    data.get("priority", "medium"), "open",
                    data["reporter_name"], data.get("reporter_email"),
                    data.get("hostname"), None,
                    json.dumps(data.get("machine_context") or {}),
                    json.dumps(data.get("suggestions") or []),
                    now, now,
                ),
            )
            return self.get_ticket(cur.lastrowid)

    def get_ticket(self, ticket_id: int) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM tickets WHERE id=?", (ticket_id,)).fetchone()
        return self._ticket_row(row) if row else None

    def list_tickets(
        self,
        status: Optional[str] = None,
        priority: Optional[str] = None,
        hostname: Optional[str] = None,
        assigned_to: Optional[str] = None,
    ) -> list[Dict[str, Any]]:
        query = "SELECT * FROM tickets WHERE 1=1"
        args: list = []
        for col, val in [("status", status), ("priority", priority), ("hostname", hostname), ("assigned_to", assigned_to)]:
            if val:
                query += f" AND {col}=?"
                args.append(val)
        query += " ORDER BY id DESC"
        with self._connect() as conn:
            rows = conn.execute(query, args).fetchall()
        return [self._ticket_row(r) for r in rows]

    def update_ticket(self, ticket_id: int, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        allowed = {"title", "description", "category", "priority", "status", "assigned_to"}
        fields = {k: v for k, v in updates.items() if k in allowed}
        if not fields:
            return self.get_ticket(ticket_id)
        fields["updated_at"] = _utc_now_iso()
        set_clause = ", ".join(f"{k}=?" for k in fields)
        with self._connect() as conn:
            conn.execute(f"UPDATE tickets SET {set_clause} WHERE id=?", [*fields.values(), ticket_id])
        return self.get_ticket(ticket_id)

    def add_ticket_note(self, ticket_id: int, author: str, note: str) -> Dict[str, Any]:
        now = _utc_now_iso()
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO ticket_notes (ticket_id, author, note, created_at) VALUES (?,?,?,?)",
                (ticket_id, author, note, now),
            )
            conn.execute("UPDATE tickets SET updated_at=? WHERE id=?", (now, ticket_id))
        return {"ticket_id": ticket_id, "author": author, "note": note, "created_at": now}

    def get_ticket_notes(self, ticket_id: int) -> list[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT author, note, created_at FROM ticket_notes WHERE ticket_id=? ORDER BY id",
                (ticket_id,),
            ).fetchall()
        return [{"author": r["author"], "note": r["note"], "created_at": r["created_at"]} for r in rows]

    def delete_ticket(self, ticket_id: int) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM ticket_notes WHERE ticket_id=?", (ticket_id,))
            conn.execute("DELETE FROM tickets WHERE id=?", (ticket_id,))

    def _ticket_row(self, row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "id": row["id"],
            "title": row["title"],
            "description": row["description"],
            "category": row["category"],
            "priority": row["priority"],
            "status": row["status"],
            "reporter_name": row["reporter_name"],
            "reporter_email": row["reporter_email"],
            "hostname": row["hostname"],
            "assigned_to": row["assigned_to"],
            "machine_context": json.loads(row["machine_context_json"] or "{}"),
            "suggestions": json.loads(row["suggestions_json"] or "[]"),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def list_segments(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    network_segment,
                    COUNT(DISTINCT hostname) AS total_machines
                FROM ingest
                GROUP BY network_segment
                ORDER BY network_segment
                """
            ).fetchall()
        return [
            {
                "network_segment": r["network_segment"],
                "total_machines": int(r["total_machines"]),
            }
            for r in rows
        ]

    def get_latest_payloads_by_segment(self, segment: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT payload_json FROM ingest
                WHERE id IN (
                    SELECT MAX(id) FROM ingest
                    WHERE network_segment = ?
                    GROUP BY hostname
                )
                """,
                (segment,),
            ).fetchall()
        return [json.loads(r["payload_json"]) for r in rows]

    def enqueue_command(self, hostname: str, action: str, params: dict) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO commands (hostname, action, params_json, created_at) VALUES (?, ?, ?, ?)",
                (hostname, action, json.dumps(params), _utc_now_iso()),
            )
            return cur.lastrowid

    def enqueue_command_segment(self, segment: str, action: str, params: dict) -> list[int]:
        machines = self.list_machines_by_segment(segment)
        return [self.enqueue_command(m["hostname"], action, params) for m in machines]

    def pop_pending_commands(self, hostname: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, action, params_json FROM commands WHERE hostname=? AND status='pending' ORDER BY id",
                (hostname,),
            ).fetchall()
            if rows:
                ids = [r["id"] for r in rows]
                conn.execute(
                    f"UPDATE commands SET status='dispatched' WHERE id IN ({','.join('?'*len(ids))})",
                    ids,
                )
        return [{"id": r["id"], "action": r["action"], "params": json.loads(r["params_json"])} for r in rows]

    def complete_command(self, cmd_id: int, success: bool, result: dict) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE commands SET status=?, executed_at=?, result_json=? WHERE id=?",
                ("done" if success else "failed", _utc_now_iso(), json.dumps(result), cmd_id),
            )

    def list_commands(self, hostname: str | None = None, status: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT id, hostname, action, params_json, status, created_at, executed_at, result_json FROM commands WHERE 1=1"
        args: list = []
        if hostname:
            query += " AND hostname=?"
            args.append(hostname)
        if status:
            query += " AND status=?"
            args.append(status)
        query += " ORDER BY id DESC LIMIT 200"
        with self._connect() as conn:
            rows = conn.execute(query, args).fetchall()
        return [
            {
                "id": r["id"],
                "hostname": r["hostname"],
                "action": r["action"],
                "params": json.loads(r["params_json"]),
                "status": r["status"],
                "created_at": r["created_at"],
                "executed_at": r["executed_at"],
                "result": json.loads(r["result_json"]) if r["result_json"] else None,
            }
            for r in rows
        ]

    def save_wmi_snapshot(self, hostname: str, ip: str, data: Dict[str, Any]) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO wmi_snapshots (hostname, ip, snapshot_json, collected_at) VALUES (?,?,?,?)",
                (hostname, ip, json.dumps(data, ensure_ascii=False), _utc_now_iso()),
            )

    def get_latest_wmi_snapshot(self, hostname: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT snapshot_json FROM wmi_snapshots WHERE hostname=? ORDER BY id DESC LIMIT 1",
                (hostname,),
            ).fetchone()
        return json.loads(row["snapshot_json"]) if row else None

    def upsert_scan_result(self, result: Dict[str, Any]) -> None:
        ip = str(result.get("ip") or "")
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO scan_results (ip, hostname, network_segment, status, open_ports_json, services_json, scanned_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    hostname=excluded.hostname,
                    network_segment=excluded.network_segment,
                    status=excluded.status,
                    open_ports_json=excluded.open_ports_json,
                    services_json=excluded.services_json,
                    scanned_at=excluded.scanned_at
                """,
                (
                    ip,
                    str(result.get("hostname") or ""),
                    str(result.get("network_segment") or ""),
                    str(result.get("status") or "unknown"),
                    json.dumps(result.get("open_ports") or []),
                    json.dumps(result.get("services") or {}),
                    str(result.get("scanned_at") or ""),
                ),
            )

    def list_scan_results(self, segment: str | None = None, status: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT ip, hostname, network_segment, status, open_ports_json, services_json, scanned_at FROM scan_results WHERE 1=1"
        args: list = []
        if segment:
            query += " AND network_segment=?"
            args.append(segment)
        if status:
            query += " AND status=?"
            args.append(status)
        query += " ORDER BY network_segment, ip"
        with self._connect() as conn:
            rows = conn.execute(query, args).fetchall()
        return [
            {
                "ip": r["ip"],
                "hostname": r["hostname"],
                "network_segment": r["network_segment"],
                "status": r["status"],
                "open_ports": json.loads(r["open_ports_json"]),
                "services": json.loads(r["services_json"]),
                "scanned_at": r["scanned_at"],
            }
            for r in rows
        ]

    def list_machines_by_segment(self, segment: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT hostname, role, MAX(id) AS last_id
                FROM ingest
                WHERE network_segment = ?
                GROUP BY hostname, role
                ORDER BY hostname
                """,
                (segment,),
            ).fetchall()
        return [{"hostname": r["hostname"], "role": r["role"]} for r in rows]


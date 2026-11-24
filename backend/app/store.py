"""SQLite persistence: scans, findings, proposals and an append-only audit log."""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, kind TEXT,
  content TEXT, created_at TEXT, risk INTEGER, reviewed INTEGER DEFAULT 0, provider TEXT);
CREATE TABLE IF NOT EXISTS findings(scan_id INTEGER, id INTEGER, data TEXT, PRIMARY KEY(scan_id, id));
CREATE TABLE IF NOT EXISTS proposals(id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER,
  finding_id INTEGER, action TEXT, rationale TEXT, status TEXT DEFAULT 'pending',
  reviewer TEXT, note TEXT, decided_at TEXT, proposed_by TEXT);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, actor TEXT,
  event TEXT, scan_id INTEGER, detail TEXT);
"""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Store:
    def __init__(self, path: str | None = None):
        self.path = path or os.environ.get("ASDIP_DB", "asdip.db")
        self.lock = threading.Lock()
        self.db = sqlite3.connect(self.path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    def audit(self, actor: str, event: str, scan_id: int | None, detail: dict | None = None):
        self.db.execute("INSERT INTO audit(ts,actor,event,scan_id,detail) VALUES(?,?,?,?,?)",
                        (now(), actor, event, scan_id, json.dumps(detail or {})))

    def create_scan(self, name, kind, content, findings, risk) -> int:
        with self.lock:
            cur = self.db.execute("INSERT INTO scans(name,kind,content,created_at,risk) VALUES(?,?,?,?,?)",
                                  (name, kind, content, now(), risk))
            sid = cur.lastrowid
            for f in findings:
                self.db.execute("INSERT INTO findings VALUES(?,?,?)", (sid, f["id"], json.dumps(f)))
            self.audit("system", "scan_created", sid, {"findings": len(findings), "kind": kind})
            self.db.commit()
            return sid

    def get_scan(self, sid: int, with_content=False):
        row = self.db.execute("SELECT * FROM scans WHERE id=?", (sid,)).fetchone()
        if not row:
            return None
        out = {k: row[k] for k in ("id", "name", "kind", "created_at", "risk", "reviewed", "provider")}
        if with_content:
            out["content"] = row["content"]
        out["findings"] = [json.loads(r["data"]) for r in self.db.execute(
            "SELECT data FROM findings WHERE scan_id=? ORDER BY id", (sid,))]
        out["proposals"] = [dict(r) for r in self.db.execute(
            "SELECT * FROM proposals WHERE scan_id=? ORDER BY id", (sid,))]
        return out

    def list_scans(self):
        return [dict(r) for r in self.db.execute(
            "SELECT id,name,kind,created_at,risk,reviewed,provider FROM scans ORDER BY id DESC LIMIT 50")]

    def add_proposals(self, sid: int, proposals: list[dict], provider_label: str):
        with self.lock:
            self.db.execute("DELETE FROM proposals WHERE scan_id=? AND status='pending'", (sid,))
            for p in proposals:
                self.db.execute(
                    "INSERT INTO proposals(scan_id,finding_id,action,rationale,proposed_by) VALUES(?,?,?,?,?)",
                    (sid, p["finding_id"], p["action"], p["rationale"], provider_label))
            self.db.execute("UPDATE scans SET reviewed=1, provider=? WHERE id=?", (provider_label, sid))
            self.audit("agent", "proposals_created", sid, {"count": len(proposals), "provider": provider_label})
            self.db.commit()

    def decide(self, pid: int, decision: str, reviewer: str, note: str):
        with self.lock:
            row = self.db.execute("SELECT * FROM proposals WHERE id=?", (pid,)).fetchone()
            if not row:
                return None
            if row["status"] != "pending":
                raise ValueError("proposal already decided")
            status = "approved" if decision == "approve" else "rejected"
            self.db.execute("UPDATE proposals SET status=?, reviewer=?, note=?, decided_at=? WHERE id=?",
                            (status, reviewer, note, now(), pid))
            self.audit(reviewer, f"proposal_{status}", row["scan_id"],
                       {"proposal_id": pid, "finding_id": row["finding_id"], "action": row["action"]})
            self.db.commit()
            return dict(self.db.execute("SELECT * FROM proposals WHERE id=?", (pid,)).fetchone())

    def audit_log(self, limit=100):
        return [dict(r) for r in self.db.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))]


def apply_approved(content: str, findings: list[dict], proposals: list[dict]) -> str:
    """Redact only spans a human approved. Nothing else in the text is changed."""
    approved = {p["finding_id"] for p in proposals if p["status"] == "approved" and p["action"] == "redact"}
    lines = content.splitlines()
    for f in sorted((f for f in findings if f["id"] in approved and not f["statement_level"]),
                    key=lambda f: (f["line"], f["start"]), reverse=True):
        ln = lines[f["line"] - 1]
        lines[f["line"] - 1] = ln[:f["start"]] + f"[REDACTED:{f['rule_id']}]" + ln[f["end"]:]
    return "\n".join(lines) + ("\n" if content.endswith("\n") else "")

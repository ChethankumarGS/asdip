"""FastAPI app for ASDIP."""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import llm
from .scanner import risk_score, scan_text
from .store import Store, apply_approved
from .validation import ValidationError, validate_scan_input


class ScanIn(BaseModel):
    name: str
    kind: str
    content: str


class DecisionIn(BaseModel):
    decision: str
    reviewer: str = "reviewer"
    note: str = ""


def create_app(store: Store | None = None, provider=None) -> FastAPI:
    app = FastAPI(title="ASDIP", version="0.1.0")
    st = store or Store()
    prov = provider or llm.get_provider()

    @app.get("/api/health")
    def health():
        return {"ok": True, "provider_mode": prov.mode, "provider_label": prov.label}

    @app.post("/api/scans")
    def create_scan(body: ScanIn):
        try:
            name, kind, content = validate_scan_input(body.name, body.kind, body.content)
        except ValidationError as exc:
            raise HTTPException(422, str(exc))
        findings = scan_text(content, kind)
        sid = st.create_scan(name, kind, content, findings, risk_score(findings))
        return st.get_scan(sid)

    @app.get("/api/scans")
    def list_scans():
        return st.list_scans()

    @app.get("/api/scans/{sid}")
    def get_scan(sid: int):
        scan = st.get_scan(sid)
        if not scan:
            raise HTTPException(404, "scan not found")
        return scan

    @app.post("/api/scans/{sid}/review")
    def review(sid: int):
        scan = st.get_scan(sid, with_content=True)
        if not scan:
            raise HTTPException(404, "scan not found")
        if not scan["findings"]:
            raise HTTPException(409, "nothing to review: no findings")
        try:
            proposals = llm.run_review(prov, scan["findings"], scan["content"].splitlines())
        except Exception as exc:  # provider/network failure must not corrupt state
            raise HTTPException(502, f"review failed: {type(exc).__name__}")
        st.add_proposals(sid, proposals, prov.label)
        return st.get_scan(sid)

    @app.post("/api/proposals/{pid}/decision")
    def decide(pid: int, body: DecisionIn):
        if body.decision not in ("approve", "reject"):
            raise HTTPException(422, "decision must be approve or reject")
        reviewer = (body.reviewer or "reviewer").strip()[:60] or "reviewer"
        try:
            res = st.decide(pid, body.decision, reviewer, body.note[:300])
        except ValueError as exc:
            raise HTTPException(409, str(exc))
        if not res:
            raise HTTPException(404, "proposal not found")
        return res

    @app.get("/api/scans/{sid}/redacted")
    def redacted(sid: int):
        scan = st.get_scan(sid, with_content=True)
        if not scan:
            raise HTTPException(404, "scan not found")
        text = apply_approved(scan["content"], scan["findings"], scan["proposals"])
        return {"content": text, "applied": sum(1 for p in scan["proposals"]
                                                if p["status"] == "approved" and p["action"] == "redact")}

    @app.get("/api/audit")
    def audit():
        return st.audit_log()

    dist = Path(os.environ.get("ASDIP_FRONTEND_DIST", Path(__file__).resolve().parents[2] / "frontend" / "dist"))
    if dist.exists():
        app.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")

        @app.get("/{path:path}")
        def spa(path: str):
            return FileResponse(dist / "index.html")

    return app


app = create_app() if os.environ.get("ASDIP_AUTOSTART", "1") == "1" else None

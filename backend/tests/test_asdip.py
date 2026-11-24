import os
os.environ["ASDIP_AUTOSTART"] = "0"
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import llm
from app.main import create_app
from app.scanner import luhn_ok, scan_text
from app.store import Store
from app.validation import ValidationError, validate_scan_input, validate_tool_call

SAMPLES = Path(__file__).resolve().parents[2] / "samples"


@pytest.fixture
def client(tmp_path):
    return TestClient(create_app(Store(str(tmp_path / "t.db")), llm.OfflineRulesProvider()))


def rules(findings):
    return {f["rule_id"] for f in findings}


def test_luhn():
    assert luhn_ok("4111 1111 1111 1111")
    assert not luhn_ok("4111 1111 1111 1112")


def test_log_detection_and_masking():
    f = scan_text((SAMPLES / "app.log").read_text(), "log")
    assert {"EMAIL", "CREDIT_CARD", "API_KEY_ASSIGNMENT", "PHONE", "AWS_ACCESS_KEY", "IPV4"} <= rules(f)
    assert all("4111 1111 1111 1111" not in str(x) and "AKIAFAKE" not in str(x) for x in f)
    card = next(x for x in f if x["rule_id"] == "CREDIT_CARD")
    assert card["preview"].endswith("1111") and set(card["preview"][:-4]) == {"*"}


def test_invalid_card_not_flagged():
    assert "CREDIT_CARD" not in rules(scan_text("order 4111 1111 1111 1112 shipped", "log"))


def test_sql_rules():
    f = scan_text((SAMPLES / "report.sql").read_text(), "sql")
    assert {"SQL_SELECT_STAR_PII", "SQL_GRANT_ALL", "SQL_DELETE_NO_WHERE",
            "SQL_PLAINTEXT_PASSWORD", "US_SSN", "EMAIL"} <= rules(f)
    assert not any(x["line"] == 7 for x in f)  # parameterised, bounded query is clean


def test_validation():
    with pytest.raises(ValidationError):
        validate_scan_input("x", "pdf", "data")
    with pytest.raises(ValidationError):
        validate_scan_input("x", "log", "a\x00b")
    with pytest.raises(ValidationError):
        validate_scan_input("x", "log", "a" * 300_000)
    with pytest.raises(ValidationError):
        validate_tool_call("propose_action", {"finding_id": 1, "action": "delete_everything", "rationale": "x"}, {1})
    with pytest.raises(ValidationError):
        validate_tool_call("propose_action", {"finding_id": 9, "action": "redact", "rationale": "x"}, {1})
    with pytest.raises(ValidationError):
        validate_tool_call("rm_rf", {}, {1})


def test_rejects_bad_input_over_api(client):
    r = client.post("/api/scans", json={"name": "a", "kind": "zip", "content": "x"})
    assert r.status_code == 422


def test_human_in_the_loop_flow(client):
    text = (SAMPLES / "app.log").read_text()
    scan = client.post("/api/scans", json={"name": "app.log", "kind": "log", "content": text}).json()
    sid = scan["id"]
    # nothing is redacted before review or approval
    assert client.get(f"/api/scans/{sid}/redacted").json()["content"] == text
    reviewed = client.post(f"/api/scans/{sid}/review").json()
    assert len(reviewed["proposals"]) == len(scan["findings"])
    assert all(p["status"] == "pending" for p in reviewed["proposals"])
    # pending proposals still change nothing
    assert client.get(f"/api/scans/{sid}/redacted").json()["content"] == text
    card = next(f for f in scan["findings"] if f["rule_id"] == "CREDIT_CARD")
    prop = next(p for p in reviewed["proposals"] if p["finding_id"] == card["id"])
    assert prop["action"] == "redact"
    client.post(f"/api/proposals/{prop['id']}/decision", json={"decision": "approve", "reviewer": "asha"})
    out = client.get(f"/api/scans/{sid}/redacted").json()
    assert "[REDACTED:CREDIT_CARD]" in out["content"] and "4111 1111 1111 1111" not in out["content"]
    assert "AKIAFAKEFAKEFAKE1234" in out["content"]  # unapproved finding untouched
    assert out["applied"] == 1
    # decisions are final and audited
    assert client.post(f"/api/proposals/{prop['id']}/decision", json={"decision": "reject"}).status_code == 409
    events = [e["event"] for e in client.get("/api/audit").json()]
    assert "proposal_approved" in events and "proposals_created" in events


def test_rejected_proposal_changes_nothing(client):
    text = "contact bob@example.test now"
    sid = client.post("/api/scans", json={"name": "n", "kind": "file", "content": text}).json()["id"]
    p = client.post(f"/api/scans/{sid}/review").json()["proposals"][0]
    client.post(f"/api/proposals/{p['id']}/decision", json={"decision": "reject"})
    assert client.get(f"/api/scans/{sid}/redacted").json()["content"] == text


class ScriptedLLM:
    """Stands in for a model that misbehaves: bad tool args, then a valid proposal."""
    mode, label = "llm", "scripted"

    def __init__(self):
        self.n = 0

    def next_step(self, messages):
        self.n += 1
        if self.n == 1:
            return {"tool_calls": [{"id": "a", "name": "propose_action",
                                    "arguments": {"finding_id": 99, "action": "redact", "rationale": "x"}}]}
        if self.n == 2:
            return {"tool_calls": [{"id": "b", "name": "propose_action",
                                    "arguments": {"finding_id": 1, "action": "format_disk", "rationale": "x"}}]}
        if self.n == 3:
            return {"tool_calls": [{"id": "c", "name": "get_finding_context", "arguments": {"finding_id": 1}}]}
        if self.n == 4:
            return {"tool_calls": [{"id": "d", "name": "propose_action",
                                    "arguments": {"finding_id": 1, "action": "redact", "rationale": "ok"}}]}
        return {"final": "done"}


def test_invalid_model_tool_calls_are_rejected_and_context_is_masked():
    findings = scan_text("mail zed@example.test card 4111 1111 1111 1111", "log")
    seen = []

    class Spy(ScriptedLLM):
        def next_step(self, messages):
            seen.extend(str(m) for m in messages)
            return super().next_step(messages)

    props = llm.run_review(Spy(), findings[:1], ["mail zed@example.test card 4111 1111 1111 1111"])
    assert [p["action"] for p in props] == ["redact"]  # only the valid call became a proposal
    blob = " ".join(seen)
    assert "1111 1111 1111 1111" not in blob


def test_default_provider_is_offline_without_key(monkeypatch):
    monkeypatch.delenv("ASDIP_LLM_API_KEY", raising=False)
    assert llm.get_provider().mode == "offline-rules"

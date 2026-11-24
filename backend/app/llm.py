"""Agent layer: an LLM (or an offline stand-in) reviews findings through tools.

Two providers share one interface:

* OpenAICompatibleProvider calls a real chat-completions API with tool calling.
  It is used only when ASDIP_LLM_API_KEY is set.
* OfflineRulesProvider is a deterministic policy with NO language model. It is
  the default so the demo and tests run without keys, and the UI labels it.

The model only ever sees masked previews. Its tool calls are validated, and
every proposal it makes stays "pending" until a human approves it.
"""
from __future__ import annotations

import json
import os
from typing import Protocol

import httpx

from .validation import ValidationError, validate_tool_call

TOOLS = [
    {"type": "function", "function": {
        "name": "list_findings", "description": "List findings for the scan (masked previews only).",
        "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {
        "name": "get_finding_context", "description": "Get the masked line around one finding.",
        "parameters": {"type": "object", "properties": {"finding_id": {"type": "integer"}},
                       "required": ["finding_id"]}}},
    {"type": "function", "function": {
        "name": "propose_action",
        "description": "Propose how to handle a finding. A human must approve before anything is applied.",
        "parameters": {"type": "object", "properties": {
            "finding_id": {"type": "integer"},
            "action": {"type": "string", "enum": ["redact", "escalate", "dismiss"]},
            "rationale": {"type": "string"}},
            "required": ["finding_id", "action", "rationale"]}}},
]

SYSTEM_PROMPT = (
    "You are a data-risk reviewer. Use the tools to inspect findings, then call propose_action "
    "once per finding. Prefer redact for exposed secrets and personal data, escalate for risky "
    "SQL statements and critical items needing an owner, dismiss only for clearly low risk. "
    "You cannot apply anything; a human reviewer approves each proposal."
)


class Provider(Protocol):
    mode: str
    label: str

    def next_step(self, messages: list[dict]) -> dict: ...


class OfflineRulesProvider:
    mode = "offline-rules"
    label = "Offline rules (no LLM)"

    def next_step(self, messages: list[dict]) -> dict:
        proposed = {m["finding_id"] for m in messages if m.get("role") == "proposal_log"}
        listing = next((json.loads(m["content"]) for m in messages
                        if m.get("role") == "tool" and m.get("name") == "list_findings"), None)
        if listing is None:
            return {"tool_calls": [{"name": "list_findings", "arguments": {}}]}
        for f in listing:
            if f["id"] in proposed:
                continue
            if f["statement_level"] or f["severity"] == "critical" and f["rule_id"] == "PRIVATE_KEY":
                action, why = "escalate", "Needs an owner to review the statement or rotate the key."
            elif f["severity"] == "low":
                action, why = "dismiss", "Low severity identifier."
            else:
                action, why = "redact", f"{f['title']} should not appear in stored text."
            return {"tool_calls": [{"name": "propose_action", "arguments": {
                "finding_id": f["id"], "action": action, "rationale": why}}]}
        return {"final": "Review complete (offline rules)."}


class OpenAICompatibleProvider:
    mode = "llm"

    def __init__(self, api_key: str, base_url: str, model: str):
        self.api_key, self.base_url, self.model = api_key, base_url.rstrip("/"), model
        self.label = f"LLM tool-calling ({model})"

    def next_step(self, messages: list[dict]) -> dict:
        chat = [{"role": "system", "content": SYSTEM_PROMPT}]
        for m in messages:
            if m.get("role") == "proposal_log":
                continue
            chat.append({k: v for k, v in m.items() if k in ("role", "content", "tool_calls", "tool_call_id", "name")})
        r = httpx.post(f"{self.base_url}/chat/completions", timeout=60,
                       headers={"Authorization": f"Bearer {self.api_key}"},
                       json={"model": self.model, "messages": chat, "tools": TOOLS})
        r.raise_for_status()
        msg = r.json()["choices"][0]["message"]
        if msg.get("tool_calls"):
            calls = []
            for tc in msg["tool_calls"]:
                try:
                    args = json.loads(tc["function"]["arguments"] or "{}")
                except json.JSONDecodeError:
                    args = {"_invalid": True}
                calls.append({"id": tc["id"], "name": tc["function"]["name"], "arguments": args,
                              "raw": tc})
            return {"tool_calls": calls, "assistant": msg}
        return {"final": msg.get("content") or ""}


def get_provider() -> Provider:
    key = os.environ.get("ASDIP_LLM_API_KEY")
    if key:
        return OpenAICompatibleProvider(
            key, os.environ.get("ASDIP_LLM_BASE_URL", "https://api.openai.com/v1"),
            os.environ.get("ASDIP_LLM_MODEL", "gpt-4o-mini"))
    return OfflineRulesProvider()


def run_review(provider: Provider, findings: list[dict], lines: list[str], max_steps: int = 60) -> list[dict]:
    """Drive the tool-calling loop. Returns validated proposals (all still pending)."""
    ids = {f["id"] for f in findings}
    by_id = {f["id"]: f for f in findings}
    masked = [{k: f[k] for k in ("id", "rule_id", "title", "severity", "line", "preview", "statement_level")}
              for f in findings]
    messages: list[dict] = [{"role": "user", "content": "Review the findings for this scan."}]
    proposals: dict[int, dict] = {}
    for _ in range(max_steps):
        step = provider.next_step(messages)
        if "final" in step:
            break
        if "assistant" in step:
            messages.append(step["assistant"])
        for call in step["tool_calls"]:
            tool_id = call.get("id", call["name"])
            try:
                if call["arguments"].get("_invalid"):
                    raise ValidationError("arguments were not valid JSON")
                args = validate_tool_call(call["name"], call["arguments"], ids)
                if call["name"] == "list_findings":
                    result = masked
                elif call["name"] == "get_finding_context":
                    result = {"line": f"[line {by_id[args['finding_id']]['line']}] "
                                      f"{masked_line(lines, findings, by_id[args['finding_id']]['line'])}"}
                else:
                    proposals[args["finding_id"]] = args
                    messages.append({"role": "proposal_log", "finding_id": args["finding_id"]})
                    result = {"status": "pending_human_approval"}
            except ValidationError as exc:
                result = {"error": str(exc)}
            messages.append({"role": "tool", "tool_call_id": tool_id, "name": call["name"],
                             "content": json.dumps(result)})
        if len(proposals) == len(ids):
            break
    return list(proposals.values())


def masked_line(lines: list[str], findings: list[dict], lineno: int) -> str:
    """The line with EVERY finding on it masked, so no other secret leaks into context."""
    line = lines[lineno - 1]
    for f in sorted((f for f in findings if f["line"] == lineno and not f["statement_level"]),
                    key=lambda f: f["start"], reverse=True):
        line = line[:f["start"]] + f["preview"] + line[f["end"]:]
    return line[:200]

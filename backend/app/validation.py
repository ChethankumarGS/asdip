"""Input validation applied before scanning and before any LLM tool call runs."""
from __future__ import annotations

MAX_CONTENT_BYTES = 200_000
MAX_LINES = 5_000
ALLOWED_KINDS = {"log", "sql", "file"}
ALLOWED_ACTIONS = {"redact", "escalate", "dismiss"}
MAX_RATIONALE = 400


class ValidationError(ValueError):
    pass


def validate_scan_input(name: str, kind: str, content: str) -> tuple[str, str, str]:
    name = (name or "").strip()
    if not name or len(name) > 120:
        raise ValidationError("name must be 1 to 120 characters")
    if kind not in ALLOWED_KINDS:
        raise ValidationError(f"kind must be one of {sorted(ALLOWED_KINDS)}")
    if not isinstance(content, str) or not content.strip():
        raise ValidationError("content is empty")
    if "\x00" in content:
        raise ValidationError("binary content is not supported")
    if len(content.encode("utf-8")) > MAX_CONTENT_BYTES:
        raise ValidationError(f"content is larger than {MAX_CONTENT_BYTES} bytes")
    if content.count("\n") + 1 > MAX_LINES:
        raise ValidationError(f"content has more than {MAX_LINES} lines")
    safe_name = "".join(c for c in name if c.isprintable() and c not in "<>")
    return safe_name, kind, content


def validate_tool_call(name: str, args: dict, valid_finding_ids: set[int]) -> dict:
    """Validate arguments the model produced. Anything off is rejected, not repaired."""
    if name == "list_findings":
        return {}
    if name == "get_finding_context":
        fid = args.get("finding_id")
        if not isinstance(fid, int) or fid not in valid_finding_ids:
            raise ValidationError("unknown finding_id")
        return {"finding_id": fid}
    if name == "propose_action":
        fid = args.get("finding_id")
        action = args.get("action")
        rationale = args.get("rationale", "")
        if not isinstance(fid, int) or fid not in valid_finding_ids:
            raise ValidationError("unknown finding_id")
        if action not in ALLOWED_ACTIONS:
            raise ValidationError(f"action must be one of {sorted(ALLOWED_ACTIONS)}")
        if not isinstance(rationale, str) or not rationale.strip():
            raise ValidationError("rationale is required")
        return {"finding_id": fid, "action": action, "rationale": rationale.strip()[:MAX_RATIONALE]}
    raise ValidationError(f"unknown tool {name!r}")

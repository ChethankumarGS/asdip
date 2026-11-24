"""Rule-based detectors for sensitive data in logs, SQL and plain files.

Findings never carry the raw secret. They carry the line number, the column
span (used only for redaction) and a masked preview, so downstream code and
the LLM layer only ever see masked values.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, asdict

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Detector:
    rule_id: str
    title: str
    severity: str
    pattern: re.Pattern
    applies_to: tuple = ("log", "sql", "file")
    validator: object = None  # optional callable(match_text) -> bool


def luhn_ok(text: str) -> bool:
    digits = [int(c) for c in re.sub(r"\D", "", text)]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


DETECTORS = [
    Detector("PRIVATE_KEY", "Private key block", "critical",
             re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    Detector("AWS_ACCESS_KEY", "AWS access key id", "critical",
             re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    Detector("API_KEY_ASSIGNMENT", "Hard-coded API key or secret", "high",
             re.compile(r"(?i)\b(?:api[_-]?key|secret|token|passwd|password)\b\s*[:=]\s*['\"]?([A-Za-z0-9_\-/.+]{8,})['\"]?")),
    Detector("JWT", "JSON Web Token", "high",
             re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    Detector("CREDIT_CARD", "Payment card number (Luhn valid)", "critical",
             re.compile(r"\b(?:\d[ -]?){13,19}\b"), validator=luhn_ok),
    Detector("EMAIL", "Email address", "medium",
             re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    Detector("IN_AADHAAR_LIKE", "Aadhaar-style 12 digit id", "high",
             re.compile(r"\b\d{4}\s\d{4}\s\d{4}\b")),
    Detector("US_SSN", "US SSN pattern", "high",
             re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    Detector("PHONE", "Phone number", "medium",
             re.compile(r"(?<!\d)(?:\+\d{1,3}[ -]?)?(?:\(\d{3}\)|\d{3})[ -]\d{3}[ -]\d{4}(?!\d)")),
    Detector("IPV4", "IPv4 address", "low",
             re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
             applies_to=("log", "file")),
]

# SQL statements that are risky regardless of literal values.
SQL_RULES = [
    ("SQL_SELECT_STAR_PII", "SELECT * on a table that looks like it holds personal data", "medium",
     re.compile(r"(?i)\bselect\s+\*\s+from\s+\w*(?:user|customer|patient|employee|account|payment)\w*")),
    ("SQL_DELETE_NO_WHERE", "DELETE or UPDATE without a WHERE clause", "high",
     re.compile(r"(?i)^\s*(?:delete\s+from\s+\w+|update\s+\w+\s+set\s+[^;]*?)\s*;?\s*$")),
    ("SQL_GRANT_ALL", "Broad GRANT ALL privileges", "high",
     re.compile(r"(?i)\bgrant\s+all\b")),
    ("SQL_PLAINTEXT_PASSWORD", "Password literal in SQL", "critical",
     re.compile(r"(?i)\bidentified\s+by\s+'[^']+'|\bpassword\s*=\s*'[^']+'")),
]


def mask(rule_id: str, text: str) -> str:
    """Return a preview that cannot be reversed to the original value."""
    if rule_id == "EMAIL":
        local, _, domain = text.partition("@")
        return f"{local[:1]}***@{domain}"
    if rule_id in ("CREDIT_CARD", "US_SSN", "IN_AADHAAR_LIKE", "PHONE"):
        digits = re.sub(r"\D", "", text)
        return "*" * max(len(digits) - 4, 0) + digits[-4:]
    if rule_id in ("IPV4",):
        parts = text.split(".")
        return ".".join(parts[:2] + ["*", "*"])
    if rule_id == "PRIVATE_KEY":
        return "-----BEGIN ... PRIVATE KEY-----"
    return text[:4] + "*" * 6 if len(text) > 4 else "****"


def scan_text(content: str, kind: str) -> list[dict]:
    findings: list[dict] = []
    lines = content.splitlines()
    for lineno, line in enumerate(lines, start=1):
        taken: list[tuple[int, int]] = []

        def free(s: int, e: int) -> bool:
            return all(e <= a or s >= b for a, b in taken)

        for det in DETECTORS:
            if kind not in det.applies_to:
                continue
            for m in det.pattern.finditer(line):
                group = 1 if det.pattern.groups else 0
                s, e = m.start(group), m.end(group)
                text = m.group(group)
                if det.validator and not det.validator(text):
                    continue
                if det.rule_id == "API_KEY_ASSIGNMENT" and re.fullmatch(r"[A-Za-z_]+", text) and not any(c.isdigit() for c in text):
                    continue  # plain word such as "password=required"
                if not free(s, e):
                    continue
                taken.append((s, e))
                findings.append(_finding(det.rule_id, det.title, det.severity, lineno, s, e, text))
        if kind == "sql":
            for rule_id, title, sev, pat in SQL_RULES:
                m = pat.search(line)
                if m and free(m.start(), m.end()):
                    # statement-level risk: nothing is redacted, a reviewer decides
                    findings.append(_finding(rule_id, title, sev, lineno, m.start(), m.end(), m.group(0), statement=True))
    for i, f in enumerate(findings, start=1):
        f["id"] = i
    return findings


def _finding(rule_id, title, severity, lineno, s, e, text, statement=False) -> dict:
    return {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "line": lineno,
        "start": s,
        "end": e,
        "preview": "statement flagged" if statement else mask(rule_id, text),
        "statement_level": statement,
    }


def risk_score(findings: list[dict]) -> int:
    return sum(SEVERITY_ORDER[f["severity"]] ** 2 for f in findings)

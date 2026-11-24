# ASDIP: AI Secure Data Intelligence & Agentic Audit Platform

A small, working platform that scans logs, SQL and text files for sensitive data risks and routes every
proposed fix through a human reviewer before anything is applied.

Stack: Python, FastAPI, SQLite, React (Vite), optional LLM API with tool calling.

## What it does

1. **Scan.** Rule-based detectors find emails, phone numbers, Luhn-valid card numbers, SSN and Aadhaar-style ids,
   AWS keys, JWTs, private keys, hard-coded secrets and IPs. SQL scans also flag risky statements
   (`SELECT *` on personal-data tables, `DELETE`/`UPDATE` with no `WHERE`, `GRANT ALL`, password literals).
2. **Validate input.** Size, line count, type and binary content are checked before scanning. Every tool call a
   model makes is validated too (known finding id, allowed action, required rationale). Invalid calls are
   rejected and never become proposals.
3. **AI review via tool calling.** A reviewer agent uses three tools (`list_findings`, `get_finding_context`,
   `propose_action`) to propose `redact`, `escalate` or `dismiss` for each finding. It only sees masked previews.
4. **Human-in-the-loop approvals.** Proposals stay `pending`. Only an approved `redact` changes the output text.
   Every scan, proposal and decision is written to an audit log.
5. **Review dashboard.** Accessible React UI (labelled controls, table captions, live status region, visible focus).

## LLM modes (read this)

* **Default: `offline-rules`.** No language model. A deterministic policy plays the reviewer so the demo and tests
  run without keys. The UI badge says "Offline rules (no LLM)".
* **LLM mode.** Set `ASDIP_LLM_API_KEY` (optional `ASDIP_LLM_BASE_URL`, `ASDIP_LLM_MODEL`) to use any OpenAI
  compatible chat-completions API with tool calling. This path is implemented but not exercised in CI. The tests
  cover the tool loop with a scripted stand-in model.

## Run

```bash
cd backend && pip install -r requirements.txt
cd ../frontend && npm install && npm run build
cd ../backend && uvicorn app.main:app --port 8000   # open http://localhost:8000
python -m pytest                                      # 10 tests
```

Dev mode for the UI: `npm run dev` in `frontend/` (proxies `/api` to port 8000).

## Limits

* Detectors are regex rules plus a Luhn check. They will miss unusual formats and can raise false positives.
* Scan content is stored in a local SQLite file (`asdip.db`). There is no authentication or multi-user model.
* The "55% faster audit review" figure on the author's CV was not measured by this repo. No benchmark is included.
* Sample data in `samples/` is synthetic.

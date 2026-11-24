import React, { useEffect, useState, useCallback } from "react";

const SAMPLES = {
  log: `2026-03-02 10:14:01 INFO  login ok user=asha.rao@example.test ip=203.0.113.24
2026-03-02 10:14:09 WARN  payment retry card=4111 1111 1111 1111 amount=499.00
2026-03-02 10:15:30 ERROR config load failed api_key=sk_test_FAKE0123456789abcd
2026-03-02 10:16:02 INFO  support call back +1 415-555-0132
2026-03-02 10:17:44 DEBUG aws key AKIAFAKEFAKEFAKE1234 used by worker-3
2026-03-02 10:18:00 INFO  health check ok`,
  sql: `-- synthetic demo data only
SELECT * FROM customer_accounts;
INSERT INTO users(name, email, ssn) VALUES ('Demo Person', 'demo.person@example.test', '123-45-6789');
CREATE USER reporter IDENTIFIED BY 'Winter2026!';
GRANT ALL ON warehouse.* TO reporter;
DELETE FROM sessions;
SELECT id, total FROM orders WHERE id = 7;`,
};

async function api(path, options) {
  const res = await fetch(`/api${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.detail || `Request failed (${res.status})`);
  return body;
}

export default function App() {
  const [health, setHealth] = useState(null);
  const [name, setName] = useState("app.log");
  const [kind, setKind] = useState("log");
  const [content, setContent] = useState(SAMPLES.log);
  const [scan, setScan] = useState(null);
  const [redacted, setRedacted] = useState(null);
  const [audit, setAudit] = useState([]);
  const [reviewer, setReviewer] = useState("reviewer");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  const refreshAudit = useCallback(() => api("/audit").then(setAudit).catch(() => {}), []);
  useEffect(() => {
    api("/health").then(setHealth).catch(() => setMessage("Backend not reachable."));
    refreshAudit();
  }, [refreshAudit]);

  const run = async (fn, ok) => {
    setBusy(true);
    setMessage("");
    try {
      await fn();
      if (ok) setMessage(ok);
    } catch (e) {
      setMessage(`Error: ${e.message}`);
    } finally {
      setBusy(false);
      refreshAudit();
    }
  };

  const loadRedacted = (id) => api(`/scans/${id}/redacted`).then(setRedacted);
  const submitScan = () =>
    run(async () => {
      const s = await api("/scans", { method: "POST", body: JSON.stringify({ name, kind, content }) });
      setScan(s);
      await loadRedacted(s.id);
    }, "Scan complete. Run the AI review to get proposals.");
  const review = () =>
    run(async () => {
      setScan(await api(`/scans/${scan.id}/review`, { method: "POST" }));
    }, "Proposals created. Nothing is applied until you approve.");
  const decide = (p, decision) =>
    run(async () => {
      await api(`/proposals/${p.id}/decision`, { method: "POST", body: JSON.stringify({ decision, reviewer }) });
      setScan(await api(`/scans/${scan.id}`));
      await loadRedacted(scan.id);
    }, `Proposal ${decision === "approve" ? "approved" : "rejected"}.`);

  const findingById = (id) => scan?.findings.find((f) => f.id === id);
  const pending = scan?.proposals.filter((p) => p.status === "pending").length ?? 0;

  return (
    <main>
      <header>
        <h1>ASDIP</h1>
        <p className="sub">AI Secure Data Intelligence &amp; Agentic Audit Platform</p>
        {health && (
          <p className={`badge ${health.provider_mode}`} data-testid="provider">
            Reviewer: {health.provider_label}
          </p>
        )}
      </header>

      <div role="status" aria-live="polite" className="message">{message}</div>

      <section aria-labelledby="new-scan">
        <h2 id="new-scan">1. Scan input</h2>
        <div className="row">
          <label>Name
            <input value={name} onChange={(e) => setName(e.target.value)} maxLength={120} />
          </label>
          <label>Type
            <select value={kind} onChange={(e) => setKind(e.target.value)}>
              <option value="log">Log</option>
              <option value="sql">SQL</option>
              <option value="file">Text file</option>
            </select>
          </label>
          <div className="samples">
            <button type="button" className="ghost" onClick={() => { setName("app.log"); setKind("log"); setContent(SAMPLES.log); }}>Load sample log</button>
            <button type="button" className="ghost" onClick={() => { setName("report.sql"); setKind("sql"); setContent(SAMPLES.sql); }}>Load sample SQL</button>
          </div>
        </div>
        <label>Content (synthetic data only in this demo)
          <textarea rows={8} value={content} onChange={(e) => setContent(e.target.value)} spellCheck={false} />
        </label>
        <button type="button" onClick={submitScan} disabled={busy}>Scan for sensitive data</button>
      </section>

      {scan && (
        <>
          <section aria-labelledby="findings">
            <h2 id="findings">2. Findings <span className="count">{scan.findings.length}</span> <span className="count">risk {scan.risk}</span></h2>
            {scan.findings.length === 0 ? <p>No findings.</p> : (
              <table>
                <caption className="sr">Findings with masked previews</caption>
                <thead><tr><th>#</th><th>Severity</th><th>Rule</th><th>Line</th><th>Masked preview</th></tr></thead>
                <tbody>
                  {scan.findings.map((f) => (
                    <tr key={f.id}>
                      <td>{f.id}</td>
                      <td><span className={`sev ${f.severity}`}>{f.severity}</span></td>
                      <td>{f.title}</td><td>{f.line}</td><td><code>{f.preview}</code></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            <button type="button" onClick={review} disabled={busy || scan.findings.length === 0}>Run AI review</button>
          </section>

          <section aria-labelledby="approvals">
            <h2 id="approvals">3. Human approvals <span className="count">{pending} pending</span></h2>
            <label className="inline">Reviewer name
              <input value={reviewer} onChange={(e) => setReviewer(e.target.value)} maxLength={60} />
            </label>
            {scan.proposals.length === 0 ? <p>No proposals yet.</p> : (
              <ul className="proposals">
                {scan.proposals.map((p) => {
                  const f = findingById(p.finding_id);
                  return (
                    <li key={p.id}>
                      <div>
                        <strong>{p.action}</strong> finding #{p.finding_id}
                        {f && <> ({f.title}, line {f.line})</>}
                        <div className="why">{p.rationale}</div>
                        <div className="why">Proposed by {p.proposed_by}</div>
                      </div>
                      {p.status === "pending" ? (
                        <div className="actions">
                          <button type="button" onClick={() => decide(p, "approve")} disabled={busy}>Approve</button>
                          <button type="button" className="ghost" onClick={() => decide(p, "reject")} disabled={busy}>Reject</button>
                        </div>
                      ) : <span className={`status ${p.status}`}>{p.status} by {p.reviewer}</span>}
                    </li>
                  );
                })}
              </ul>
            )}
          </section>

          <section aria-labelledby="out">
            <h2 id="out">4. Output after approved redactions</h2>
            <pre aria-label="Redacted output">{redacted?.content}</pre>
            <p className="why">{redacted?.applied ?? 0} redaction(s) applied. Only approved redactions change the text.</p>
          </section>
        </>
      )}

      <section aria-labelledby="audit">
        <h2 id="audit">Audit log</h2>
        <table>
          <caption className="sr">Audit events, newest first</caption>
          <thead><tr><th>Time (UTC)</th><th>Actor</th><th>Event</th><th>Scan</th></tr></thead>
          <tbody>
            {audit.slice(0, 8).map((a) => (
              <tr key={a.id}><td>{a.ts.replace("T", " ").slice(0, 19)}</td><td>{a.actor}</td><td>{a.event}</td><td>{a.scan_id ?? ""}</td></tr>
            ))}
          </tbody>
        </table>
      </section>
    </main>
  );
}

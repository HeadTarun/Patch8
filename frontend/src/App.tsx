import { useEffect, useMemo, useRef, useState } from "react";
import { Activity, ArrowDownToLine, ArrowRight, Check, ChevronRight, CircleAlert, Clock3, Code2, Cpu, FileArchive, FileCode2, Fingerprint, LoaderCircle, LockKeyhole, RefreshCw, ShieldCheck, Sparkles, UploadCloud, X } from "lucide-react";

type Cwe = { id: string; name: string; description: string; url: string; mitigations: string[]; mapping_usage?: string; top25_2025_rank?: number | null };
type Finding = { id: string; file: string; line: number; rule_id: string; message: string; source_tool: string; source_tools: string[]; classification: string; cwe: Cwe | null; mapping_confidence: string; mapping_rationale: string; analyzer_confidence: string; severity: string; risk_context: string; evidence: string };
type CheckState = "passed" | "failed" | "running" | "not_available" | "not_measured" | "not_run" | "baseline_ready" | "measured" | "unverified";
type AnalysisView = { product: string; ir_version: string; mode: string; status: string; coverage: { languages: string[]; supported_families: string[]; analyzer_status: Record<string, { status: string; error?: string | null }>; notes: string[] }; records: unknown[]; errors: string[]; comparison?: { counts: { legacy: number; ir: number; matched: number; legacy_only: number; ir_only: number }; legacy_only: Finding[]; ir_only: Finding[] } };
type Checks = { build: CheckState; tests: CheckState; sanitizers: CheckState; security?: CheckState; verification?: CheckState; security_details?: string; details?: string; performance: CheckState };
type Job = { id: string; state: string; progress?: string; error?: string; source_files?: number; findings: Finding[]; checks: Checks; performance?: { baseline_median_ms: number; patched_median_ms: number; delta_percent: number | null } | null; report?: { source_files: number; taxonomy_version: string; scan_status?: string; analyzer_status?: Record<string, { status: string; error?: string | null }>; summary?: { candidates: number }; analysis?: AnalysisView; shadow_analysis?: AnalysisView }; repair?: Repair };
type Repair = { id: string; finding_id: string; file: string; diff: string; explanation: string; state: string };

const API = "/api";
const STATUS_LABEL: Record<string, string> = { passed: "Passed", failed: "Failed", running: "Running", not_available: "Not available", not_measured: "Not measured", not_run: "Not run", baseline_ready: "Baseline ready", measured: "Measured", unverified: "Unverified" };

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, init);
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(typeof body.detail === "string" ? body.detail : body.detail?.message || `Request failed (${response.status})`);
  }
  return response.json() as Promise<T>;
}

function App() {
  const input = useRef<HTMLInputElement>(null);
  const [job, setJob] = useState<Job | null>(null);
  const [selectedId, setSelectedId] = useState("");
  const [repair, setRepair] = useState<Repair | null>(null);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    if (!job || !["queued", "analyzing", "validating", "verifying"].includes(job.state)) return;
    const timer = window.setInterval(async () => {
      try {
        const updated = await request<Job>(`${API}/jobs/${job.id}`);
        setJob(updated);
        if (updated.repair) setRepair(updated.repair);
        if (updated.state === "failed" || updated.state === "complete") window.clearInterval(timer);
      } catch (cause) { setError(cause instanceof Error ? cause.message : "Could not refresh scan."); }
    }, 1600);
    return () => window.clearInterval(timer);
  }, [job?.id, job?.state]);

  const selected = useMemo(() => job?.findings.find((finding) => finding.id === selectedId) ?? job?.findings[0] ?? null, [job, selectedId]);
  const running = job && ["queued", "analyzing", "validating", "verifying"].includes(job.state);

  async function upload(file?: File) {
    if (!file) return;
    setError(""); setRepair(null); setBusy("upload");
    try {
      const form = new FormData(); form.append("file", file);
      const created = await request<{ id: string }>(`${API}/jobs`, { method: "POST", body: form });
      setJob({ id: created.id, state: "queued", findings: [], checks: { build: "not_available", tests: "not_available", sanitizers: "not_available", security: "not_run", verification: "not_run", performance: "not_measured" } });
      setSelectedId("");
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Upload failed."); }
    finally { setBusy(""); if (input.current) input.current.value = ""; }
  }

  async function makeRepair() {
    if (!job || !selected) return;
    setBusy("repair"); setError("");
    try {
      const result = await request<Repair>(`${API}/jobs/${job.id}/repair/${selected.id}`, { method: "POST" });
      setRepair(result);
      setJob(await request<Job>(`${API}/jobs/${job.id}`));
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Repair generation failed."); }
    finally { setBusy(""); }
  }

  async function applyRepair() {
    if (!job || !repair) return;
    const partial = job.checks?.verification === "unverified";
    if (partial && !window.confirm("Some verification checks were unavailable. Accept this working copy with those limitations?")) return;
    setBusy("apply"); setError("");
    try {
      await request(`${API}/jobs/${job.id}/apply/${repair.id}?confirm_partial=${partial}`, { method: "POST" });
      const updated = await request<Job>(`${API}/jobs/${job.id}`);
      setJob(updated);
      setRepair(updated.repair || { ...repair, state: "validating" });
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Could not apply patch."); }
    finally { setBusy(""); }
  }

  function reset() { setJob(null); setRepair(null); setSelectedId(""); setError(""); }

  return <div className="app-shell">
    <header className="topbar">
      <a className="brand" href="#top" aria-label="PatchProof home"><span className="brand-mark"><img src="/firmware/patchproof-mark.svg" alt=""/></span><span className="brand-wordmark"><span>Patch</span><span>Proof</span></span></a>
      <div className="top-links"><span className="top-link"><span className="live-dot"/> CWE 5.0 / Schema 8.0</span><span className="top-divider"/><span className="top-link"><LockKeyhole size={14}/> ephemeral workspace</span></div>
      <a className="github-link" href="https://cwe.mitre.org/data/" target="_blank" rel="noreferrer">CWE catalog <ArrowRight size={14}/></a>
    </header>

    <main id="top">
      {!job ? <section className="hero-layout">
        <div className="hero-copy">
          <div className="eyebrow"><span className="eyebrow-line"/> FIRMWARE SECURITY WORKBENCH <span className="eyebrow-version">MVP 0.1</span></div>
          <h1>Find the flaw.<br/><span>Prove the fix.</span></h1>
          <p className="hero-lede">A C/C++ firmware scanner that connects every repair to its weakness, source evidence, and validation results.</p>
          <div className="hero-trust"><span><Check size={15}/> CWE-linked findings</span><span><Check size={15}/> Reviewable patches</span><span><Check size={15}/> Isolated analysis</span></div>
          <div className="signal-card"><div className="signal-icon"><Activity size={18}/></div><div><div className="signal-title">An evidence chain for every repair</div><p>Finding <ChevronRight size={12}/> CWE <ChevronRight size={12}/> Patch <ChevronRight size={12}/> Checks</p></div><div className="signal-badge">TRACEABLE</div></div>
        </div>
        <section className="upload-card" aria-label="Start a firmware scan">
          <div className="card-heading"><div><span className="card-kicker">START A NEW SCAN</span><h2>Bring your firmware</h2></div><span className="step-mark">01 <span>/ 03</span></span></div>
          <button className="drop-zone" onClick={() => input.current?.click()} onDragOver={(event) => event.preventDefault()} onDrop={(event) => { event.preventDefault(); void upload(event.dataTransfer.files[0]); }} disabled={!!busy}>
            <span className="upload-icon"><UploadCloud size={22}/></span><strong>Drop a project ZIP or source file here</strong><span>or browse your files</span><small>ZIP · up to 25 MB &nbsp; C/C++ source · up to 200 KB</small>
          </button>
          <input ref={input} type="file" accept=".zip,.c,.cpp,application/zip,text/plain" hidden onChange={(event) => void upload(event.target.files?.[0])}/>
          <div className="privacy-note"><LockKeyhole size={14}/><span>AI requests may send relevant source to the configured cloud fallback.</span></div>
          {busy === "upload" && <div className="inline-loading"><LoaderCircle size={16} className="spin"/> Creating isolated scan…</div>}
          {error && <div className="error-banner" role="alert"><CircleAlert size={15}/>{error}</div>}
        </section>
      </section> : <section className="workspace">
        <div className="workspace-head"><div><div className="eyebrow"><span className="eyebrow-line"/> FIRMWARE SECURITY WORKBENCH</div><h1 className="workspace-title">Scan <span>workspace</span></h1></div><button className="button button-quiet" onClick={reset}><RefreshCw size={15}/> New scan</button></div>
          {running ? <div className="scan-progress"><div className="progress-orbit"><LoaderCircle size={25} className="spin"/></div><div><div className="progress-title">{job.state === "validating" ? "Validating the patched copy" : "Analyzing your project"}</div><p>{job.progress || "Waiting for the isolated worker…"}</p><div className="progress-track"><span/></div></div><span className="scan-state"><span className="live-dot"/> {job.state}</span></div> : job.state === "failed" ? <div className="error-banner large"><CircleAlert/>{job.error || "Scan failed."}</div> : <>
          {error && <div className="error-banner" role="alert"><CircleAlert size={15}/>{error}</div>}
          <div className="report-toolbar"><div className="project-meta"><span className="project-icon"><FileArchive size={18}/></span><span><b>{job.id.slice(0, 8)} scan</b><small>Source files: {job.source_files ?? job.report?.source_files ?? 0} · CWE {job.report?.taxonomy_version || "5.0"}</small></span></div><div className="toolbar-actions"><a className="button button-outline" href={`${API}/jobs/${job.id}/sarif`}><ArrowDownToLine size={15}/> Export SARIF</a><span className="expiry"><Clock3 size={14}/> one-hour TTL</span></div></div>
          {job.report?.scan_status && <section className={`analysis-status ${job.report.scan_status.toLowerCase()}`}><b>Detection status: {job.report.scan_status}</b><div>{Object.entries(job.report.analyzer_status || {}).map(([name, status]) => <span key={name}>{name}: {status.status}{status.error ? ` — ${status.error}` : ""}</span>)}</div></section>}
          {(job.report?.shadow_analysis || job.report?.analysis) && (() => {
            const analysis = job.report?.shadow_analysis || job.report?.analysis;
            if (!analysis) return null;
            return <details className="ir-inspector"><summary>PatchProof analysis details · {analysis.mode} · IR {analysis.ir_version}</summary><div className="ir-summary"><span><b>Status</b>{analysis.status}</span><span><b>Languages</b>{analysis.coverage.languages.join(", ") || "unknown"}</span><span><b>Families</b>{analysis.coverage.supported_families.join(", ")}</span>{analysis.comparison && <span><b>Legacy / IR matches</b>{analysis.comparison.counts.matched} of {analysis.comparison.counts.legacy} / {analysis.comparison.counts.ir}</span>}</div><div className="ir-analyzers">{Object.entries(analysis.coverage.analyzer_status).map(([name, status]) => <span key={name}>{name}: {status.status}{status.error ? ` — ${status.error}` : ""}</span>)}</div>{analysis.coverage.notes.map((note) => <p className="ir-note" key={note}>{note}</p>)}{analysis.errors.map((item, index) => <p className="ir-error" key={`${index}-${item}`}>{item}</p>)}{analysis.comparison && <div className="ir-differences"><b>Disagreements</b><span>Legacy only: {analysis.comparison.counts.legacy_only}; IR only: {analysis.comparison.counts.ir_only}</span>{analysis.comparison.legacy_only.length > 0 && <pre>{JSON.stringify(analysis.comparison.legacy_only, null, 2)}</pre>}{analysis.comparison.ir_only.length > 0 && <pre>{JSON.stringify(analysis.comparison.ir_only, null, 2)}</pre>}</div>}<div className="ir-records"><b>Common intermediate representation ({analysis.records.length})</b><pre>{JSON.stringify(analysis.records, null, 2)}</pre></div></details>;
          })()}
          <div className="evidence-grid"><Evidence icon={<Code2 size={16}/>} label="Build" state={job.checks?.build || "not_available"}/><Evidence icon={<Check size={16}/>} label="Tests" state={job.checks?.tests || "not_available"}/><Evidence icon={<Activity size={16}/>} label="Sanitizers" state={job.checks?.sanitizers || "not_available"}/><Evidence icon={<ShieldCheck size={16}/>} label="Security" state={job.checks?.security || "not_run"}/><Evidence icon={<Check size={16}/>} label="Verification" state={job.checks?.verification || "not_run"}/><Evidence icon={<Cpu size={16}/>} label="Performance" state={job.checks?.performance || "not_measured"}/></div>
          {job.checks?.security_details && <div className="benchmark-note">Security verification: {job.checks.security_details}</div>}
          {job.performance && <div className="benchmark-note">Benchmark median: {job.performance.baseline_median_ms} ms → {job.performance.patched_median_ms} ms <span>Δ {job.performance.delta_percent === null ? "unavailable" : `${job.performance.delta_percent > 0 ? "+" : ""}${job.performance.delta_percent}%`}</span></div>}
          <div className="findings-layout">
            <section className="findings-panel"><div className="section-head"><div><span className="card-kicker">STATIC ANALYSIS</span><h2>Findings and candidates <span className="count-pill">{job.findings.length}</span></h2></div><div className="analyzer-label"><span className="live-dot"/> Clang + Cppcheck + Semgrep</div></div>
              <div className="finding-list">{job.findings.length ? job.findings.map((finding) => <button key={finding.id} className={`finding-row ${selected?.id === finding.id ? "selected" : ""}`} onClick={() => { setSelectedId(finding.id); setRepair(null); }}><span className={`finding-mark ${finding.classification === "SUSPICIOUS_CANDIDATE" ? "medium" : finding.severity === "error" ? "high" : "medium"}`}><CircleAlert size={16}/></span><span className="finding-main"><span className="finding-title">{finding.cwe?.name || "Suspicious buffer operation"}</span><span className="finding-location"><FileCode2 size={13}/>{finding.file}<i>:</i>{finding.line}</span></span><span className="cwe-chip">{finding.cwe?.id || "Candidate"}</span><ChevronRight size={15} className="row-chevron"/></button>) : <div className="empty-findings"><span className="empty-shield"><ShieldCheck size={24}/></span><b>No supported findings or candidates reported</b><p>Scanners did not report the supported CWE classes in this project. This is not proof that the firmware is vulnerability-free.</p></div>}</div>
            </section>
            <aside className="detail-panel">{selected ? <><div className="detail-top"><div className="detail-label">{selected.classification === "SUSPICIOUS_CANDIDATE" ? "CANDIDATE DETAILS" : "FINDING DETAILS"} <span>#{selected.id.slice(0, 6)}</span></div><span className="severity-tag">{selected.source_tools.join(", ")}</span></div><h2>{selected.cwe?.name || "Suspicious buffer operation"}</h2>{selected.cwe && <div className="detail-tags"><span className="cwe-chip">{selected.cwe.id}</span>{selected.cwe.top25_2025_rank && <span className="top25-chip" title="General software and CVE context; not a device-specific risk rating">2025 Top 25 · #{selected.cwe.top25_2025_rank}</span>}<a href={selected.cwe.url} target="_blank" rel="noreferrer">MITRE record <ArrowRight size={12}/></a></div>}{selected.cwe && <p className="detail-description">{selected.cwe.description}</p>}<div className="detail-block"><span className="detail-label">ANALYZER EVIDENCE</span><p>{selected.message}</p><small>{selected.file}:{selected.line} · {selected.rule_id}</small><pre className="evidence-code">{selected.evidence}</pre></div><div className="confidence-line"><span><Fingerprint size={14}/> Classification</span><b>{selected.classification.replaceAll("_", " ")}</b></div><div className="confidence-line"><span><Activity size={14}/> Analyzer confidence</span><b>{selected.analyzer_confidence}</b></div>{selected.cwe && <><div className="confidence-line"><span>Contextual risk</span><b>Not assessed</b></div><div className="confidence-line"><span>CWE mapping confidence</span><b>{selected.mapping_confidence}</b></div><div className="detail-block"><span className="detail-label">MAPPING RATIONALE</span><p>{selected.mapping_rationale}</p></div>{selected.cwe.mapping_usage && <div className="mitigation"><span className="detail-label">MITRE MAPPING USE</span><p>{selected.cwe.mapping_usage}</p></div>}{selected.cwe.mitigations?.[0] && <div className="mitigation"><span className="detail-label">CWE MITIGATION GUIDANCE</span><p>{selected.cwe.mitigations[0]}</p></div>}</>}{selected.cwe && <button className="button button-primary repair-button" onClick={() => void makeRepair()} disabled={!!busy}>{busy === "repair" ? <><LoaderCircle size={16} className="spin"/> Generating patch…</> : <><Sparkles size={16}/> Generate repair proposal</>}</button>}</> : <div className="empty-detail"><FileCode2 size={26}/><b>Select a finding</b><span>Source location, weakness mapping, and repair options will appear here.</span></div>}</aside>
          </div>
          {repair && <section className="repair-panel"><div className="repair-head"><div><span className="card-kicker">REPAIR PROPOSAL</span><h2>Review before applying</h2></div><span className={`proposal-state ${repair.state === "applied_to_copy" ? "applied" : ""}`}>{repair.state === "applied_to_copy" ? <><Check size={13}/> applied to copy</> : <><Sparkles size={13}/> proposed</>}</span></div><p className="repair-explanation">{repair.explanation || "Minimal source change proposed for this finding."}</p><div className="diff-head"><span><FileCode2 size={14}/> {repair.file}</span><span>UNIFIED DIFF</span></div><pre className="diff-view">{repair.diff.split("\n").map((line, index) => <span key={index} className={line.startsWith("+") && !line.startsWith("+++") ? "diff-add" : line.startsWith("-") && !line.startsWith("---") ? "diff-remove" : line.startsWith("@@") ? "diff-hunk" : ""}>{line}{"\n"}</span>)}</pre><div className="repair-actions">{repair.state !== "applied_to_copy" ? <button className="button button-primary" onClick={() => void applyRepair()} disabled={!!busy || repair.state !== "review_ready"}>{busy === "apply" ? <><LoaderCircle size={15} className="spin"/> Applying…</> : <><Check size={15}/> Accept verified copy</>}</button> : <a className="button button-primary" href={`${API}/jobs/${job.id}/download`}><ArrowDownToLine size={15}/> Download patched ZIP</a>}<a className="button button-outline" href={`${API}/jobs/${job.id}/diff`}><ArrowDownToLine size={15}/> Download diff</a><span className="patch-disclaimer">Proposed code is untrusted until independently reviewed and tested.</span></div></section>}
        </>}
      </section>}
    </main>

    <footer className="footer"><span><span className="brand-mini"><img src="/firmware/patchproof-mark.svg" alt=""/></span><span className="brand-wordmark"><span>Patch</span><span>Proof</span></span> <span className="footer-sep">/</span> FIRMWARE REPAIR LAB</span><span>CWE IDs describe weakness types; analysis coverage is limited.</span><span>Built for safer embedded software <span className="footer-heart">✳</span></span></footer>
  </div>;
}

function Evidence({ icon, label, state }: { icon: React.ReactNode; label: string; state: CheckState }) {
  const good = state === "passed";
  const bad = state === "failed";
  return <div className={`evidence-card ${good ? "good" : ""} ${bad ? "bad" : ""}`}><span className="evidence-icon">{icon}</span><span className="evidence-label">{label}</span><span className="evidence-state">{good ? <Check size={12}/> : bad ? <X size={12}/> : null}{STATUS_LABEL[state] || state}</span></div>;
}


export default App;

export type Severity = "critical" | "high" | "medium" | "low" | "informational" | "unassessed";
export type Repo = { id: string; name: string; branch: string; lastScan: string; findings: number; provider: "Upload" | "GitHub"; private: boolean };
export type Scan = { id: string; repo: string; branch: string; pr: number; status: "No findings reported" | "Needs attention" | "Running" | "Failed" | "Partial" | "Not verified"; time: string; findings: number; jobId: string; state: string };
export type Finding = { id: string; jobId: string; title: string; severity: Severity; tool: string; file: string; line: number; status: string; cwe: string; description: string; evidence: string; analyzerSeverity: string };
export type Patch = { id: string; findingId: string; explanation: string; diff: string; file: string; provider: string; state: string; metadata?: {line:number; added_lines:number; deleted_lines:number; reasons:string[]; security_improvement:string; warnings:string[]} };
export type FindingExplanation = { summary: string; impact: string; recommended_action: string; provider_used: string };
export type BuildDiagnostic = {category:string; file:string; line:number; column:number; message:string; source:"original"|"proposed"};
export type RepairChecks = { [key:string]:string|boolean|BuildDiagnostic[]|undefined; details?:string; security_details?:string; build_diagnostics?:BuildDiagnostic[]; baseline_shared_dependency?:boolean; verification_outcome?:string};
export type GitHubRepository = { full_name: string; default_branch: string; description?: string | null; updated_at?: string };
export type AnalysisReport = { scan_status?: "COMPLETED" | "PARTIAL" | "FAILED"; analyzer_status?: Record<string, {status:string; error?:string|null}>; [key:string]:any };
export type Job = { id: string; name: string; provider: string; state: string; created_at: number; progress?: string; findings?: any[]; checks?: Record<string, string>; error?: string; report?: AnalysisReport; repair?: any; source_files?: number; uploaded_files?: string[]; source?: { type: "github"; repository: string; branch: string; commit_sha: string } };
export type Dashboard = { open: number; critical: number; scanned: number; fixed: number; scans: Scan[]; findings: Finding[]; bySeverity: Record<Severity, number> };

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api${path}`, { ...init, headers: { ...(init?.body instanceof FormData ? {} : { "Content-Type": "application/json" }), ...init?.headers }, cache: "no-store", signal: init?.signal || AbortSignal.timeout(210_000) });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    const detail = payload.detail;
    const message = typeof detail === "string" ? detail : detail?.message || detail?.user_message || (detail?.code ? `The repair could not be matched safely (${detail.code.replaceAll("_", " ")}). Check the source preview and repair status for details.` : `Request failed (${response.status}).`);
    throw new Error(message);
  }
  return response.json().catch(() => { throw new Error("The server returned an unreadable response. Retry the request."); }) as Promise<T>;
}

export const getJobs = () => request<Job[]>("/jobs?limit=100");
export const getJob = (id: string) => request<Job>(`/jobs/${encodeURIComponent(id)}`);
export const getGitHubRepositories = (providerToken: string, page = 1) => request<{ repositories: GitHubRepository[]; next_page: number | null }>("/github/repositories", { method: "POST", body: JSON.stringify({ provider_token: providerToken, page }) });
export const scanGitHubRepository = (providerToken: string, fullName: string) => request<{ id: string; state: string; expires_in_seconds: number }>("/github/scan", { method: "POST", body: JSON.stringify({ provider_token: providerToken, full_name: fullName }) });
export const getFiles = (id: string) => request<{ files: string[] }>(`/jobs/${encodeURIComponent(id)}/files`);
export const getProviders = () => request<{ providers: Record<string, { configured: boolean; available?: boolean; model_available?: boolean; model?: string; deep_model?:string; label?: string }> }>("/providers");
export function createScan(files: FileList | File[], onProgress: (percent: number) => void) {
  const body = new FormData();
  for (const file of Array.from(files)) body.append("files", file, (file as File & { webkitRelativePath?: string }).webkitRelativePath || file.name);
  return new Promise<{ id: string; state: string; expires_in_seconds: number }>((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/jobs");
    xhr.upload.onprogress = (event) => { if (event.lengthComputable) onProgress(Math.round(event.loaded / event.total * 100)); };
    xhr.timeout = 120_000;
    xhr.onload = () => {
      let payload: {id?:string;state?:string;expires_in_seconds?:number;detail?:unknown};
      try { payload = JSON.parse(xhr.responseText || "{}"); }
      catch { reject(new Error(`Upload failed (${xhr.status}). The server returned an unreadable response.`)); return; }
      if (xhr.status >= 200 && xhr.status < 300 && payload.id && payload.state) resolve(payload as {id:string;state:string;expires_in_seconds:number});
      else reject(new Error(typeof payload.detail === "string" ? payload.detail : `Upload failed (${xhr.status}). Check the file and retry.`));
    };
    xhr.ontimeout = () => reject(new Error("Upload timed out. Check your connection and retry."));
    xhr.onabort = () => reject(new Error("Upload cancelled."));
    xhr.onerror = () => reject(new Error("Upload failed. Check your connection and retry."));
    xhr.send(body);
  });
}
export async function getFindings(): Promise<Finding[]> {
  const jobs = await getJobs();
  return jobs.flatMap((job) => (job.findings || []).map((finding) => mapFinding(job, finding)));
}
export async function getFinding(id: string): Promise<Finding & { source_lines: string[]; source_start_line: number; job_id: string }> {
  const jobs = await getJobs();
  const job = jobs.find((item) => item.findings?.some((finding) => finding.id === id));
  if (!job) throw new Error("Finding not found.");
  return getFindingForJob(job.id, id);
}
export async function getFindingForJob(jobId: string, id: string): Promise<Finding & { source_lines: string[]; source_start_line: number; job_id: string }> {
  const raw = await request<any>(`/jobs/${jobId}/findings/${encodeURIComponent(id)}`);
  return { ...mapFinding({ id: jobId } as Job, raw), source_lines: raw.source_lines, source_start_line: raw.source_start_line, job_id: jobId };
}
function mapFinding(job: Job, finding: any): Finding {
  return { id: finding.id, jobId: job.id, title: finding.message, severity: normalizeSeverity(finding.severity), analyzerSeverity: finding.severity || "unknown", tool: finding.source_tools?.join(", ") || finding.source_tool || "Static analysis", file: finding.file, line: finding.line, status: finding.status || "open", cwe: finding.cwe?.id || "Unmapped", description: finding.message, evidence: finding.evidence || finding.message };
}
export function normalizeSeverity(value: string): Severity {
  return ["critical", "high", "medium", "low", "informational"].includes(value) ? value as Severity : "unassessed";
}
export function scanStatus(job: Job): Scan["status"] {
  if (job.state === "failed" || job.report?.scan_status === "FAILED") return "Failed";
  if (["queued", "analyzing", "validating", "verifying"].includes(job.state)) return "Running";
  if (job.report?.scan_status === "PARTIAL") return "Partial";
  if (job.report?.scan_status !== "COMPLETED") return "Not verified";
  return job.findings?.some(finding => finding.status !== "false_positive") ? "Needs attention" : "No findings reported";
}
function mapScan(job: Job): Scan {
  return { id: job.id, jobId: job.id, repo: job.name || "Uploaded project", branch: job.source?.branch || "Uploaded source", pr: 0, status: scanStatus(job), time: new Date(job.created_at * 1000).toLocaleString(), findings: job.findings?.length || 0, state: job.state };
}
export async function getScans(): Promise<Scan[]> { return (await getJobs()).map(mapScan); }
export async function getRepos(): Promise<Repo[]> {
  return (await getJobs()).map((job) => ({ id: job.id, name: job.name || "Uploaded project", branch: job.source?.branch || "Upload", lastScan: scanStatus(job), findings: job.findings?.length || 0, provider: job.source ? "GitHub" : "Upload", private: !job.source }));
}
export async function getDashboard(): Promise<Dashboard> {
  const jobs = await getJobs();
  const findings = jobs.flatMap((job) => (job.findings || []).map((finding) => mapFinding(job, finding)));
  const open = findings.filter((finding) => finding.status === "open");
  const severities: Severity[] = ["critical", "high", "medium", "low", "informational", "unassessed"];
  return { open: open.length, critical: open.filter((finding) => finding.severity === "critical").length, scanned: jobs.length, fixed: jobs.filter((job) => job.repair?.state === "applied_to_copy").length, scans: jobs.slice(0, 8).map(mapScan), findings, bySeverity: Object.fromEntries(severities.map((severity) => [severity, open.filter((finding) => finding.severity === severity).length])) as Record<Severity, number> };
}
export const getPatch = (jobId: string, findingId: string, mode: "standard"|"deep" = "standard") => request<{id:string; operation_id:string; finding_id:string; state:string; status:string}>(`/jobs/${jobId}/repair/${findingId}?mode=${mode}`, { method: "POST" });
export async function getSavedPatch(jobId: string, findingId: string): Promise<Patch> {
  const result = await request<any>(`/jobs/${jobId}/repair/${findingId}`);
  return { id: result.id, findingId, file: result.file, explanation: result.explanation, diff: result.diff, provider: result.provider_used, state: result.state, metadata: result.metadata };
}
export const explainFinding = (jobId: string, findingId: string) => request<FindingExplanation>(`/jobs/${jobId}/explain/${findingId}`, { method: "POST" });
export const getSavedExplanation = (jobId: string, findingId: string) => request<FindingExplanation>(`/jobs/${jobId}/explain/${findingId}`);
export const markFalsePositive = (jobId: string, findingId: string) => request(`/jobs/${jobId}/findings/${findingId}/false-positive`, { method: "POST" });
export const applyRepair = (jobId: string, patchId: string, confirmPartial = false, confirmHumanReview = false) => request<{ state: string; download: string; checks: RepairChecks }>(`/jobs/${jobId}/apply/${patchId}?confirm_partial=${confirmPartial}&confirm_human_review=${confirmHumanReview}`, { method: "POST" });
export type RepairAttempt = {attempt:number; code:string; technical:string; message:string; edits:{edit_index:number; start_line:number; end_line:number; actual:string; expected:string; replacement:string; reason:string; truncated:boolean}[]};
export const getFindingSource = (jobId:string, findingId:string) => request<{file:string; line:number; original:string; expires_at?:number}>(`/jobs/${jobId}/findings/${findingId}/source`);
export const getProjectSource = (jobId:string, path:string) => request<{file:string; original:string; source_hash:string; expires_at?:number}>(`/jobs/${jobId}/source?path=${encodeURIComponent(path)}`);
export type RepairOperation = {id?:string; finding_id?:string; mode?:"standard"|"deep"; stage?:string; status?:string; started_at?:number; generation_finished_at?:number; finished_at?:number; deadline?:number; attempt?:number; attempt_count?:number; provider?:string; model?:string; error?:string; error_detail?:RepairAttempt; attempts?:RepairAttempt[]; events?:{at:number;stage:string;status:string;provider?:string;model?:string;attempt?:number}[]; check_states?:Record<string,string>; scope_start_line?:number; scope_end_line?:number};
export const getRepairStatus = (jobId: string, findingId?:string) => request<{job_busy:boolean; scan_provider:string; attempt_count:number; max_attempts:number; deep_repair_available:boolean; deep_repair_configured:boolean; deep_model:string; attempt_history:RepairAttempt[]; operation: RepairOperation; repair?: {id: string; finding_id: string; mode?:"standard"|"deep"; file: string; diff: string; explanation: string; provider_used: string; model_used?:string; state: string; review?:{reviewed_by:string; reviewed_at:number; verification_outcome:string}; metadata?: Patch["metadata"]}; checks?: RepairChecks; preview?: {original:string; proposed:string; line:number}}>(`/jobs/${jobId}/repair-status${findingId ? `?finding_id=${encodeURIComponent(findingId)}` : ""}`);
export const rejectRepair = (jobId: string, patchId: string) => request<{ id: string; state: string }>(`/jobs/${jobId}/repair/${patchId}/reject`, { method: "POST" });

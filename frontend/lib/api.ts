export type Severity = "critical" | "high" | "medium" | "low" | "informational";
export type Repo = { id: string; name: string; branch: string; lastScan: string; findings: number; provider: "Upload"; private: true };
export type Scan = { id: string; repo: string; branch: string; pr: number; status: "Passed" | "Needs attention" | "Running" | "Failed"; time: string; findings: number; jobId: string; state: string };
export type Finding = { id: string; jobId: string; title: string; severity: Severity; tool: string; file: string; line: number; status: string; cwe: string; description: string; evidence: string };
export type Patch = { id: string; findingId: string; explanation: string; diff: string; file: string; provider: string; state: string; metadata?: {line:number; added_lines:number; deleted_lines:number; reasons:string[]; security_improvement:string; warnings:string[]} };
export type FindingExplanation = { summary: string; impact: string; recommended_action: string; provider_used: string };
export type Job = { id: string; name: string; provider: string; state: string; created_at: number; progress?: string; findings?: any[]; checks?: Record<string, string>; error?: string; report?: any; repair?: any; source_files?: number; uploaded_files?: string[] };
export type Dashboard = { open: number; critical: number; scanned: number; fixed: number; scans: Scan[]; findings: Finding[]; bySeverity: Record<Severity, number> };

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api${path}`, { ...init, headers: { ...(init?.body instanceof FormData ? {} : { "Content-Type": "application/json" }), ...init?.headers }, cache: "no-store" });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(typeof payload.detail === "string" ? payload.detail : payload.detail?.message || `Request failed (${response.status})`);
  }
  return response.json() as Promise<T>;
}

export const getJobs = () => request<Job[]>("/jobs?limit=100");
export const getJob = (id: string) => request<Job>(`/jobs/${encodeURIComponent(id)}`);
export const getFiles = (id: string) => request<{ files: string[] }>(`/jobs/${encodeURIComponent(id)}/files`);
export const getProviders = () => request<{ providers: Record<string, { configured: boolean; available?: boolean; model_available?: boolean; model?: string; label?: string }> }>("/providers");
export function createScan(files: FileList | File[], onProgress: (percent: number) => void) {
  const body = new FormData();
  for (const file of Array.from(files)) body.append("files", file, (file as File & { webkitRelativePath?: string }).webkitRelativePath || file.name);
  return new Promise<{ id: string; state: string; expires_in_seconds: number }>((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/jobs");
    xhr.upload.onprogress = (event) => { if (event.lengthComputable) onProgress(Math.round(event.loaded / event.total * 100)); };
    xhr.onload = () => { const payload = JSON.parse(xhr.responseText || "{}"); if (xhr.status >= 200 && xhr.status < 300) resolve(payload); else reject(new Error(payload.detail || `Upload failed (${xhr.status})`)); };
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
  return { id: finding.id, jobId: job.id, title: finding.message, severity: finding.severity || "informational", tool: finding.source_tools?.join(", ") || finding.source_tool || "Static analysis", file: finding.file, line: finding.line, status: finding.status || "open", cwe: finding.cwe?.id || "Unmapped", description: finding.message, evidence: finding.evidence || finding.message };
}
function mapScan(job: Job): Scan {
  const findings = job.findings || [];
  const needsAttention = findings.some((finding) => finding.status !== "false_positive");
  return { id: job.id, jobId: job.id, repo: job.name || "Uploaded project", branch: "Uploaded source", pr: 0, status: job.state === "complete" ? needsAttention ? "Needs attention" : "Passed" : job.state === "failed" ? "Failed" : "Running", time: new Date(job.created_at * 1000).toLocaleString(), findings: findings.length, state: job.state };
}
export async function getScans(): Promise<Scan[]> { return (await getJobs()).map(mapScan); }
export async function getRepos(): Promise<Repo[]> {
  return (await getJobs()).map((job) => ({ id: job.id, name: job.name || "Uploaded project", branch: "Upload", lastScan: job.state, findings: job.findings?.length || 0, provider: "Upload", private: true }));
}
export async function getDashboard(): Promise<Dashboard> {
  const jobs = await getJobs();
  const findings = jobs.flatMap((job) => (job.findings || []).map((finding) => mapFinding(job, finding)));
  const open = findings.filter((finding) => finding.status === "open");
  const severities: Severity[] = ["critical", "high", "medium", "low", "informational"];
  return { open: open.length, critical: open.filter((finding) => finding.severity === "critical").length, scanned: jobs.length, fixed: jobs.filter((job) => job.repair?.state === "applied_to_copy").length, scans: jobs.slice(0, 8).map(mapScan), findings, bySeverity: Object.fromEntries(severities.map((severity) => [severity, open.filter((finding) => finding.severity === severity).length])) as Record<Severity, number> };
}
export async function getPatch(jobId: string, findingId: string): Promise<Patch> {
  const result = await request<any>(`/jobs/${jobId}/repair/${findingId}`, { method: "POST" });
  return { id: result.id, findingId, file: result.file, explanation: result.explanation, diff: result.diff, provider: result.provider_used, state: result.state, metadata: result.metadata };
}
export async function getSavedPatch(jobId: string, findingId: string): Promise<Patch> {
  const result = await request<any>(`/jobs/${jobId}/repair/${findingId}`);
  return { id: result.id, findingId, file: result.file, explanation: result.explanation, diff: result.diff, provider: result.provider_used, state: result.state, metadata: result.metadata };
}
export const explainFinding = (jobId: string, findingId: string) => request<FindingExplanation>(`/jobs/${jobId}/explain/${findingId}`, { method: "POST" });
export const getSavedExplanation = (jobId: string, findingId: string) => request<FindingExplanation>(`/jobs/${jobId}/explain/${findingId}`);
export const markFalsePositive = (jobId: string, findingId: string) => request(`/jobs/${jobId}/findings/${findingId}/false-positive`, { method: "POST" });
export const applyRepair = (jobId: string, patchId: string, confirmPartial = false) => request<{ state: string; download: string; checks: Record<string, string> }>(`/jobs/${jobId}/apply/${patchId}?confirm_partial=${confirmPartial}`, { method: "POST" });
export type RepairAttempt = {attempt:number; code:string; technical:string; message:string; edits:{edit_index:number; start_line:number; end_line:number; actual:string; expected:string; replacement:string; reason:string; truncated:boolean}[]};
export const getFindingSource = (jobId:string, findingId:string) => request<{file:string; line:number; original:string; expires_at?:number}>(`/jobs/${jobId}/findings/${findingId}/source`);
export const getRepairStatus = (jobId: string, findingId?:string) => request<{job_busy:boolean; operation: {id?: string; finding_id?: string; stage?: string; status?: string; started_at?: number; finished_at?:number; attempt?: number; provider?: string; error?: string; attempts?:RepairAttempt[]; events?:{at:number;stage:string;status:string;provider?:string;attempt?:number}[]; check_states?:Record<string,string>; scope_start_line?:number; scope_end_line?:number}; repair?: {id: string; finding_id: string; file: string; diff: string; explanation: string; provider_used: string; state: string; metadata?: Patch["metadata"]}; checks?: Record<string,string>; preview?: {original:string; proposed:string; line:number}}>(`/jobs/${jobId}/repair-status${findingId ? `?finding_id=${encodeURIComponent(findingId)}` : ""}`);
export const rejectRepair = (jobId: string, patchId: string) => request<{ id: string; state: string }>(`/jobs/${jobId}/repair/${patchId}/reject`, { method: "POST" });

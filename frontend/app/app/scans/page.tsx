"use client";
import { useMemo, useState } from "react";
import { Filter } from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { EmptyState, ErrorState, LoadingState } from "@/components/ui/states";
import { getFindings } from "@/lib/api";
import { useRemote } from "@/lib/use-remote";
export default function Scans() {
  const { data, loading, error, retry } = useRemote(getFindings);
  const [severity,setSeverity]=useState("all"); const [tool,setTool]=useState("all"); const [status,setStatus]=useState("all");
  const rows=useMemo(()=>data?.filter(f=>(severity==="all"||f.severity===severity)&&(tool==="all"||f.tool.toLowerCase().includes(tool))&&(status==="all"||f.status===status))??[],[data,severity,tool,status]);
  return <AppShell active="Findings"><main className="app-content"><div className="page-head"><div><div className="eyebrow">SCAN RESULTS</div><h1>Findings</h1><p>Issues reported by the analyzers configured for each uploaded scan.</p></div><span className="status-pill"><Filter size={13}/>{data?.length??0} findings</span></div>
    {loading?<LoadingState rows={4}/>:error?<ErrorState retry={retry}/>:!data?.length?<EmptyState title="No findings to show" body="Run a scan to see analyzer findings here."/>:<><div className="filter-row"><label>Severity <select aria-label="Filter by severity" value={severity} onChange={e=>setSeverity(e.target.value)}><option value="all">All</option>{["critical","high","medium","low","informational","unassessed"].map(x=><option key={x} value={x}>{x === "unassessed" ? "Not assessed" : x}</option>)}</select></label><label>Tool <select aria-label="Filter by tool" value={tool} onChange={e=>setTool(e.target.value)}><option value="all">All tools</option>{["clang","cppcheck","semgrep"].map(x=><option key={x} value={x}>{x === "unassessed" ? "Not assessed" : x}</option>)}</select></label><label>Status <select aria-label="Filter by status" value={status} onChange={e=>setStatus(e.target.value)}><option value="all">All</option><option value="open">Open</option><option value="false_positive">False positive</option></select></label><span className="tag">{rows.length} results</span></div>{rows.length?<section className="panel list-panel"><div className="table-scroll"><table className="findings-table"><thead><tr><th>Severity</th><th>Finding</th><th>Tool</th><th>File</th><th>Project</th><th>Status</th></tr></thead><tbody>{rows.map(f=><tr key={`${f.jobId}-${f.id}`}><td><span className={`severity ${f.severity}`}><i className="severity-dot"/>{f.severity === "unassessed" ? "Not assessed" : f.severity}</span></td><td><a href={`/app/findings/${f.id}?job=${f.jobId}`}>{f.title}<span className="tag"> {f.cwe}</span></a></td><td>{f.tool}</td><td className="mono">{f.file}:{f.line}</td><td className="mono">{f.jobId.slice(0,8)}</td><td>{f.status}</td></tr>)}</tbody></table></div></section>:<EmptyState title="No matching findings" body="Try changing or clearing the filters."/>}</>}
  </main></AppShell>;
}

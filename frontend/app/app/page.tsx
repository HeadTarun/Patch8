"use client";
import { ArrowRight, ShieldCheck, Upload } from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { EmptyState, ErrorState, LoadingState } from "@/components/ui/states";
import { getDashboard, type Severity } from "@/lib/api";
import { useRemote } from "@/lib/use-remote";

const levels: Severity[] = ["critical", "high", "medium", "low", "informational"];
export default function Dashboard() {
  const { data, loading, error, retry } = useRemote(getDashboard);
  return <AppShell active="Overview"><main className="app-content">
    <div className="page-head"><div><div className="eyebrow">SCAN WORKSPACE</div><h1>Security at a glance</h1><p>Metrics are calculated from saved scans. Uploaded source is processed by the configured analyzers.</p></div><a className="button primary" href="/app/projects"><Upload size={15}/> New scan</a></div>
    {loading ? <LoadingState rows={5}/> : error ? <ErrorState retry={retry}/> : !data || !data.scanned ? <EmptyState title="No scans yet" body="Upload a C or C++ source file or project archive to start a real scan."/> : <>
      <div className="stats-grid">{[["Open findings",data.open],["Critical findings",data.critical],["Scans stored",data.scanned],["Repaired copies",data.fixed]].map(([label,value])=><article className="panel stat-card" key={label as string}><div className="stat-label">{label as string}</div><div className="stat-value">{value as number}</div><div className="stat-foot"><ShieldCheck size={13}/>From scan records</div></article>)}</div>
      <div className="dashboard-grid"><section className="panel chart-panel"><div className="panel-head"><h2>Open findings by severity</h2><span className="tag">CURRENT SCANS</span></div><div className="grid gap-4">{levels.map(level=>{const count=data.bySeverity[level]||0; const max=Math.max(1,...levels.map(item=>data.bySeverity[item]||0));return <div key={level} className="grid grid-cols-[100px_1fr_32px] items-center gap-3"><span className={`severity ${level}`}><i className="severity-dot"/>{level}</span><div className="h-2 overflow-hidden rounded bg-white/5"><div className={`h-full rounded ${level}`} style={{width:`${Math.max(count?4:0,count/max*100)}%`,background:"var(--severity)"}}/></div><span className="mono text-right">{count}</span></div>})}</div></section>
        <section className="panel list-panel"><div className="panel-head"><h2>Recent scans</h2><a href="/app/projects" className="tag">All projects <ArrowRight size={12}/></a></div>{data.scans.length ? <div className="grid gap-2">{data.scans.map(scan=><a href={`/app/analysis/${scan.jobId}`} className="repo-card panel" key={scan.id}><span className="repo-avatar"><ShieldCheck size={17}/></span><span className="repo-meta"><strong>{scan.repo}</strong><span>{scan.time} · {scan.findings} findings · {scan.state}</span></span><span className={`status-pill ${scan.status==="Passed"?"good":scan.status==="Failed"?"bad":""}`}>{scan.status}</span></a>)}</div>:<EmptyState title="No scans yet"/>}</section></div>
      <section className="panel list-panel section-gap"><div className="panel-head"><h2>Findings to review</h2><a href="/app/scans" className="tag">View findings <ArrowRight size={12}/></a></div>{data.findings.length ? <div className="table-scroll"><table className="findings-table"><thead><tr><th>Severity</th><th>Finding</th><th>Project</th><th>Location</th><th>Status</th></tr></thead><tbody>{data.findings.slice(0,6).map(finding=><tr key={`${finding.jobId}-${finding.id}`}><td><span className={`severity ${finding.severity}`}><i className="severity-dot"/>{finding.severity}</span></td><td><a href={`/app/findings/${finding.id}?job=${finding.jobId}`}>{finding.title}</a></td><td>{finding.jobId.slice(0,8)}</td><td className="mono">{finding.file}:{finding.line}</td><td>{finding.status}</td></tr>)}</tbody></table></div>:<EmptyState title="No findings recorded" body="Completed scan findings will appear here."/>}</section>
    </>}
  </main></AppShell>;
}

"use client";
import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { ArrowLeft, Check } from "lucide-react";
import { FindingActions } from "@/components/finding-actions";
import { AppShell } from "@/components/app-shell";
import { Button } from "@/components/ui/button";
import { EmptyState, ErrorState, LoadingState } from "@/components/ui/states";
import { getFindingForJob, markFalsePositive, type Finding } from "@/lib/api";

export default function FindingDetail() {
  const {id}=useParams<{id:string}>();
  const [jobId,setJobId]=useState(""); const [finding,setFinding]=useState<(Finding&{source_lines:string[];source_start_line:number;job_id:string})|null>(null);
  const [loading,setLoading]=useState(true); const [error,setError]=useState(""); const [busy,setBusy]=useState(false); const [notice,setNotice]=useState("");
  useEffect(()=>{const job=new URLSearchParams(window.location.search).get("job")||"";setJobId(job);if(!job){setError("This finding URL is missing its scan ID.");setLoading(false);return;}getFindingForJob(job,id).then(setFinding).catch(reason=>setError(reason instanceof Error?reason.message:"Finding unavailable.")).finally(()=>setLoading(false));},[id]);
  async function falsePositive(){setBusy(true);try{await markFalsePositive(jobId,id);setFinding(current=>current?{...current,status:"false_positive"}:current);setNotice("Finding marked as false positive in the saved scan.");}catch(reason){setNotice(reason instanceof Error?reason.message:"Could not update finding.");}finally{setBusy(false);}}
  return <AppShell active="Findings"><main className="app-content"><a className="tag" href="/app/scans"><ArrowLeft size={13}/> Back to findings</a>
    {loading?<div className="section-gap"><LoadingState rows={3}/></div>:error?<div className="section-gap"><ErrorState retry={()=>window.location.reload()}/></div>:!finding?<div className="section-gap"><EmptyState title="Finding unavailable" body="This finding may have expired with its scan."/></div>:<>
      <div className="page-head section-gap"><div><div className="eyebrow mono">{finding.id} · {finding.tool} · {finding.cwe} · Scan {jobId.slice(0,8)}</div><h1>{finding.title}</h1><p>{finding.file}:{finding.line}</p></div><span className={`severity ${finding.severity}`}><i className="severity-dot"/>{finding.severity}</span></div>
      <div className="detail-grid"><section className="panel detail-box"><div className="panel-head"><h2>Reported source</h2><span className="tag">{finding.file}</span></div><div className="code-block">{finding.source_lines.map((line,index)=>{const lineNumber=finding.source_start_line+index;return <span key={lineNumber} className={`code-line ${lineNumber===finding.line?"highlight":""}`}><span style={{display:"inline-block",width:36,color:"#707d83"}}>{lineNumber}</span>{line}</span>})}</div><p className="tag">Highlighted line is the analyzer's reported location.</p></section><section className="panel detail-box"><div className="eyebrow">ANALYZER EXPLANATION</div><h2 style={{marginTop:12}}>{finding.title}</h2><p>{finding.description}</p><div className="code-block">Evidence: {finding.evidence}</div><div className="setting-row"><span><strong>Scanner</strong><small>{finding.tool}</small></span><span className="status-pill">{finding.cwe}</span></div><div className="setting-row"><span><strong>Finding status</strong><small>{finding.status}</small></span><span className="status-pill">{finding.status}</span></div></section></div>
      <section className="panel detail-box section-gap"><div className="eyebrow">REPAIR WORKSPACE</div><FindingActions jobId={jobId} findingId={id} eligible={finding.cwe!=="Unmapped" && finding.status!=="false_positive"}/><div className="toolbar section-gap"><Button onClick={falsePositive} disabled={busy||finding.status==="false_positive"}><Check size={14}/>{finding.status==="false_positive"?"Marked false positive":"Mark as false positive"}</Button></div>{notice&&<p role="status">{notice}</p>}</section>
    </>}
  </main></AppShell>;
}

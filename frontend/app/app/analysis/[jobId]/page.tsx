"use client";
import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { ArrowLeft, CircleAlert, CircleCheck, Clock3, Download, FileCode2, LoaderCircle, RefreshCw, ShieldCheck } from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { CodePreview } from "@/components/code-preview";
import { FindingActions } from "@/components/finding-actions";
import { EmptyState, ErrorState, LoadingState } from "@/components/ui/states";
import { getFiles, getJob, getProjectSource, getRepairStatus, type Job, type RepairOperation } from "@/lib/api";

type RepairStatus = Awaited<ReturnType<typeof getRepairStatus>>;
const lifecycleSteps = ["Upload", "Scan", "Findings", "Repair", "Verification", "Review"];
const sourceExtension = /\.(c|cc|cpp|cxx|h|hh|hpp|hxx)$/i;

function LifecycleRoadmap({job, status}:{job:Job; status:RepairStatus|null}) {
  const operation:RepairOperation|undefined=status?.operation;
  const repair=status?.repair||job.repair;
  const findings=job.findings||[];
  let current=2; let failed=-1; let warning=-1; let completeAll=false;
  const repairStage=(operation?.stage||"").toLowerCase();
  if(job.state==="failed"){current=1;failed=1;}
  else if(["queued","analyzing"].includes(job.state)){current=1;}
  else if(repair?.state==="verification_failed"||repairStage.includes("verification failed")){
    current=4;failed=4;
  } else if(operation?.status==="timed_out"||operation?.status==="failed"||operation?.status==="human_review"){
    current=3;failed=operation.status==="human_review"? -1:3;warning=operation.status==="human_review"?3:-1;
  } else if(operation?.status==="verifying"||["validating","verifying"].includes(job.state)){
    current=4;
  } else if(repair?.state==="review_ready"){
    current=5;
  } else if(repair?.state==="applied_to_copy"){
    current=5;completeAll=true;
  } else if(operation?.status==="queued"||operation?.status==="running"){
    current=3;
    if(["checking edits","preparing candidate"].some(stage=>repairStage.includes(stage))) current=3;
  } else if(job.state==="complete"&&!findings.length){
    current=2;warning=2;
  }
  const scanDone=["complete","validating","verifying"].includes(job.state)||current>1||completeAll;
  const titles=["Files received",job.state==="failed"?"Scan failed":scanDone?"Scan complete":job.state==="analyzing"?"Scanning":"Queued",
    findings.length?`${findings.length} finding${findings.length===1?"":"s"}`:"No findings",
    operation?.status==="timed_out"?"Timed out":operation?.status==="human_review"?"Human review":current>3?"Candidate ready":operation?.stage||"Waiting for review",
    repair?.checks?.verification_outcome||job.checks?.verification||"Pending checks",
    repair?.state==="applied_to_copy"?"Accepted":repair?.state==="review_ready"?"Ready to review":"Pending review"];
  const description=job.error||job.progress||operation?.error||"Follow the scan and repair from upload through review.";
  const analyzerRows=Object.entries((job.report?.analyzer_status||{}) as Record<string,{status:string;error?:string|null}>);
  return <section className="panel lifecycle-roadmap-card" aria-label="Project lifecycle" aria-live="polite">
    <div className="roadmap-header"><div><div className="eyebrow">PROJECT LIFECYCLE</div><h2>{description}</h2></div>
      <span className={`lifecycle-badge ${failed>=0?"life-failed":warning>=0?"life-warning":current<5||(!completeAll&&current===5)?"life-active":"life-complete"}`}>{failed>=0?<CircleAlert size={14}/>:warning>=0?<CircleAlert size={14}/>:current<5||(!completeAll&&current===5)?<Clock3 size={14}/>:<CircleCheck size={14}/>} {titles[failed>=0?failed:warning>=0?warning:current]}</span>
    </div>
    <ol className="lifecycle-roadmap" aria-label="Upload, scan, findings, repair, verification, review">
      {lifecycleSteps.map((label,index)=>{
        const state=completeAll||index<current?"complete":index===failed?"failed":index===warning?"warning":index===current?"active":"pending";
        const Icon=state==="complete"?CircleCheck:state==="failed"?CircleAlert:state==="warning"?CircleAlert:state==="active"?LoaderCircle:Clock3;
        return <li className={`roadmap-step roadmap-${state}`} key={label} aria-current={state==="active"||state==="failed"||state==="warning"?"step":undefined}>
          <span className="roadmap-marker"><Icon size={15} className={state==="active"?"scan-spinner":""}/></span>
          <span className="roadmap-step-copy"><strong>{label}</strong><small>{titles[index]}</small></span>
        </li>;
      })}
    </ol>
    {job.report?.scan_status&&<p className="lifecycle-summary">Analyzer coverage: <strong>{String(job.report.scan_status).replaceAll("_"," ").toLowerCase()}</strong></p>}
    {!!analyzerRows.length&&<details className="lifecycle-details"><summary>Analyzer results ({analyzerRows.length})</summary><ul>{analyzerRows.map(([name,result])=><li key={name}><span>{name}</span><span className={`lifecycle-text ${result.status==="completed"?"life-complete":result.status==="failed"?"life-failed":"life-pending"}`}>{result.status}{result.error?`: ${result.error}`:""}</span></li>)}</ul></details>}
  </section>;
}

export default function Analysis() {
  const {jobId}=useParams<{jobId:string}>();
  const [selected,setSelected]=useState("");
  const [job,setJob]=useState<Job|null>(null);
  const [files,setFiles]=useState<string[]>([]);
  const [repairStatus,setRepairStatus]=useState<RepairStatus|null>(null);
  const [sourcePath,setSourcePath]=useState("");
  const [sourceText,setSourceText]=useState("");
  const [sourceError,setSourceError]=useState("");
  const [loading,setLoading]=useState(true);
  const [error,setError]=useState("");
  async function refresh(){
    try{const value=await getJob(jobId);setJob(value);const tree=await getFiles(jobId);setFiles(tree.files);setSourcePath(current=>current||tree.files.find(path=>sourceExtension.test(path))||"");setError("");}
    catch(reason){setError(reason instanceof Error?reason.message:"Could not load scan.");}
    finally{setLoading(false);}
  }
  async function refreshRepair(){try{setRepairStatus(await getRepairStatus(jobId));}catch{}}
  useEffect(()=>{setLoading(true);setJob(null);setFiles([]);setSourcePath("");setRepairStatus(null);setError("");void refresh();void refreshRepair();},[jobId]);
  useEffect(()=>{
    if(!job||!["queued","analyzing","validating","verifying"].includes(job.state))return;
    const timer=window.setInterval(()=>void refresh(),2500);return()=>window.clearInterval(timer);
  },[jobId,job?.state]);
  useEffect(()=>{const timer=window.setInterval(()=>void refreshRepair(),2000);return()=>window.clearInterval(timer);},[jobId]);
  useEffect(()=>{
    let active=true;setSourceText("");setSourceError("");
    if(!sourcePath)return;
    getProjectSource(jobId,sourcePath).then(result=>{if(active)setSourceText(result.original);}).catch(reason=>{if(active)setSourceError(reason instanceof Error?reason.message:"Could not load source preview.");});
    return()=>{active=false;};
  },[jobId,sourcePath,files.length]);
  const sourceFiles=files.filter(path=>sourceExtension.test(path));
  return <AppShell active="Projects"><main className="app-content"><a className="tag" href="/app/projects"><ArrowLeft size={13}/> Projects</a>
    {loading?<div className="section-gap"><LoadingState rows={4}/></div>:error&&!job?<div className="section-gap"><ErrorState retry={()=>{setLoading(true);void refresh();}}/></div>:!job?<EmptyState title="Scan unavailable" body="The scan expired or could not be found."/>:<>
      <div className="page-head section-gap"><div><div className="eyebrow">PROJECT ANALYSIS · {job.id.slice(0,8)}</div><h1>{job.name}</h1>{job.source&&<p>GitHub · {job.source.branch} · commit {job.source.commit_sha.slice(0,7)}</p>}<p>{job.progress||"Scan status from the analysis worker"}</p></div><span className={`status-pill ${job.state==="complete"?"good":job.state==="failed"?"bad":""}`}><RefreshCw size={12} className={["queued","analyzing","validating"].includes(job.state)?"scan-spinner":""}/>{job.state}</span></div>
      {job.state==="failed"&&<div className="panel error-state" role="alert"><h2>Scan failed</h2><p>{job.error||"The analysis worker could not complete this scan."}</p></div>}
      <div className="stats-grid"><article className="panel stat-card"><div className="stat-label">Findings</div><div className="stat-value">{job.findings?.length??"—"}</div></article><article className="panel stat-card"><div className="stat-label">Source files</div><div className="stat-value">{job.source_files??files.length}</div></article><article className="panel stat-card"><div className="stat-label">Analysis status</div><div className="stat-value" style={{fontSize:18}}>{job.report?.scan_status||job.state}</div></article><article className="panel stat-card"><div className="stat-label">Patch checks</div><div className="stat-value" style={{fontSize:18}}>{job.checks?.verification||"Not run"}</div></article></div>
      <LifecycleRoadmap job={job} status={repairStatus}/>
      <section className="panel list-panel section-gap"><div className="panel-head"><h2><ShieldCheck size={16}/> Findings</h2><span className="tag">{job.findings?.length??0}</span></div>{job.findings?.length?<div className="grid gap-2">{job.findings.map(finding=><div key={finding.id}><a className="repo-card panel" href={`/app/findings/${finding.id}?job=${job.id}`}><span className={`severity ${finding.severity}`}><i className="severity-dot"/>{finding.severity}</span><span className="repo-meta"><strong>{finding.message}</strong><span className="mono">{finding.file}:{finding.line} · {finding.source_tool} · {finding.cwe?.id||"unmapped"}</span></span><span className="tag">{finding.status||"open"}</span></a>{["complete","validating","verifying"].includes(job.state)&&<button className="button" onClick={()=>setSelected(finding.id)}>Review repair</button>}</div>)}</div>:job.state==="complete"?<EmptyState title="No findings reported" body="The completed scan reported no findings from the configured analyzers."/>:<LoadingState rows={2}/>}</section>
      {selected&&job.findings?.find(f=>f.id===selected)&&<section className="panel detail-box section-gap"><FindingActions jobId={job.id} findingId={selected} eligible={!!job.findings.find(f=>f.id===selected)?.cwe&&job.findings.find(f=>f.id===selected)?.status!=="false_positive"}/></section>}
      <section className="panel source-browser section-gap"><div className="panel-head"><div><div className="eyebrow">UPLOADED PROJECT</div><h2>Source preview</h2></div><FileCode2 size={17} className="accent"/></div>
        {sourceFiles.length?<><label className="source-preview-select">Choose source file<select value={sourcePath} onChange={event=>setSourcePath(event.target.value)}>{sourceFiles.map(path=><option key={path} value={path}>{path}</option>)}</select></label>{sourceError?<p role="alert">{sourceError}</p>:sourceText?<CodePreview text={sourceText} label={`Source preview ${sourcePath}`}/>:<p className="muted">Loading source preview…</p>}</>:<p className="muted">Source files will be available here after the upload is extracted.</p>}
      </section>
      {job.checks&&<section className="panel verification-card section-gap"><div className="panel-head"><div><div className="eyebrow">CHECK RESULTS</div><h2>Build and security verification</h2></div><span className="tag">Independent results</span></div><div className="verification-grid">{["build","tests","sanitizers","security","verification","verification_outcome"].filter(key=>job.checks?.[key]).map(key=><div className="verification-item" key={key}><span>{key.replaceAll("_"," ")}</span><strong className={`verification-state ${["passed","verified"].includes(String(job.checks?.[key]))?"verify-good":["failed"].includes(String(job.checks?.[key]))?"verify-bad":["not_available","not_verified","unverified","partially_verified"].includes(String(job.checks?.[key]))?"verify-warn":"verify-neutral"}`}>{String(job.checks?.[key]).replaceAll("_"," ")}</strong></div>)}</div>{job.checks.details&&<details className="lifecycle-details"><summary>Build and test details</summary><pre className="verification-diagnostics">{job.checks.details}</pre></details>}{job.checks.security_details&&<details className="lifecycle-details"><summary>Security rescan details</summary><p>{job.checks.security_details}</p></details>}</section>}
      {job.repair?.state==="applied_to_copy"&&<section className="panel detail-box section-gap"><div className="panel-head"><div><div className="eyebrow">REPAIR WORKING COPY</div><h2>Verification: {job.checks?.verification||job.repair.state}</h2></div><a className="button" href={`/api/jobs/${job.id}/download`}><Download size={14}/> Download patched project</a></div><p>{job.checks?.security_details||job.repair.explanation}</p><a className="tag" href={`/api/jobs/${job.id}/diff`}>Download diff</a></section>}
    </>}
  </main></AppShell>;
}

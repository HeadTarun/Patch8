"use client";
import { useEffect, useState } from "react";
import { applyRepair, explainFinding, getFindingSource, getPatch, getRepairStatus, getSavedExplanation, type FindingExplanation } from "../lib/api";

type Status = Awaited<ReturnType<typeof getRepairStatus>>;
type Source = Awaited<ReturnType<typeof getFindingSource>>;
const phases = ["Prepare", "Generate", "Check edits", "Verify", "Review"] as const;
function phaseFor(stage = ""): number {
  if (["locating code"].includes(stage)) return 0;
  if (["generating", "retrying", "provider fallback"].includes(stage)) return 1;
  if (["checking edits", "preparing candidate"].includes(stage)) return 2;
  if (["queued for verification", "preparing verification", "building and testing", "building", "testing", "sanitizer checks", "security rescan"].includes(stage)) return 3;
  if (["review ready", "verification failed"].includes(stage)) return 4;
  return -1;
}
function tone(value?: string): string {
  if (["running", "verifying"].includes(value || "")) return "active";
  if (["passed", "verified", "complete", "completed"].includes(value || "")) return "success";
  if (["failed"].includes(value || "")) return "failure";
  if (["not_available", "unverified", "not_verified", "partially_verified"].includes(value || "")) return "warning";
  return "pending";
}
function label(value?: string): string {
  return ({not_available:"Unavailable", not_verified:"Not verified", partially_verified:"Partially verified", unverified:"Unverified", not_run:"Not started", pending:"Pending", running:"Running", passed:"Passed", failed:"Failed", verified:"Verified"} as Record<string,string>)[value || ""] || (value ? value.replaceAll("_"," ") : "Not started");
}
const descriptions: Record<string,string> = {
  "locating code":"Finding the relevant source and repair scope.",
  "generating":"The AI is preparing a suggestion.",
  "retrying":"The first suggestion needs correction; another attempt is underway.",
  "provider fallback":"The first provider was unavailable; trying the configured fallback.",
  "checking edits":"Checking whether the suggestion matches the original source.",
  "preparing candidate":"Preparing a candidate from the validated edits.",
  "queued for verification":"The candidate is waiting for a verification worker.",
  "preparing verification":"Preparing an isolated copy for verification.",
  "building and testing":"Running available build and test checks.",
  "building":"Building the candidate in isolation.",
  "testing":"Running available tests.",
  "sanitizer checks":"Running sanitizer checks.",
  "security rescan":"Checking the candidate for security findings.",
  "review ready":"The candidate and its verification results are ready for review.",
  "verification failed":"Verification failed or could not establish enough evidence."
};
function Code({text, line}: {text:string; line?:number}) {
  return <pre className="code-block" style={{whiteSpace:"pre",overflow:"auto",maxHeight:500}}>{text.split("\n").map((value,index)=><span className={`code-line ${index+1===line?"highlight":""}`} key={index}><span style={{display:"inline-block",width:48,color:"#707d83"}}>{index+1}</span>{value}</span>)}</pre>;
}
export function FindingActions({jobId, findingId, eligible}: {jobId:string; findingId:string; eligible:boolean}) {
  const [status,setStatus]=useState<Status|null>(null);
  const [source,setSource]=useState<Source|null>(null);
  const [explanation,setExplanation]=useState<FindingExplanation|null>(null);
  const [busy,setBusy]=useState(""); const [error,setError]=useState(""); const [ack,setAck]=useState(false);
  const [view,setView]=useState<"compare"|"original"|"proposed"|"diff">("compare"); const [now,setNow]=useState(Date.now());
  async function refresh(){try{setStatus(await getRepairStatus(jobId,findingId))}catch(e){setError(e instanceof Error?e.message:"Could not load repair status.")}}
  useEffect(()=>{setStatus(null);setSource(null);setAck(false);void refresh();getFindingSource(jobId,findingId).then(setSource).catch(e=>setError(e.message));getSavedExplanation(jobId,findingId).then(setExplanation).catch(()=>{});},[jobId,findingId]);
  const op=status?.operation; const repair=status?.repair; const active=!!status?.job_busy;
  useEffect(()=>{if(!active && busy!=="repair")return;const timer=window.setInterval(()=>{setNow(Date.now());void refresh()},2000);return()=>window.clearInterval(timer)},[jobId,findingId,active,busy]);
  async function run(action:string){setBusy(action);setError("");try{
    if(action==="explain")setExplanation(await explainFinding(jobId,findingId));
    if(action==="repair"){const pending=getPatch(jobId,findingId);await refresh();await pending;await refresh()}
    if(action==="accept"&&repair){await applyRepair(jobId,repair.id,ack);window.location.href=`/app/analysis/${jobId}`}
  }catch(e){await refresh();if(action!=="repair")setError(e instanceof Error?e.message:"Request failed.")}finally{setBusy("")}}
  const outcome=status?.checks?.verification_outcome; const attempts=op?.attempts||[]; const latest=attempts.at(-1);
  const elapsed=op?.started_at?Math.max(0,Math.floor(((op.finished_at||now/1000)-op.started_at))):0;
  const proposed=status?.preview?.proposed; const checks=op?.check_states || status?.checks;
  const currentPhase=phaseFor(op?.stage);
  const seenPhases=new Set((op?.events||[]).map(event=>phaseFor(event.stage)).filter(index=>index>=0));
  const phaseState=(index:number) => {
    if (index===currentPhase) {
      if (op?.status==="failed" || op?.stage==="verification failed") return "failure";
      if (op?.status==="complete") return tone(outcome);
      return op?.status==="queued" ? "pending" : "active";
    }
    return index < currentPhase && seenPhases.has(index) ? "success" : "pending";
  };
  return <div className="section-gap">
    <div className="toolbar"><button className="button" disabled={!!busy} onClick={()=>void run("explain")}>{busy==="explain"?"Explaining...":"Explain with AI"}</button><button className="button primary" disabled={!!busy||active||!eligible} onClick={()=>void run("repair")}>{active||busy==="repair"?"Repair in progress...":op?.status==="failed"||repair?.state==="verification_failed"?"Retry repair":"Suggest repair"}</button></div>
    {!eligible&&<p className="muted">Automated repair is unavailable for this finding.</p>}
    {active&&!op?.id&&<p>Another finding has a repair in progress.</p>}
    {op?.id&&<div className="repair-lifecycle"><div className={`repair-stage repair-${op.status==="failed"||op.stage==="verification failed"?"failure":op.status==="complete"?tone(outcome):op.status==="queued"?"pending":"active"}`}><div role="status" aria-live="polite"><span className="repair-stage-kicker">Current stage</span><strong>{op.status==="failed" ? "Repair stopped" : label(op.stage)}</strong><p>{op.status==="failed" ? "The operation stopped. Review the details and retry when ready." : descriptions[op.stage||""] || "Showing the latest reported operation state."}</p></div><span className="repair-stage-meta">{elapsed}s elapsed{op.attempt?` · attempt ${op.attempt}`:""}{op.provider?` · ${op.provider}`:""}</span></div>
      <ol className="repair-phase-list" aria-label="Repair lifecycle">{phases.map((phase,index)=>{const state=phaseState(index);return <li key={phase} className={`repair-phase repair-${state}`} aria-current={index===currentPhase?"step":undefined}><span aria-hidden="true" className="repair-phase-dot"/><span>{phase}</span><small>{state==="active"?"In progress":state==="success"?"Completed":state==="failure"?"Stopped":state==="warning"?"Review needed":"Pending"}</small></li>})}</ol>
      {op.scope_start_line&&<p className="repair-scope">Permitted repair scope: lines {op.scope_start_line}–{op.scope_end_line}</p>}{op.error&&<div className="repair-error" role="alert"><h3>Operation stopped</h3><p>{op.error}</p><a href="/app/projects">Upload updated source</a></div>}
      {!!op.events?.length&&<details><summary>View lifecycle</summary><ol>{op.events.map((event,i)=><li key={i}>{new Date(event.at*1000).toLocaleTimeString()} · {event.stage}{event.provider?` · ${event.provider}`:""}{event.attempt?` · attempt ${event.attempt}`:""}</li>)}</ol></details>}
    </div>}
    {error&&<p role="alert">{error}</p>}
    {explanation&&<div><h3>AI explanation · {explanation.provider_used}</h3><p>{explanation.summary}</p><p>{explanation.impact}</p><p>{explanation.recommended_action}</p></div>}
    <h3>Code review {source&&<small> · {source.file}:{source.line}</small>}</h3>
    <div className="toolbar">{(["compare","original","proposed","diff"] as const).map(v=><button className="button" disabled={v==="diff"&&!repair?.diff} aria-pressed={view===v} key={v} onClick={()=>setView(v)}>{v==="proposed"?"Suggested repair":v}</button>)}</div>
    <div style={{display:"flex",flexWrap:"wrap",gap:16}}>
      {(view==="compare"||view==="original")&&<section style={{flex:"1 1 340px",minWidth:0}}><h4>Original source</h4>{source?<Code text={source.original} line={source.line}/>:<p>Loading source…</p>}</section>}
      {(view==="compare"||view==="proposed")&&<section style={{flex:"1 1 340px",minWidth:0}}><h4>{proposed?"Repair candidate":"Suggested repair"}</h4>{proposed?<Code text={proposed} line={source?.line}/>:<p>{latest?.edits.length?"See the unapplied suggestion below.":"A repair candidate has not been created."}</p>}</section>}
      {view==="diff"&&repair&&<section style={{flex:"1 1 100%",minWidth:0}}><h4>Validated diff</h4><pre className="code-block">{repair.diff}</pre></section>}
    </div>
    {attempts.map(attempt=><details key={attempt.attempt} open={attempt===latest&&op?.status==="failed"}><summary>View mismatch · attempt {attempt.attempt}</summary><p>{attempt.message}</p>{attempt.edits.map(edit=><div key={edit.edit_index}><h4>Unapplied AI suggestion · lines {edit.start_line}–{edit.end_line}</h4><p>Actual uploaded code</p><Code text={edit.actual}/><p>Text the AI expected</p><Code text={edit.expected}/><p>Suggested replacement — not applied</p><Code text={edit.replacement}/><p>{edit.reason}{edit.truncated?" (snippets truncated)":""}</p></div>)}<details><summary>Technical details</summary><p>{attempt.code}: {attempt.technical}</p></details></details>)}
    {repair&&<div><p>{repair.explanation}</p><p>{repair.metadata?.security_improvement}</p>{repair.metadata?.reasons?.map((reason,i)=><p key={i}>{reason}</p>)}{repair.metadata&&<p>Added {repair.metadata.added_lines} · deleted {repair.metadata.deleted_lines} lines</p>}{repair.metadata?.warnings?.map((warning,i)=><p key={i}>{warning}</p>)}</div>}
    <section className="repair-verification"><h4>Verification <span className={`repair-badge repair-${tone(outcome)}`}>{label(outcome)}</span></h4><div className="repair-checks">{["build","tests","sanitizers","security"].map(key=>{const value=checks?.[key] || (repair?"pending":"not_run");return <div className="repair-check" key={key}><span>{key==="sanitizers"?"Sanitizers":key.charAt(0).toUpperCase()+key.slice(1)}</span><span className={`repair-badge repair-${tone(value)}`}>{label(value)}</span></div>})}</div>{status?.checks?.details&&<details><summary>Build and test details</summary><pre className="repair-technical">{status.checks.details}</pre></details>}{status?.checks?.security_details&&<details><summary>Security check details</summary><p>{status.checks.security_details}</p></details>}</section>
    {repair?.state==="review_ready"&&<div>{outcome==="partially_verified"&&<label><input type="checkbox" checked={ack} onChange={e=>setAck(e.target.checked)}/> I understand unavailable checks were not completed.</label>}<button className="button primary" disabled={!!busy||(outcome==="partially_verified"&&!ack)} onClick={()=>void run("accept")}>{outcome==="partially_verified"?"Review limitations and accept":"Accept working copy"}</button></div>}
    {repair?.state==="verification_failed"&&<p>This candidate cannot be accepted. Review the checks or retry.</p>}
    {repair&&<a href={`/api/jobs/${jobId}/diff`}>Download {outcome==="verified"?"":"unverified "}patch for manual review</a>}
  </div>;
}

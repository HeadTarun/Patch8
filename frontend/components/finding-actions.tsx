"use client";
import { useEffect, useState } from "react";
import { Check, LoaderCircle, Sparkles } from "lucide-react";
import { applyRepair, explainFinding, getFindingSource, getPatch, getRepairStatus, getSavedExplanation, rejectRepair, type FindingExplanation } from "../lib/api";
import { CodePreview, RepairDiffPreview, UnifiedDiffPreview } from "./code-preview";

type Status = Awaited<ReturnType<typeof getRepairStatus>>;
type Source = Awaited<ReturnType<typeof getFindingSource>>;

export function FindingActions({jobId, findingId, eligible}: {jobId:string; findingId:string; eligible:boolean}) {
  const [status,setStatus]=useState<Status|null>(null);
  const [source,setSource]=useState<Source|null>(null);
  const [explanation,setExplanation]=useState<FindingExplanation|null>(null);
  const [busy,setBusy]=useState(""); const [error,setError]=useState(""); const [ack,setAck]=useState(false); const [reviewed,setReviewed]=useState(false);
  const [view,setView]=useState<"compare"|"original"|"proposed"|"diff">("compare"); const [now,setNow]=useState(Date.now());
  async function refresh(){try{setStatus(await getRepairStatus(jobId,findingId));}catch(e){setError(e instanceof Error?e.message:"Could not load repair status.");}}
  useEffect(()=>{
    setStatus(null);setSource(null);setAck(false);setReviewed(false);setView("compare");
    void refresh();
    getFindingSource(jobId,findingId).then(setSource).catch(e=>setError(e.message));
    getSavedExplanation(jobId,findingId).then(setExplanation).catch(()=>{});
  },[jobId,findingId]);
  const op=status?.operation; const repair=status?.repair; const active=!!status?.job_busy;
  useEffect(()=>{setReviewed(false);setAck(false)},[repair?.id]);
  useEffect(()=>{if(!active&&busy!=="repair")return;const timer=window.setInterval(()=>{setNow(Date.now());void refresh()},2000);return()=>window.clearInterval(timer)},[jobId,findingId,active,busy]);
  async function run(action:string){
    setBusy(action);setError("");
    try{
      if(action==="explain")setExplanation(await explainFinding(jobId,findingId));
      if(action==="repair"||action==="deep"){
        if(action==="deep"&&!window.confirm("Deep repair sends relevant source code and prior verification diagnostics to Groq. Continue?"))return;
        await getPatch(jobId,findingId,action==="deep"?"deep":"standard");await refresh();
      }
      if(action==="accept"&&repair){await applyRepair(jobId,repair.id,ack,reviewed);window.location.href=`/app/analysis/${jobId}`;}
      if(action==="reject"&&repair){await rejectRepair(jobId,repair.id);await refresh();}
    }catch(e){await refresh();setError(e instanceof Error?e.message:"Request failed.");}
    finally{setBusy("");}
  }
  const outcome=status?.checks?.verification_outcome;
  const attempts=status?.attempt_history?.length?status.attempt_history:op?.attempts||[];
  const latest=attempts.at(-1);
  const opActive=["running","queued","verifying"].includes(op?.status||"");
  const end=op?.generation_finished_at??op?.finished_at??(opActive?Math.min(now/1000,op?.deadline??now/1000):undefined);
  const elapsed=op?.started_at&&end?Math.min(180,Math.max(0,Math.floor(end-op.started_at))):null;
  const elapsedLabel=elapsed===null?"duration unavailable":`${Math.floor(elapsed/60)}:${String(elapsed%60).padStart(2,"0")}`;
  const humanReview=op?.status==="human_review"||((status?.attempt_count||0)>=(status?.max_attempts||3)&&!opActive&&repair?.state!=="review_ready"&&repair?.state!=="applied_to_copy");
  const proposed=status?.preview?.proposed;
  const checks=op?.check_states||status?.checks;
  const diagnostics=status?.checks?.build_diagnostics||[];
  const diagnosticName=(category:string)=>({syntax_error:"Syntax error",type_error:"Type error",compiler_error:"Compiler error",missing_project_dependency:"Missing project dependency",missing_system_header:"Missing system header",toolchain_unavailable:"Toolchain unavailable"}[category]||"Needs human review");
  return <div className="finding-actions">
    <div className="toolbar"><button className="button" disabled={!!busy} onClick={()=>void run("explain")}>{busy==="explain"?<><LoaderCircle size={14} className="scan-spinner"/> Explaining…</>:"Explain with AI"}</button>
      {!humanReview&&repair?.state!=="review_ready"&&repair?.state!=="applied_to_copy"&&status?.scan_provider!=="none"&&<button className="button primary" disabled={!!busy||active||!eligible} onClick={()=>void run("repair")}>{active||busy==="repair"?<><LoaderCircle size={14} className="scan-spinner"/> Repair in progress…</>:<><Sparkles size={14}/> {op?.status==="failed"||op?.status==="timed_out"||repair?.state==="verification_failed"||repair?.state==="rejected"?"Retry repair":"Suggest repair"}</>}</button>}
      {!humanReview&&repair?.state!=="review_ready"&&repair?.state!=="applied_to_copy"&&status?.deep_repair_available&&<button className="button" disabled={!!busy||active||!eligible} onClick={()=>void run("deep")}>{busy==="deep"?<><LoaderCircle size={14} className="scan-spinner"/> Deep repair in progress…</>:<><Sparkles size={14}/> Deep repair · {status.deep_model}</>}</button>}
    </div>
    {humanReview&&<p className="repair-human-review" role="status"><strong>Human review required.</strong> The three-suggestion limit has been reached. Review the original code and unapplied suggestions below.</p>}
    {status?.attempt_count!==undefined&&<p className="muted">Repair suggestions: {status.attempt_count} / {status.max_attempts}</p>}
    {status?.deep_repair_configured&&status.deep_repair_available&&<p className="muted">Deep repair uses Groq with high reasoning effort. Relevant source and prior check results are sent only when you choose this action.</p>}
    {!status?.deep_repair_configured&&status?.attempt_count!==undefined&&status.attempt_count<(status.max_attempts||3)&&status.scan_provider==="none"&&<p className="muted">Deep repair is unavailable until Groq is configured.</p>}
    {!eligible&&<p className="muted">Automated repair is unavailable for this finding.</p>}
    {active&&!op?.id&&<p className="muted">Another finding has a repair in progress.</p>}
    {op?.id&&<section className={`repair-operation repair-operation-${op.status||"pending"}`} role="status" aria-live="polite">
      <div className="repair-operation-heading"><strong>{op.stage||"Repair status"}</strong><span>{op.status==="verifying"?"Generation ":""}{elapsedLabel}{op.attempt?` · attempt ${op.attempt}`:""}{op.mode==="deep"?" · Deep repair":""}{op.provider?` · ${op.provider}`:""}{op.model?` · ${op.model}`:""}</span></div>
      {op.scope_start_line&&<p>Repair scope: lines {op.scope_start_line}–{op.scope_end_line}</p>}
      {op.error&&<div role="alert"><strong>{op.status==="timed_out"?"Repair timed out":"Repair stopped"}</strong><p>{op.error}</p></div>}
      {!!op.events?.length&&<details><summary>View repair events</summary><ol>{op.events.map((event,index)=><li key={`${event.at}-${index}`}>{new Date(event.at*1000).toLocaleTimeString()} · {event.stage}{event.provider?` · ${event.provider}`:""}{event.model?` · ${event.model}`:""}{event.attempt?` · attempt ${event.attempt}`:""}</li>)}</ol></details>}
    </section>}
    {error&&<p role="alert">{error}</p>}
    {explanation&&<section className="repair-explanation"><h3>AI explanation · {explanation.provider_used}</h3><p>{explanation.summary}</p><p>{explanation.impact}</p><p>{explanation.recommended_action}</p></section>}
    <div className="repair-preview-heading"><h3>Code review</h3>{source&&<span className="mono">{source.file}:{source.line}</span>}</div>
    <div className="toolbar repair-preview-tabs" role="group" aria-label="Repair preview views">
      {(["compare","original","proposed","diff"] as const).map(mode=><button className="button" aria-pressed={view===mode} disabled={(mode==="proposed"&&!proposed)||(mode==="diff"&&!repair?.diff)} key={mode} onClick={()=>setView(mode)}>{mode==="proposed"?"Suggested repair":mode==="diff"?"Unified diff":mode}</button>)}
    </div>
    {view==="compare"&&repair?.diff?<RepairDiffPreview diff={repair.diff}/>:<div className="repair-code-columns">
      {(view==="compare"||view==="original")&&<section><h4>Original source</h4>{source?<CodePreview text={source.original} line={source.line} label="Original source"/>:<p className="muted">Loading source…</p>}</section>}
      {(view==="compare"||view==="proposed")&&<section><h4>{proposed?"Proposed repair":"Suggested repair"}</h4>{proposed?<CodePreview text={proposed} line={source?.line} label="Proposed source"/>:<p className="muted">{latest?.edits.length?"Review the unapplied suggestion below.":"A repair candidate has not been created."}</p>}</section>}
    </div>}
    {view==="diff"&&repair?.diff&&<UnifiedDiffPreview diff={repair.diff}/>}
    {status?.checks?.baseline_shared_dependency&&<p className="repair-human-review" role="status"><strong>Human review required.</strong> The original and proposed source share a missing dependency, so compilation is unavailable. Review the diagnostics and code; partial acceptance requires acknowledgment.</p>}
    {!!diagnostics.length&&<section className="compile-diagnostics" aria-label="Compiler diagnostics"><h3>Compiler diagnostics · human review</h3><p>Compare each message with the original and proposed code above. These results are attributed to the source shown.</p><ul>{diagnostics.map((item,index)=><li className={`compile-diagnostic compile-${item.category}`} key={`${item.source}-${item.file}-${item.line}-${index}`}><strong>{diagnosticName(item.category)}</strong><span>{item.source} · {item.file}{item.line?`:${item.line}:${item.column}`:""}</span><code>{item.message}</code></li>)}</ul></section>}
    {status?.checks?.build==="passed"&&<p className="compile-diagnostic-clean" role="status">No compiler errors were reported. Review the proposed code before accepting.</p>}
    {attempts.map(attempt=><details className="repair-attempt" key={attempt.attempt} open={attempt===latest&&(op?.status==="failed"||op?.status==="timed_out"||op?.status==="human_review")}><summary>Unapplied suggestion · attempt {attempt.attempt}</summary><p>{attempt.message}</p>
      {attempt.edits.map(edit=><section className="repair-attempt-edit" key={edit.edit_index}><h4>Proposed edit · lines {edit.start_line}–{edit.end_line}</h4><div className="repair-code-columns"><div><span className="repair-code-label">Uploaded source</span><CodePreview text={edit.actual||"(no matching source text)"} startLine={edit.start_line}/></div><div><span className="repair-code-label">AI expected</span><CodePreview text={edit.expected||"(empty)"} startLine={edit.start_line}/></div><div><span className="repair-code-label">Suggested replacement · not applied</span><CodePreview text={edit.replacement||"(empty)"} startLine={edit.start_line}/></div></div><p>{edit.reason}{edit.truncated?" (snippets truncated)":""}</p></section>)}
      {attempt.technical&&<details><summary>Technical detail · {attempt.code}</summary><p className="repair-technical">{attempt.technical}</p></details>}
    </details>)}
    {repair&&<section className="repair-explanation"><p>{repair.explanation}</p>{repair.provider_used&&<p>Generated by {repair.provider_used}{repair.model_used?` · ${repair.model_used}`:""}</p>}<p>{repair.metadata?.security_improvement}</p>{repair.metadata?.reasons?.map((reason,index)=><p key={index}>{reason}</p>)}{repair.metadata&&<p>Added {repair.metadata.added_lines} · deleted {repair.metadata.deleted_lines} lines</p>}{repair.metadata?.warnings?.map((warning,index)=><p key={index}>{warning}</p>)}</section>}
    {repair?.review&&<p className="muted">Author review recorded {new Date(repair.review.reviewed_at*1000).toLocaleString()} · {repair.review.verification_outcome}</p>}
    <section className="repair-verification"><h4>Verification: {outcome||"Not started"}</h4>{outcome&&outcome!=="verified"&&<p className="muted">Some checks failed or could not run. Review each result below; partial verification does not confirm full correctness.</p>}{checks&&<div className="repair-check-grid">{["build","tests","sanitizers","security"].map(key=><div className="repair-check" key={key}><span>{key}</span><strong className={`verify-${checks[key]==="passed"?"good":checks[key]==="failed"?"bad":["not_available","unverified","partially_verified"].includes(String(checks[key]))?"warn":"neutral"}`}>{String(checks[key]||"pending")}</strong></div>)}</div>}
      {status?.checks?.details&&<details><summary>Build and test details</summary><pre className="verification-diagnostics">{status.checks.details}</pre></details>}
      {status?.checks?.security_details&&<details><summary>Security check details</summary><p>{status.checks.security_details}</p></details>}
    </section>
    {repair?.state==="review_ready"&&<div className="repair-accept-row"><label><input type="checkbox" checked={reviewed} onChange={event=>setReviewed(event.target.checked)}/> I reviewed the original and proposed code and the verification results.</label>{outcome==="partially_verified"&&<label><input type="checkbox" checked={ack} onChange={event=>setAck(event.target.checked)}/> I understand unavailable checks were not completed.</label>}<button className="button" disabled={!!busy||active} onClick={()=>void run("reject")}>{busy==="reject"?<><LoaderCircle size={14} className="scan-spinner"/> Rejecting…</> : "Reject suggestion"}</button><button className="button primary" disabled={!!busy||!reviewed||(outcome==="partially_verified"&&!ack)} onClick={()=>void run("accept")}>{busy==="accept"?<><LoaderCircle size={14} className="scan-spinner"/> Accepting…</>:<><Check size={14}/> {outcome==="verified"?"Accept verified copy":"Accept reviewed copy"}</>}</button></div>}
    {repair?.state==="verification_failed"&&<p className="repair-failure-note">This candidate cannot be accepted. Review verification results or retry within the remaining suggestion limit.</p>}
    {repair&&<a href={`/api/jobs/${jobId}/diff`}>Download {outcome==="verified"?"":"unverified "}patch for manual review</a>}
  </div>;
}

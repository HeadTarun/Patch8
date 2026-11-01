"use client";
import { FileDown } from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { EmptyState, ErrorState, LoadingState } from "@/components/ui/states";
import { getJobs, type Job } from "@/lib/api";
import { useRemote } from "@/lib/use-remote";
export default function Reports(){const{data,loading,error,retry}=useRemote(getJobs);return <AppShell active="Reports"><main className="app-content"><div className="page-head"><div><div className="eyebrow">SCAN REPORTS</div><h1>Reports</h1><p>Download actual scan outputs for projects retained in your workspace.</p></div></div>{loading?<LoadingState rows={4}/>:error?<ErrorState retry={retry}/>:!data?.some(job=>job.report)?<EmptyState title="No reports yet" body="Complete a scan to export its findings as SARIF."/>:<div className="grid gap-2">{data.filter(job=>job.report).map((job:Job)=><article className="repo-card panel" key={job.id}><span className="repo-avatar"><FileDown size={17}/></span><span className="repo-meta"><strong>{job.name}</strong><span className="mono">{job.id} · {job.report?.scan_status||"Not verified"} · {job.findings?.length||0} findings</span></span><a className="button small" href={`/api/jobs/${job.id}/sarif`} download>Export SARIF <FileDown size={13}/></a></article>)}</div>}</main></AppShell>}

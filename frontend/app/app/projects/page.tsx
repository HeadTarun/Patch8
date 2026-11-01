"use client";
import { useEffect, useRef, useState } from "react";
import { Archive, FileCode2, FolderOpen, LoaderCircle, Upload } from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { CodePreview } from "@/components/code-preview";
import { EmptyState, ErrorState, LoadingState } from "@/components/ui/states";
import { createScan, getJobs, type Job } from "@/lib/api";
import { useRemote } from "@/lib/use-remote";

export default function Projects() {
  const { data, loading, error, retry } = useRemote(getJobs);
  const [selected, setSelected] = useState<File[]>([]);
  const [progress, setProgress] = useState<number | null>(null);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [previewKey, setPreviewKey] = useState("");
  const [previewText, setPreviewText] = useState("");
  const [previewError, setPreviewError] = useState("");
  const folderRef = useRef<HTMLInputElement>(null);
  const sourceFiles = selected.filter(file => /\.(c|cc|cpp|cxx|h|hh|hpp|hxx)$/i.test(file.name));
  const selectedKey = (file: File) => (file as File & {webkitRelativePath?: string}).webkitRelativePath || file.name;
  const previewFile = sourceFiles.find(file => selectedKey(file) === previewKey) || sourceFiles[0];
  useEffect(() => {
    let current = true;
    setPreviewText(""); setPreviewError("");
    if (!previewFile) return () => { current = false; };
    if (previewFile.size > 200_000) { setPreviewError("This source exceeds the 200 KB preview limit."); return () => { current = false; }; }
    previewFile.text().then(text => { if (current) setPreviewText(text); }).catch(() => { if (current) setPreviewError("Could not read this source file."); });
    return () => { current = false; };
  }, [previewFile]);
  function choose(files: FileList | null, folder = false) {
    let chosen=Array.from(files||[]);
    if(folder){const extensions=new Set([".c",".cc",".cpp",".cxx",".h",".hh",".hpp",".hxx",".cmake",".txt",".md",".json",".yaml",".yml",".toml",".ini",".cfg",".mk",".xml",".sh",".properties",".gradle",".bazel",".bzl",".make",".conf"]);const names=new Set(["makefile","cmakelists.txt","dockerfile","meson.build","meson.options","configure","configure.ac","readme",".gitignore",".editorconfig"]);const ignored=new Set([".git","node_modules","build","dist","vendor","venv",".venv","__pycache__","target"]);const included=chosen.filter(file=>{const relative=(file.webkitRelativePath||file.name).replace(/\\/g,"/");const parts=relative.split("/");const basename=parts[parts.length-1]||"";const extension=basename.includes(".")?basename.slice(basename.lastIndexOf(".")).toLowerCase():"";return !parts.some(part=>ignored.has(part.toLowerCase()))&&(extensions.has(extension)||names.has(basename.toLowerCase()));});setMessage(included.length<chosen.length?`${chosen.length-included.length} unsupported or generated file(s) skipped.`:"");chosen=included;}
    else setMessage("");
    setSelected(chosen);
    const firstSource = chosen.find(file => /\.(c|cc|cpp|cxx|h|hh|hpp|hxx)$/i.test(file.name));
    setPreviewKey(firstSource ? (firstSource as File & {webkitRelativePath?: string}).webkitRelativePath || firstSource.name : "");
  }
  async function submit() {
    if (!selected.length) return;
    setBusy(true); setProgress(0); setMessage("");
    try { const result = await createScan(selected, setProgress); window.location.href = `/app/analysis/${result.id}`; }
    catch (reason) { setMessage(reason instanceof Error ? reason.message : "Upload failed."); setBusy(false); setProgress(null); }
  }
  return <AppShell active="Projects"><main className="app-content">
    <div className="page-head"><div><div className="eyebrow">SOURCE PROJECTS</div><h1>Upload a project</h1><p>Scan C and C++ files with the installed Clang, Cppcheck, and Semgrep analyzers. Files are retained for up to one hour.</p></div></div>
    <section className="panel setting-card"><div className="panel-head"><div><h2>New scan</h2><p className="muted">Choose files, a project folder, or one ZIP archive.</p></div><Upload size={18} className="accent"/></div>
      <div className="filter-row"><label className="button"><input className="sr-only" aria-label="Choose source files" type="file" accept=".c,.cc,.cpp,.cxx,.h,.hh,.hpp,.hxx,.zip" multiple onChange={e=>choose(e.target.files)}/><Archive size={15}/> Choose files or ZIP</label><input ref={folderRef} className="sr-only" type="file" multiple aria-label="Choose project folder" onChange={e=>choose(e.target.files,true)}/><button className="button" type="button" onClick={()=>{folderRef.current?.setAttribute("webkitdirectory","");folderRef.current?.click()}}><FolderOpen size={15}/> Choose folder</button></div>
      {selected.length>0&&<div className="section-gap"><div className="eyebrow">{selected.length} FILE{selected.length===1?"":"S"} SELECTED</div><div className="code-block" style={{maxHeight:140}}>{selected.slice(0,12).map(file=><span className="code-line" key={`${file.webkitRelativePath}-${file.name}`}>{file.webkitRelativePath||file.name}</span>)}{selected.length>12&&<span className="code-line">and {selected.length-12} more…</span>}</div>
        <section className="upload-source-preview" aria-label="Selected source preview"><div className="upload-preview-head"><div><div className="eyebrow">SOURCE PREVIEW</div><strong>{previewFile ? selectedKey(previewFile) : "Archive preview"}</strong></div><FileCode2 size={17}/></div>
          {sourceFiles.length>1&&<label className="source-preview-select">Preview file<select value={previewFile ? selectedKey(previewFile) : ""} onChange={event=>setPreviewKey(event.target.value)}>{sourceFiles.map(file=><option key={selectedKey(file)} value={selectedKey(file)}>{selectedKey(file)}</option>)}</select></label>}
          {previewText?<CodePreview text={previewText} label="Selected uploaded source"/>:previewError?<p className="muted">{previewError}</p>:selected.some(file=>file.name.toLowerCase().endsWith(".zip"))?<p className="muted">ZIP source previews are available on the analysis page after extraction.</p>:<p className="muted">Select a C/C++ source file to preview its contents.</p>}
        </section>
      </div>}
      {busy&&<div className="section-gap" role="status"><div className="setting-row"><span>{progress===100?"Upload complete · scan queued":"Uploading project"}</span><span>{progress??0}%</span></div><div className="upload-progress-track"><div className="upload-progress-fill" style={{width:`${progress||0}%`}}/></div><p className="muted">The analysis worker updates the scan status on the next page.</p></div>}
      {message&&<p role="status" className="muted">{message}</p>}<div className="toolbar section-gap"><button className="button primary" disabled={!selected.length||busy} onClick={submit}>{busy?<><LoaderCircle size={14} className="scan-spinner"/> Uploading…</>:<>Start scan <Upload size={14}/></>}</button><span className="muted">C/C++ sources (.c/.cc/.cpp/.cxx and headers) plus common text project files · ZIP up to 25 MB · source files up to 200 KB each. Generated folders are skipped.</span></div>
    </section>
    <section className="section-gap"><div className="panel-head"><h2>Recent projects and scans</h2><span className="tag">{data?.length||0}</span></div>{loading?<LoadingState rows={3}/>:error?<ErrorState retry={retry}/>:!data?.length?<EmptyState title="No uploaded projects" body="After your first upload, scan history will appear here."/>:<div className="grid gap-2">{data.map((job:Job)=><a className="repo-card panel" href={`/app/analysis/${job.id}`} key={job.id}><span className="repo-avatar"><FolderOpen size={17}/></span><span className="repo-meta"><strong>{job.name}</strong><span className="mono">{job.id} · {new Date(job.created_at*1000).toLocaleString()} · {job.source_files??job.uploaded_files?.length??"—"} source files</span></span><span className={`status-pill ${job.state==="complete"?"good":job.state==="failed"?"bad":""}`}>{job.state}</span></a>)}</div>}</section>
  </main></AppShell>;
}

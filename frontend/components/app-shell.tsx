"use client";
import { Fragment, useEffect, useState } from "react";
import { ArrowUpRight, Boxes, CircleDot, FileDown, LayoutDashboard, ListChecks, Settings2, Upload } from "lucide-react";
import { Brand } from "@/components/brand";
const links = [{ href: "/app", label: "Overview", icon: LayoutDashboard }, { href: "/app/projects", label: "Projects", icon: Boxes }, { href: "/app/scans", label: "Findings", icon: ListChecks }, { href: "/app/reports", label: "Reports", icon: FileDown }, { href: "/app/settings", label: "Settings", icon: Settings2 }];
export function AppShell({ children, active = "" }: { children: React.ReactNode; active?: string }) {
  const [email,setEmail]=useState(""); const [checking,setChecking]=useState(true);
  const [sessionError,setSessionError]=useState(""); const [attempt,setAttempt]=useState(0);
  useEffect(()=>{
    const controller=new AbortController(); setChecking(true);setSessionError("");
    fetch("/api/auth/me", {signal:AbortSignal.any([controller.signal,AbortSignal.timeout(15000)])}).then(async response=>{
      if(response.status===401){window.location.replace("/login");return;}
      if(!response.ok)throw new Error("The account service is temporarily unavailable.");
      const user=await response.json();setEmail(user.email);setChecking(false);
    }).catch(error=>{if(error.name!=="AbortError"){setSessionError("Could not connect to your workspace. Retry when the service is available.");setChecking(false);}});
    return ()=>controller.abort();
  },[attempt]);
  async function signOut(){try{const response=await fetch("/api/auth/logout",{method:"POST"});if(!response.ok)throw new Error();window.location.replace("/login");}catch{setSessionError("Sign out could not finish. Retry to safely end your session.");}}
  if(checking)return <main className="app-content"><div className="skeleton-card" aria-label="Checking session"/></main>;
  if(sessionError)return <main className="app-content"><p role="alert">{sessionError}</p><button className="button" onClick={()=>setAttempt(value=>value+1)}>Retry connection</button><button className="button" onClick={()=>void signOut()}>Retry sign out</button></main>;
  return <div className="app-frame"><aside className="sidebar"><Brand app /><nav aria-label="Main navigation">{links.map(({ href, label, icon: Icon }) => <Fragment key={label}>{label === "Settings" && <div className="side-label">Workspace</div>}<a className={`side-link ${active === label ? "active" : ""}`} href={href} aria-label={label} aria-current={active === label ? "page" : undefined}><Icon size={16}/><span>{label}</span></a></Fragment>)}</nav><div className="side-bottom"><div className="side-label">SIGNED IN</div><span className="side-link" title={email}><CircleDot size={15}/><span className="truncate">{email}</span></span><a href="/" className="side-link"><ArrowUpRight size={13}/><span>Product overview</span></a></div></aside><section className="app-main"><header className="app-topbar"><span className="mono">Patch8 / scans</span><div className="toolbar"><button className="button small" onClick={signOut}>Sign out</button><a className="button small primary" href="/app/projects"><Upload size={13}/> New scan</a></div></header>{children}</section></div>;
}

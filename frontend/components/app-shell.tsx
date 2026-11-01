"use client";
import { Fragment, useEffect, useState } from "react";
import { Activity, ArrowUpRight, Boxes, CircleDot, FileDown, LayoutDashboard, ListChecks, Settings2, ShieldCheck, Upload } from "lucide-react";
import { Brand } from "@/components/brand";
const links = [{ href: "/app", label: "Overview", icon: LayoutDashboard }, { href: "/app/projects", label: "Projects", icon: Boxes }, { href: "/app/scans", label: "Findings", icon: ListChecks }, { href: "/app/reports", label: "Reports", icon: FileDown }, { href: "/app/settings", label: "Settings", icon: Settings2 }];
export function AppShell({ children, active = "" }: { children: React.ReactNode; active?: string }) {
  const [email,setEmail]=useState(""); const [checking,setChecking]=useState(true);
  useEffect(()=>{fetch("/api/auth/me").then(async response=>{if(!response.ok){window.location.replace("/login");return;}const user=await response.json();setEmail(user.email);setChecking(false);}).catch(()=>window.location.replace("/login"));},[]);
  async function signOut(){await fetch("/api/auth/logout",{method:"POST"});window.location.replace("/login");}
  if(checking)return <main className="app-content"><div className="skeleton-card" aria-label="Checking session"/></main>;
  return <div className="app-frame"><aside className="sidebar"><Brand app /><nav aria-label="Main navigation">{links.map(({ href, label, icon: Icon }) => <Fragment key={label}>{label === "Settings" && <div className="side-label">Workspace</div>}<a className={`side-link ${active === label ? "active" : ""}`} href={href} aria-label={label} aria-current={active === label ? "page" : undefined}><Icon size={16}/><span>{label}</span></a></Fragment>)}</nav><div className="side-bottom"><div className="side-label">SIGNED IN</div><span className="side-link" title={email}><CircleDot size={15}/><span className="truncate">{email}</span></span><a href="/" className="side-link"><ArrowUpRight size={13}/><span>Product overview</span></a></div></aside><section className="app-main"><header className="app-topbar"><span className="mono">PatchProof / scans</span><div className="toolbar"><button className="button small" onClick={signOut}>Sign out</button><a className="button small primary" href="/app/projects"><Upload size={13}/> New scan</a></div></header>{children}</section></div>;
}

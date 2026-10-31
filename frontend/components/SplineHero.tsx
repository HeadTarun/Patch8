"use client";
import dynamic from "next/dynamic";
import { Component, useEffect, useState } from "react";
import type { ErrorInfo, ReactNode } from "react";
import { useReducedMotion } from "framer-motion";
const SplineCanvas = dynamic(() => import("@splinetool/react-spline/next"), { ssr: false });
class SceneBoundary extends Component<{ children: ReactNode; fallback: ReactNode }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() { return { failed: true }; }
  componentDidCatch(_error: Error, _info: ErrorInfo) {}
  render() { return this.state.failed ? this.props.fallback : this.props.children; }
}
export default function SplineHero() {
  const reduceMotion = useReducedMotion(); const [allowed, setAllowed] = useState(false); const [loaded, setLoaded] = useState(false);
  useEffect(() => { const query = window.matchMedia("(min-width: 768px) and (prefers-reduced-motion: no-preference)"); const update = () => setAllowed(query.matches && Boolean(process.env.NEXT_PUBLIC_SPLINE_SCENE_URL)); update(); query.addEventListener("change", update); return () => query.removeEventListener("change", update); }, []);
  const poster = <img className="spline-poster" src="/spline-poster.svg" alt="Glowing cyan shield surrounded by scanning nodes" style={{ opacity: loaded && allowed ? 0 : 1 }} />;
  return <div className="spline-wrap" aria-label="PatchGuard scanning visualization">
    <div className="hero-halo" />{poster}
    {allowed && !reduceMotion && <SceneBoundary fallback={poster}><div className="spline-canvas" style={{ opacity: loaded ? 1 : 0 }}><SplineCanvas scene={process.env.NEXT_PUBLIC_SPLINE_SCENE_URL!} onLoad={() => setLoaded(true)} onError={() => setLoaded(false)} /></div></SceneBoundary>}
  </div>;
}

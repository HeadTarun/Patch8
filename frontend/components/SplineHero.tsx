"use client";
import dynamic from "next/dynamic";
import { Component, useEffect, useRef, useState } from "react";
import type { ErrorInfo, ReactNode } from "react";
import { Play } from "lucide-react";
import { useReducedMotion } from "framer-motion";
const SplineCanvas = dynamic(() => import("@splinetool/react-spline/next"), { ssr: false });
type Vector3 = { x: number; y: number; z: number };
type SceneObject = { position: Vector3; rotation: Vector3; scale: Vector3; visible: boolean };
type SceneRuntime = { findObjectByName: (name: string) => SceneObject | null };
type Tile = { parts: SceneObject[]; from: Vector3[]; target: [number, number] };
type Playground = { tiles: Tile[]; flaw: SceneObject; check: SceneObject[]; nodes: { object: SceneObject; from: Vector3; phase: number }[]; orbit: SceneObject };
class SceneBoundary extends Component<{ children: ReactNode; fallback: ReactNode; onError: () => void }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() { return { failed: true }; }
  componentDidCatch(_error: Error, _info: ErrorInfo) { this.props.onError(); }
  render() { return this.state.failed ? this.props.fallback : this.props.children; }
}
export default function SplineHero() {
  const reduceMotion = useReducedMotion(); const [allowed, setAllowed] = useState(false); const [loaded, setLoaded] = useState(false);
  const [playground, setPlayground] = useState<Playground | null>(null);
  const [played, setPlayed] = useState(false);
  const frame = useRef<number | null>(null);
  useEffect(() => { const query = window.matchMedia("(min-width: 768px) and (prefers-reduced-motion: no-preference)"); const update = () => setAllowed(query.matches && Boolean(process.env.NEXT_PUBLIC_SPLINE_SCENE_URL)); update(); query.addEventListener("change", update); return () => query.removeEventListener("change", update); }, []);
  useEffect(() => () => { if (frame.current !== null) cancelAnimationFrame(frame.current); }, []);
  useEffect(() => { if (!allowed || reduceMotion) { if (frame.current !== null) cancelAnimationFrame(frame.current); frame.current = null; setLoaded(false); setPlayground(null); } }, [allowed, reduceMotion]);
  function prepareScene(app: unknown) {
    const runtime = app as SceneRuntime;
    const get = (name: string) => runtime.findObjectByName(name) ?? null;
    const tileSpecs: [string, string[], number, number][] = [
      ["Tile Panel 1", ["Tile Code Line 1A", "Tile Code Line 1B"], -140, 112],
      ["Tile Panel 2", ["Tile Code Line 2A", "Tile Code Line 2B"], -140, -112],
      ["Tile Panel 3", ["Tile Code Line 3A", "Tile Code Line 3B"], 140, 112],
      ["Tile Panel 4", ["Tile Code Line 4A", "Tile Code Line 4B"], 140, -112],
    ];
    const tiles = tileSpecs.map(([panelName, codeNames, x, y]) => {
      const parts = [get(panelName), ...codeNames.map(get)];
      return parts.some(part => !part) ? null : { parts: parts as SceneObject[], from: (parts as SceneObject[]).map(part => ({ ...part.position })), target: [x, y] as [number, number] };
    });
    const flaw = get("Flaw Marker"); const check = [get("Check Short"), get("Check Long")]; const orbit = get("Scan Orbit");
    const nodes = Array.from({ length: 6 }, (_, i) => get(`Network Node ${i + 1}`));
    if (tiles.some(tile => !tile) || !flaw || check.some(part => !part) || !orbit || nodes.some(node => !node)) return;
    flaw.visible = true;
    check.forEach(part => { part!.visible = false; part!.scale.x = 0.001; part!.scale.y = 0.001; });
    setPlayground({ tiles: tiles as Tile[], flaw, check: check as SceneObject[], orbit, nodes: nodes.map((object, i) => ({ object: object!, from: { ...object!.position }, phase: i * 1.8 })) });
    setLoaded(true);
  }
  function playScan() {
    if (!playground) return;
    if (frame.current !== null) cancelAnimationFrame(frame.current);
    setPlayed(true);
    const started = performance.now(); let checksShown = false;
    playground.tiles.forEach(tile => tile.parts.forEach((part, index) => Object.assign(part.position, tile.from[index])));
    playground.flaw.visible = true; Object.assign(playground.flaw.scale, { x: 1, y: 1, z: 1 });
    playground.check.forEach(part => { part.visible = false; Object.assign(part.scale, { x: 0.001, y: 0.001, z: 1 }); });
    const ease = (value: number) => { const p = Math.max(0, Math.min(1, value)); return 1 - Math.pow(1 - p, 3); };
    const tick = (now: number) => {
      const elapsed = now - started;
      if (elapsed < 2700) {
        playground.tiles.forEach((tile, i) => tile.parts.forEach((part, index) => {
          const from = tile.from[index]; const progress = ease((elapsed - i * 110) / 1450);
          const endX = tile.target[0] + from.x - tile.from[0].x; const endY = tile.target[1] + from.y - tile.from[0].y;
          part.position.x = from.x + (endX - from.x) * progress;
          part.position.y = from.y + (endY - from.y) * progress;
        }));
        const pulse = 1 + Math.sin(now * 0.018) * 0.16;
        Object.assign(playground.flaw.scale, { x: pulse, y: pulse, z: pulse });
        if (elapsed > 1750 && !checksShown) { checksShown = true; playground.flaw.visible = false; playground.check.forEach(part => { part.visible = true; }); }
        if (checksShown) { const reveal = ease((elapsed - 1750) / 420); playground.check.forEach(part => { part.scale.x = reveal; part.scale.y = reveal; }); }
      } else {
        playground.tiles.forEach(tile => tile.parts.forEach((part, index) => Object.assign(part.position, { x: tile.target[0] + tile.from[index].x - tile.from[0].x, y: tile.target[1] + tile.from[index].y - tile.from[0].y })));
        playground.flaw.visible = false;
        playground.check.forEach(part => { part.visible = true; part.scale.x = 1; part.scale.y = 1; });
        checksShown = true;
      }
      playground.nodes.forEach(({ object, from, phase }) => { object.position.y = from.y + Math.sin(now * 0.0007 + phase) * 3; });
      playground.orbit.rotation.z = Math.sin(now * 0.0002) * 1.2;
      frame.current = requestAnimationFrame(tick);
    };
    frame.current = requestAnimationFrame(tick);
  }
  const poster = <img className="spline-poster" src="/spline-poster.svg" alt="Navy and blue shield surrounded by connected scanning nodes" style={{ opacity: loaded && allowed ? 0 : 1 }} />;
  return <div className="spline-wrap" aria-label="PatchProof scanning visualization">
    <div className="hero-halo" />{poster}
    {allowed && !reduceMotion && <SceneBoundary onError={() => { setPlayground(null); setLoaded(false); }} fallback={<img className="spline-poster" src="/spline-poster.svg" alt="Navy and blue shield surrounded by connected scanning nodes" />}><div className="spline-canvas" style={{ opacity: loaded ? 1 : 0 }}><SplineCanvas scene={process.env.NEXT_PUBLIC_SPLINE_SCENE_URL!} onLoad={prepareScene} onError={() => { setPlayground(null); setLoaded(false); }} /></div></SceneBoundary>}
    {allowed && !reduceMotion && loaded && playground && <button className="button spline-play" type="button" aria-label={played ? "Replay the sample scan animation" : "Play the sample scan animation"} onClick={playScan}><Play size={14} aria-hidden="true" />{played ? "Replay scan" : "Play scan"}</button>}
  </div>;
}

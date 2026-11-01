"use client";

import { useEffect, useRef } from "react";

type Particle = {
  x: number; y: number; vx: number; vy: number;
  offsetX: number; offsetY: number; radius: number; phase: number; color: string;
};

const colors = ["101,181,255", "77,193,215", "117,143,231", "164,155,234"];

export function ParticleBackground() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    const context = canvas?.getContext("2d");
    if (!canvas || !context) return;

    const motion = window.matchMedia("(prefers-reduced-motion: reduce)");
    let width = 0;
    let height = 0;
    let particles: Particle[] = [];
    let frame = 0;
    let previousTime = 0;
    let elapsed = 0;
    let pointer: { x: number; y: number } | null = null;

    function draw(delta: number) {
      if (!context) return;
      elapsed += delta;
      context.clearRect(0, 0, width, height);
      const easing = 1 - Math.exp(-delta * 5);

      for (const particle of particles) {
        particle.x += particle.vx * delta;
        particle.y += particle.vy * delta;
        const margin = 30;
        if (particle.x < -margin) particle.x = width + margin;
        if (particle.x > width + margin) particle.x = -margin;
        if (particle.y < -margin) particle.y = height + margin;
        if (particle.y > height + margin) particle.y = -margin;

        let targetX = 0;
        let targetY = 0;
        if (pointer && !motion.matches) {
          const dx = particle.x - pointer.x;
          const dy = particle.y - pointer.y;
          const distance = Math.hypot(dx, dy);
          if (distance < 180) {
            const force = (1 - distance / 180) * 65;
            targetX = dx / (distance || 1) * force;
            targetY = dy / (distance || 1) * force;
          }
        }
        particle.offsetX += (targetX - particle.offsetX) * easing;
        particle.offsetY += (targetY - particle.offsetY) * easing;
      }

      // Connections follow the current positions, including mouse displacement.
      const linkDistance = width < 640 ? 115 : 155;
      for (let i = 0; i < particles.length; i++) {
        const a = particles[i];
        const ax = a.x + a.offsetX;
        const ay = a.y + a.offsetY;
        for (let j = i + 1; j < particles.length; j++) {
          const b = particles[j];
          const bx = b.x + b.offsetX;
          const by = b.y + b.offsetY;
          const distance = Math.hypot(ax - bx, ay - by);
          if (distance >= linkDistance) continue;
          context.strokeStyle = `rgba(101,181,255,${(1 - distance / linkDistance) * 0.23})`;
          context.lineWidth = 0.7;
          context.beginPath();
          context.moveTo(ax, ay);
          context.lineTo(bx, by);
          context.stroke();
        }
      }

      for (const particle of particles) {
        const x = particle.x + particle.offsetX;
        const y = particle.y + particle.offsetY;
        const opacity = 0.5 + Math.sin(elapsed * 0.65 + particle.phase) * 0.18;
        context.fillStyle = `rgba(${particle.color},0.06)`;
        context.beginPath();
        context.arc(x, y, particle.radius * 3, 0, Math.PI * 2);
        context.fill();
        context.fillStyle = `rgba(${particle.color},${opacity})`;
        context.beginPath();
        context.arc(x, y, particle.radius, 0, Math.PI * 2);
        context.fill();
      }
    }

    function animate(time: number) {
      const delta = previousTime ? Math.min((time - previousTime) / 1000, 0.05) : 0;
      previousTime = time;
      draw(delta);
      frame = requestAnimationFrame(animate);
    }

    function syncAnimation() {
      cancelAnimationFrame(frame);
      previousTime = 0;
      if (motion.matches) {
        pointer = null;
        particles.forEach(particle => { particle.offsetX = 0; particle.offsetY = 0; });
      }
      draw(0);
      if (!motion.matches && !document.hidden) frame = requestAnimationFrame(animate);
    }

    function resize() {
      if (!canvas || !context) return;
      width = window.innerWidth;
      height = window.innerHeight;
      const ratio = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = Math.round(width * ratio);
      canvas.height = Math.round(height * ratio);
      context.setTransform(ratio, 0, 0, ratio, 0, 0);
      const count = Math.min(width < 640 ? 32 : 95, Math.max(24, Math.round(width * height / 14000)));
      particles = Array.from({ length: count }, (_, index) => {
        const angle = Math.random() * Math.PI * 2;
        const speed = 7 + Math.random() * 11;
        return {
          x: Math.random() * width, y: Math.random() * height,
          vx: Math.cos(angle) * speed, vy: Math.sin(angle) * speed,
          offsetX: 0, offsetY: 0, radius: 1.2 + Math.random() * 1.1,
          phase: Math.random() * Math.PI * 2, color: colors[index % colors.length],
        };
      });
      syncAnimation();
    }

    function movePointer(event: PointerEvent) {
      if (event.pointerType === "mouse") pointer = { x: event.clientX, y: event.clientY };
    }
    function clearPointer() { pointer = null; }
    function leaveWindow(event: PointerEvent) { if (!event.relatedTarget) clearPointer(); }

    resize();
    window.addEventListener("resize", resize);
    window.addEventListener("pointermove", movePointer, { passive: true });
    window.addEventListener("pointerout", leaveWindow);
    window.addEventListener("blur", clearPointer);
    document.addEventListener("visibilitychange", syncAnimation);
    motion.addEventListener("change", syncAnimation);
    return () => {
      cancelAnimationFrame(frame);
      window.removeEventListener("resize", resize);
      window.removeEventListener("pointermove", movePointer);
      window.removeEventListener("pointerout", leaveWindow);
      window.removeEventListener("blur", clearPointer);
      document.removeEventListener("visibilitychange", syncAnimation);
      motion.removeEventListener("change", syncAnimation);
    };
  }, []);

  return <canvas ref={canvasRef} className="particle-background" aria-hidden="true" />;
}

"use client";

import { useMemo } from "react";

/** Deterministic per-key usage sparkline (last ~20 buckets). */
export function UsageSparkline({
  seed,
  width = 96,
  height = 28,
}: {
  seed: string;
  width?: number;
  height?: number;
}) {
  const path = useMemo(() => {
    let h = 0;
    for (let i = 0; i < seed.length; i++) h = (h * 31 + seed.charCodeAt(i)) >>> 0;
    const rand = () => {
      h = (h * 1664525 + 1013904223) >>> 0;
      return (h >>> 8) / 16777216;
    };
    const n = 20;
    const pts = Array.from({ length: n }, (_, i) => 0.4 + rand() * 0.5 + Math.sin(i / 3) * 0.1);
    const max = Math.max(...pts);
    const x = (i: number) => (i / (n - 1)) * width;
    const y = (v: number) => height - (v / max) * (height - 3) - 1.5;
    let d = "";
    pts.forEach((v, i) => (d += (i ? "L" : "M") + x(i).toFixed(1) + "," + y(v).toFixed(1) + " "));
    const last = { x: x(n - 1), y: y(pts[n - 1]) };
    return { d, last };
  }, [seed, width, height]);

  return (
    <svg width={width} height={height} role="img" aria-label="Recent usage" className="overflow-visible">
      <path d={path.d} fill="none" stroke="var(--color-brand-soft)" strokeWidth={1.5} />
      <circle cx={path.last.x} cy={path.last.y} r={2.5} fill="var(--color-brand)" />
    </svg>
  );
}

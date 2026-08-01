"use client";

import { useState } from "react";
import { cn } from "@/lib/cn";
import {
  LAYER_LABELS,
  LAYER_ORDINAL,
  formatLatency,
  formatScore,
} from "@/lib/format";
import type { CascadeLayer, Direction, LayerResult, Verdict } from "@/types/echelon";

const INGRESS_LAYERS: CascadeLayer[] = ["heuristics", "ml_classifier", "llm_judge"];
const EGRESS_LAYERS: CascadeLayer[] = ["pii", "response_policy", "response_classifier", "response_judge"];

const VERDICT_COLOR: Record<Verdict, string> = {
  pass: "var(--color-pass)",
  flag: "var(--color-flag)",
  block: "var(--color-block)",
};

/**
 * The signature component: a prompt's 3-fold cascade rendered as an engraved
 * assay certificate. Each stage is a stamped segment (score vs. threshold);
 * the rail connecting them goes solid up to a block, then dashed — the visible
 * evidence that the cascade short-circuited to protect the latency budget.
 */
export function AssayStrip({
  layers,
  finalVerdict,
  blockedAtLayer,
  riskScore,
  direction = "ingress",
  variant = "full",
}: {
  layers: LayerResult[];
  finalVerdict: Verdict;
  blockedAtLayer?: CascadeLayer;
  riskScore: number;
  direction?: Direction;
  variant?: "full" | "compact";
}) {
  const [hover, setHover] = useState<CascadeLayer | null>(null);
  const byLayer = new Map(layers.map((l) => [l.layer, l]));
  const ALL_LAYERS = direction === "egress" ? EGRESS_LAYERS : INGRESS_LAYERS;
  const blockedIndex = blockedAtLayer ? ALL_LAYERS.indexOf(blockedAtLayer) : Infinity;
  const lastIndex = ALL_LAYERS.length - 1;

  if (variant === "compact") {
    return (
      <span className="inline-flex items-center gap-1.5" aria-label="Cascade result">
        {ALL_LAYERS.map((layer, i) => {
          const r = byLayer.get(layer);
          const reached = i <= blockedIndex && !!r;
          const color = r ? VERDICT_COLOR[r.verdict] : "var(--color-faint)";
          return (
            <span key={layer} className="flex items-center gap-1.5">
              {i > 0 ? (
                <span
                  className="h-px w-4"
                  style={{
                    background: i <= blockedIndex ? "var(--color-line-strong)" : "var(--color-line)",
                    borderTop: i > blockedIndex ? "1px dashed var(--color-line-strong)" : undefined,
                  }}
                  aria-hidden
                />
              ) : null}
              <span
                className="grid h-5 w-5 place-items-center rounded-full font-[family-name:var(--font-mono)] text-[9px]"
                style={{
                  border: `1.5px solid ${reached ? color : "var(--color-line-strong)"}`,
                  color: reached ? color : "var(--color-faint)",
                  background: r?.verdict === "block" ? "var(--color-block-wash)" : "transparent",
                }}
                title={`${LAYER_LABELS[layer]}${r ? ` · ${formatScore(r.score)}` : " · skipped"}`}
              >
                {r?.verdict === "block" ? "✕" : reached ? formatScore(r!.score).slice(1) : "–"}
              </span>
            </span>
          );
        })}
      </span>
    );
  }

  return (
    <figure
      className="relative overflow-hidden rounded-[var(--radius)] border border-[var(--color-line-strong)] bg-[var(--color-surface)]"
      aria-label="Cascade assay certificate"
    >
      {/* Engraved double top rule */}
      <div className="h-px bg-[var(--color-line-strong)]" />
      <div className="mt-[2px] h-px bg-[var(--color-line)]" />

      <figcaption className="flex items-center justify-between px-4 pt-3">
        <span className="eyebrow">Cascade Assay · {direction === "egress" ? "Egress" : "Ingress"}</span>
        <span className="font-[family-name:var(--font-mono)] text-[11px] text-[var(--color-muted)]">
          aggregate risk{" "}
          <span style={{ color: VERDICT_COLOR[finalVerdict] }}>{formatScore(riskScore)}</span>
        </span>
      </figcaption>

      {/* The rail + stamped segments */}
      <div
        className="grid gap-0 px-4 py-5"
        style={{ gridTemplateColumns: `repeat(${ALL_LAYERS.length}, minmax(0, 1fr))` }}
      >
        {ALL_LAYERS.map((layer, i) => {
          const r = byLayer.get(layer);
          const reached = i <= blockedIndex && !!r;
          const isBlock = r?.verdict === "block";
          const color = r ? VERDICT_COLOR[r.verdict] : "var(--color-faint)";
          const active = hover === layer;

          return (
            <div
              key={layer}
              className="relative flex flex-col items-center"
              onMouseEnter={() => setHover(layer)}
              onMouseLeave={() => setHover(null)}
            >
              {/* Rail segment to the left */}
              {i > 0 ? (
                <span
                  className="absolute left-0 top-3 h-0 w-1/2 -translate-x-1/2"
                  style={{
                    borderTop:
                      i <= blockedIndex
                        ? "2px solid var(--color-line-strong)"
                        : "2px dashed var(--color-line-strong)",
                    opacity: i <= blockedIndex ? 1 : 0.5,
                  }}
                  aria-hidden
                />
              ) : null}
              {/* Rail segment to the right */}
              {i < lastIndex ? (
                <span
                  className="absolute right-0 top-3 h-0 w-1/2 translate-x-1/2"
                  style={{
                    borderTop:
                      i < blockedIndex
                        ? "2px solid var(--color-line-strong)"
                        : "2px dashed var(--color-line-strong)",
                    opacity: i < blockedIndex ? 1 : 0.5,
                  }}
                  aria-hidden
                />
              ) : null}

              {/* Node stamp */}
              <span
                className={cn(
                  "relative z-10 grid h-6 w-6 place-items-center rounded-full font-[family-name:var(--font-mono)] text-[11px] transition-transform",
                  active && "scale-110",
                )}
                style={{
                  border: `1.5px solid ${reached ? color : "var(--color-line-strong)"}`,
                  background: isBlock ? "var(--color-block)" : "var(--color-surface)",
                  color: isBlock ? "#fff" : reached ? color : "var(--color-faint)",
                }}
              >
                {isBlock ? "✕" : reached ? "●" : "○"}
              </span>

              {/* Label */}
              <div className="mt-2 text-center">
                <div className="font-[family-name:var(--font-mono)] text-[10px] text-[var(--color-brand)]">
                  {LAYER_ORDINAL[layer]}
                </div>
                <div className="mt-0.5 text-xs font-medium leading-tight">
                  {LAYER_LABELS[layer]}
                </div>
              </div>

              {/* Score */}
              <div
                className="mt-2 font-[family-name:var(--font-display)] text-2xl tabular-nums"
                style={{ color: reached ? color : "var(--color-faint)" }}
              >
                {r ? formatScore(r.score) : "—"}
              </div>

              {/* Threshold micro-track */}
              {r ? (
                <div className="mt-1.5 w-16">
                  <div className="relative h-1.5 overflow-hidden rounded-full bg-[var(--color-surface-sunken)]">
                    <div
                      className="h-full rounded-full"
                      style={{ width: `${r.score * 100}%`, background: color }}
                    />
                    <div
                      className="absolute top-[-1px] h-[9px] w-px bg-[var(--color-ink)]"
                      style={{ left: `${r.threshold * 100}%` }}
                      aria-hidden
                    />
                  </div>
                  <div className="mt-1 text-center font-[family-name:var(--font-mono)] text-[9px] text-[var(--color-faint)]">
                    thresh {formatScore(r.threshold)}
                  </div>
                </div>
              ) : (
                <div className="mt-1.5 font-[family-name:var(--font-mono)] text-[10px] text-[var(--color-faint)]">
                  not reached
                </div>
              )}

              {/* Hover reveal: model + latency */}
              <div
                className="mt-2 h-4 font-[family-name:var(--font-mono)] text-[9px] text-[var(--color-muted)] transition-opacity"
                style={{ opacity: active && r ? 1 : 0 }}
                aria-hidden={!active}
              >
                {r ? `${r.model ?? ""} · ${formatLatency(r.latencyUs)}` : ""}
              </div>
            </div>
          );
        })}
      </div>

      {/* Wax-seal stamp for the short-circuit verdict */}
      {blockedAtLayer ? (
        <div
          className="pointer-events-none absolute right-4 top-1/2 -translate-y-1/3 select-none"
          style={{ transform: "translateY(-30%) rotate(-6deg)" }}
          aria-hidden
        >
          <div
            className="rounded-[3px] px-2.5 py-1 font-[family-name:var(--font-mono)] text-[10px] font-bold uppercase tracking-[0.18em]"
            style={{
              color: "var(--color-block)",
              border: "1.5px solid var(--color-block)",
              boxShadow: "inset 0 0 0 2.5px var(--color-surface), inset 0 0 0 3.5px var(--color-block)",
              opacity: 0.9,
            }}
          >
            Blocked · {LAYER_ORDINAL[blockedAtLayer]}
          </div>
        </div>
      ) : null}

      {/* Engraved bottom rule + provenance line */}
      <div
        className="border-t border-[var(--color-line)] px-4 py-2 font-[family-name:var(--font-mono)] text-[10px] text-[var(--color-muted)]"
      >
        {blockedAtLayer
          ? `Short-circuited at ${LAYER_LABELS[blockedAtLayer]} — deeper stages never evaluated.`
          : finalVerdict === "flag"
            ? direction === "egress"
              ? "Flagged for review — delivered to the user with a warning."
              : "Flagged for review — passed to the target LLM with a warning."
            : direction === "egress"
              ? `Cleared all ${ALL_LAYERS.length} stages — delivered to the user.`
              : `Cleared all ${ALL_LAYERS.length} stages — delivered to the target LLM.`}
      </div>
    </figure>
  );
}

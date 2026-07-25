"use client";

import { useMemo } from "react";
import { LAYER_LABELS, LAYER_ORDINAL, formatScore } from "@/lib/format";
import { Toggle } from "@/components/ui/toggle";
import type { LayerConfig } from "@/types/echelon";

const BINS = 28;

/** Histogram of this layer's recent scores, with the threshold split. */
function ScoreDistribution({ scores, threshold }: { scores: number[]; threshold: number }) {
  const bins = useMemo(() => {
    const b = new Array(BINS).fill(0);
    for (const s of scores) {
      const idx = Math.min(BINS - 1, Math.floor(s * BINS));
      b[idx]++;
    }
    const max = Math.max(1, ...b);
    return b.map((v) => v / max);
  }, [scores]);

  return (
    <div className="relative flex h-12 items-end gap-[2px]" aria-hidden>
      {bins.map((h, i) => {
        const center = (i + 0.5) / BINS;
        const isBlockSide = center >= threshold;
        return (
          <div
            key={i}
            className="flex-1 rounded-t-[1px]"
            style={{
              height: `${Math.max(h * 100, 3)}%`,
              background: isBlockSide ? "var(--color-block)" : "var(--color-pass)",
              opacity: isBlockSide ? 0.55 : 0.35,
            }}
          />
        );
      })}
      {/* Threshold marker */}
      <div
        className="absolute top-0 bottom-0 w-px bg-[var(--color-ink)]"
        style={{ left: `${threshold * 100}%` }}
      />
    </div>
  );
}

export function LayerControl({
  config,
  defaultThreshold,
  scores,
  onChange,
}: {
  config: LayerConfig;
  defaultThreshold: number;
  scores: number[];
  onChange: (next: LayerConfig) => void;
}) {
  const modified = config.threshold !== defaultThreshold;
  const blockRate =
    scores.length > 0
      ? scores.filter((s) => s >= config.threshold).length / scores.length
      : 0;

  return (
    <div
      className="rounded-[var(--radius-lg)] border border-[var(--color-line)] bg-[var(--color-surface)] p-5"
      style={config.enabled ? undefined : { opacity: 0.6 }}
    >
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2">
            <span className="font-[family-name:var(--font-mono)] text-xs text-[var(--color-brand)]">
              {LAYER_ORDINAL[config.layer]}
            </span>
            <span className="text-sm font-medium">{LAYER_LABELS[config.layer]}</span>
          </div>
          {config.model ? (
            <div className="mt-1 font-[family-name:var(--font-mono)] text-[11px] text-[var(--color-faint)]">
              {config.model}
            </div>
          ) : null}
        </div>
        <div className="flex items-center gap-2">
          <span className="eyebrow">{config.enabled ? "On" : "Off"}</span>
          <Toggle
            checked={config.enabled}
            onChange={(enabled) => onChange({ ...config, enabled })}
            label={`Enable ${LAYER_LABELS[config.layer]}`}
          />
        </div>
      </div>

      <div className="mt-4">
        <ScoreDistribution scores={scores} threshold={config.threshold} />
        <div className="mt-1 flex justify-between font-[family-name:var(--font-mono)] text-[9px] text-[var(--color-faint)]">
          <span>0.00 pass</span>
          <span>block 1.00</span>
        </div>
      </div>

      <div className="mt-4 flex items-center gap-4">
        <input
          type="range"
          min={0}
          max={1}
          step={0.01}
          value={config.threshold}
          disabled={!config.enabled}
          onChange={(e) => onChange({ ...config, threshold: Number(e.target.value) })}
          aria-label={`${LAYER_LABELS[config.layer]} routing threshold`}
          className="h-1.5 flex-1 cursor-pointer accent-[var(--color-brand)]"
        />
        <div className="w-24 text-right">
          <div className="font-[family-name:var(--font-mono)] text-lg tabular-nums">
            {formatScore(config.threshold)}
          </div>
          <div className="font-[family-name:var(--font-mono)] text-[10px] text-[var(--color-muted)]">
            {modified ? (
              <span className="text-[var(--color-flag)]">was {formatScore(defaultThreshold)}</span>
            ) : (
              "default"
            )}
          </div>
        </div>
      </div>

      <div className="mt-3 border-t border-[var(--color-line)] pt-3 font-[family-name:var(--font-mono)] text-[11px] text-[var(--color-muted)]">
        At this threshold, ~{(blockRate * 100).toFixed(0)}% of recent{" "}
        {LAYER_LABELS[config.layer]} scores would block.
      </div>
    </div>
  );
}

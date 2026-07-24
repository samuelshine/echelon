"use client";

import { useState } from "react";
import { cn } from "@/lib/cn";
import { CATEGORY_LABELS } from "@/lib/format";
import type { WhatIfImpact } from "@/lib/whatif";

function Stat({
  label,
  value,
  tone,
}: {
  label: string;
  value: number;
  tone?: "block" | "pass";
}) {
  const color =
    tone === "block"
      ? "var(--color-block)"
      : tone === "pass"
        ? "var(--color-pass)"
        : "var(--color-ink)";
  return (
    <div>
      <div className="tnum font-[family-name:var(--font-mono)] text-xl" style={{ color }}>
        {value > 0 && tone ? (tone === "pass" ? "+" : "−") : ""}
        {Math.abs(value).toLocaleString()}
      </div>
      <div className="eyebrow mt-0.5">{label}</div>
    </div>
  );
}

export function WhatIfBar({
  impact,
  dirty,
  onSave,
  onReset,
}: {
  impact: WhatIfImpact;
  dirty: boolean;
  onSave: () => void;
  onReset: () => void;
}) {
  const [confirming, setConfirming] = useState(false);
  const weakens = impact.regressions > 0;

  const handleSave = () => {
    if (weakens && !confirming) {
      setConfirming(true);
      return;
    }
    onSave();
    setConfirming(false);
  };

  return (
    <div className="sticky bottom-6 rounded-[var(--radius-lg)] border border-[var(--color-line-strong)] bg-[var(--color-surface)] p-5 shadow-lg">
      <div className="flex flex-wrap items-center justify-between gap-6">
        <div>
          <div className="eyebrow">What-if · against recent traffic</div>
          <div className="mt-3 flex items-center gap-8">
            <Stat label="would now pass" value={impact.newlyAllowed} tone="pass" />
            <Stat label="newly blocked" value={impact.newlyBlocked} tone="block" />
            <Stat label="known attacks freed" value={impact.regressions} tone={impact.regressions ? "pass" : undefined} />
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={() => {
              onReset();
              setConfirming(false);
            }}
            disabled={!dirty}
            className="rounded-[var(--radius)] border border-[var(--color-line-strong)] px-4 py-2 text-sm text-[var(--color-ink-soft)] disabled:opacity-40 enabled:hover:bg-[var(--color-surface-sunken)]"
          >
            Reset
          </button>
          <button
            type="button"
            onClick={handleSave}
            disabled={!dirty}
            className={cn(
              "rounded-[var(--radius)] px-4 py-2 text-sm font-medium text-white disabled:opacity-40",
              weakens
                ? "bg-[var(--color-block)] enabled:hover:brightness-110"
                : "bg-[var(--color-brand)] enabled:hover:brightness-110",
            )}
          >
            {confirming ? "I understand, save anyway" : "Save configuration"}
          </button>
        </div>
      </div>

      {/* Guardrail: warn + require confirmation when protection weakens */}
      {weakens && dirty ? (
        <div className="mt-4 flex gap-3 rounded-[var(--radius)] border border-[var(--color-block)] bg-[var(--color-block-wash)] p-4">
          <span aria-hidden className="text-[var(--color-block)]">
            ⚠
          </span>
          <div className="text-xs leading-relaxed text-[var(--color-ink-soft)]">
            <span className="font-medium text-[var(--color-block)]">
              This change weakens protection.
            </span>{" "}
            {impact.regressions.toLocaleString()} previously-blocked known attack
            {impact.regressions === 1 ? "" : "s"} would now reach the target LLM
            {impact.regressionSamples.length > 0 ? (
              <>
                {" "}
                — including{" "}
                {impact.regressionSamples
                  .map((e) => CATEGORY_LABELS[e.category].toLowerCase())
                  .join(", ")}
              </>
            ) : null}
            . {confirming ? "Confirm you want to save anyway." : "Review before saving."}
          </div>
        </div>
      ) : null}
    </div>
  );
}

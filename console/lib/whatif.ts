import type { EchelonConfig, LayerConfig, PromptEvent, Verdict } from "@/types/echelon";

/**
 * Re-run a prompt's recorded layer scores against a candidate ingress config.
 * Uses only the scores actually captured for that event (the cascade may have
 * short-circuited), which is the honest basis for a what-if: raising a threshold
 * above the score that caught an attack lets it through.
 */
export function recomputeVerdict(
  event: PromptEvent,
  ingress: LayerConfig[],
): { verdict: Verdict; blockedAt?: LayerConfig["layer"] } {
  const cfg = new Map(ingress.map((c) => [c.layer, c]));
  let verdict: Verdict = "pass";

  for (const lr of event.layers) {
    const c = cfg.get(lr.layer);
    if (!c || !c.enabled) continue;
    if (lr.score >= c.threshold) return { verdict: "block", blockedAt: lr.layer };
    if (lr.score >= c.threshold - 0.15) verdict = "flag";
  }
  return { verdict };
}

export interface WhatIfImpact {
  total: number;
  /** Prompts that were blocked under `saved` but would pass under `pending`. */
  newlyAllowed: number;
  /** Prompts newly caught by the pending config. */
  newlyBlocked: number;
  /** Of the newly-allowed, how many are known attacks (category ≠ clean). */
  regressions: number;
  /** A few example regressions for the warning copy. */
  regressionSamples: PromptEvent[];
}

export function computeImpact(
  events: PromptEvent[],
  saved: EchelonConfig,
  pending: EchelonConfig,
): WhatIfImpact {
  let newlyAllowed = 0;
  let newlyBlocked = 0;
  let regressions = 0;
  const regressionSamples: PromptEvent[] = [];

  for (const e of events) {
    const wasBlocked = recomputeVerdict(e, saved.ingress).verdict === "block";
    const willBlock = recomputeVerdict(e, pending.ingress).verdict === "block";

    if (wasBlocked && !willBlock) {
      newlyAllowed++;
      if (e.category !== "clean") {
        regressions++;
        if (regressionSamples.length < 3) regressionSamples.push(e);
      }
    }
    if (!wasBlocked && willBlock) newlyBlocked++;
  }

  return {
    total: events.length,
    newlyAllowed,
    newlyBlocked,
    regressions,
    regressionSamples,
  };
}

/** Structural equality good enough to detect "are there unsaved edits?". */
export function configsEqual(a: EchelonConfig, b: EchelonConfig): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

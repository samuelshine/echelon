import type { PromptEvent, Verdict } from "@/types/echelon";

/** Verdict presentation — color is paired with an icon + label, never alone. */
export const VERDICT_META: Record<
  Verdict,
  { label: string; glyph: string; color: string; wash: string }
> = {
  pass: { label: "Pass", glyph: "✓", color: "var(--color-pass)", wash: "var(--color-pass-wash)" },
  flag: { label: "Flag", glyph: "⚠", color: "var(--color-flag)", wash: "var(--color-flag-wash)" },
  block: { label: "Block", glyph: "✕", color: "var(--color-block)", wash: "var(--color-block-wash)" },
};

/** Color a risk score by the band it falls in. */
export function riskColor(score: number): string {
  if (score >= 0.6) return "var(--color-block)";
  if (score >= 0.45) return "var(--color-flag)";
  return "var(--color-muted)";
}

export interface LogFilterState {
  query: string;
  verdict: Verdict | "all";
  direction: "ingress" | "egress" | "all";
  layer: "heuristics" | "ml_classifier" | "llm_judge" | "all";
  minRisk: number;
  apiKeyId: string | "all";
}

export const DEFAULT_FILTERS: LogFilterState = {
  query: "",
  verdict: "all",
  direction: "all",
  layer: "all",
  minRisk: 0,
  apiKeyId: "all",
};

export function applyFilters(
  events: PromptEvent[],
  f: LogFilterState,
): PromptEvent[] {
  const q = f.query.trim().toLowerCase();
  return events.filter((e) => {
    if (f.verdict !== "all" && e.finalVerdict !== f.verdict) return false;
    if (f.direction !== "all" && e.direction !== f.direction) return false;
    if (f.layer !== "all" && e.blockedAtLayer !== f.layer) return false;
    if (e.riskScore < f.minRisk) return false;
    if (f.apiKeyId !== "all" && e.apiKeyId !== f.apiKeyId) return false;
    if (q && !e.excerpt.toLowerCase().includes(q) && !e.id.toLowerCase().includes(q))
      return false;
    return true;
  });
}

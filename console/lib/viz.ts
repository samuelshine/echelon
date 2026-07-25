import type { ThreatCategory } from "@/types/echelon";
import { CATEGORY_LABELS } from "@/lib/format";

/** Fixed categorical order — this ordering is the CVD-safety mechanism. */
export const ATTACK_ORDER: Exclude<ThreatCategory, "clean">[] = [
  "prompt_injection",
  "jailbreak",
  "pii_leak",
  "toxicity",
  "policy_violation",
  "data_exfiltration",
];

/** Each category's stable color, sourced from the themed CSS var (light/dark aware). */
export function categoryColor(c: string): string {
  return `var(--color-viz-${c})`;
}

export const categoryLabel = (c: string) => CATEGORY_LABELS[c] ?? c;

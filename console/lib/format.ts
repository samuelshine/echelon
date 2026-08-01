/**
 * Formatting helpers. Latency is the product, so we format it with care:
 * sub-millisecond overhead reads in microseconds, not "0.0 ms".
 */

export function formatLatency(us: number): string {
  if (us < 1000) return `${Math.round(us)} µs`;
  return `${(us / 1000).toFixed(us < 10_000 ? 2 : 1)} ms`;
}

export function formatCompact(n: number): string {
  return new Intl.NumberFormat("en-US", {
    notation: "compact",
    maximumFractionDigits: 1,
  }).format(n);
}

export function formatInt(n: number): string {
  return new Intl.NumberFormat("en-US").format(n);
}

export function formatPct(fraction: number, digits = 1): string {
  return `${(fraction * 100).toFixed(digits)}%`;
}

export function formatScore(score: number): string {
  return score.toFixed(2);
}

export function formatCredits(n: number): string {
  return new Intl.NumberFormat("en-US", {
    notation: "compact",
    maximumFractionDigits: 1,
  }).format(n);
}

export function formatRelativeTime(iso: string, now = Date.now()): string {
  const diff = now - new Date(iso).getTime();
  const s = Math.round(diff / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.round(h / 24);
  return `${d}d ago`;
}

export const LAYER_LABELS: Record<string, string> = {
  heuristics: "Heuristics",
  ml_classifier: "ML Classifier",
  llm_judge: "LLM Judge",
  pii: "PII Scan",
  response_policy: "Canary Check",
  response_classifier: "Response Classifier",
  response_judge: "Response Judge",
};

export const LAYER_ORDINAL: Record<string, string> = {
  heuristics: "L1",
  ml_classifier: "L2",
  llm_judge: "L3",
  pii: "R1",
  response_policy: "R2",
  response_classifier: "R3",
  response_judge: "R4",
};

export const CATEGORY_LABELS: Record<string, string> = {
  prompt_injection: "Prompt Injection",
  jailbreak: "Jailbreak",
  pii_leak: "PII Leak",
  toxicity: "Toxicity",
  policy_violation: "Policy Violation",
  data_exfiltration: "Data Exfiltration",
  malicious_code: "Malicious Code",
  clean: "Clean",
};

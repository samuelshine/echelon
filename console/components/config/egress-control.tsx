"use client";

import { Toggle } from "@/components/ui/toggle";
import type { EgressConfig } from "@/types/echelon";

const SCANNERS: {
  key: keyof EgressConfig;
  label: string;
  desc: string;
}[] = [
  {
    key: "piiMasking",
    label: "PII masking",
    desc: "Redact emails, SSNs, and card numbers from responses before they leave.",
  },
  {
    key: "toxicityScan",
    label: "Toxicity scan",
    desc: "Block responses that cross the toxicity threshold.",
  },
  {
    key: "maliciousCodeScan",
    label: "Malicious code scan",
    desc: "Classifier + LLM judge adjudicate operational malware/exploit code in responses.",
  },
  {
    key: "policyEnforcement",
    label: "Policy enforcement",
    desc: "Enforce your custom content-policy ruleset on every response.",
  },
];

export function EgressControl({
  config,
  onChange,
}: {
  config: EgressConfig;
  onChange: (next: EgressConfig) => void;
}) {
  return (
    <div className="divide-y divide-[var(--color-line)] rounded-[var(--radius-lg)] border border-[var(--color-line)] bg-[var(--color-surface)]">
      {SCANNERS.map((s) => (
        <div key={s.key} className="flex items-center justify-between gap-6 p-5">
          <div>
            <div className="text-sm font-medium">{s.label}</div>
            <div className="mt-0.5 text-xs text-[var(--color-muted)]">{s.desc}</div>
          </div>
          <Toggle
            checked={config[s.key]}
            onChange={(v) => onChange({ ...config, [s.key]: v })}
            label={s.label}
          />
        </div>
      ))}
    </div>
  );
}

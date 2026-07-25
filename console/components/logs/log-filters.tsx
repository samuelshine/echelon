"use client";

import { cn } from "@/lib/cn";
import type { LogFilterState } from "@/lib/logs";
import type { ApiKey } from "@/types/echelon";

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="flex flex-col gap-1">
      <span className="eyebrow">{label}</span>
      {children}
    </label>
  );
}

const selectCls =
  "h-9 rounded-[var(--radius)] border border-[var(--color-line-strong)] bg-[var(--color-surface)] px-2.5 text-sm text-[var(--color-ink)] focus-visible:outline-2 focus-visible:outline-[var(--color-brand)]";

const RISK_PRESETS = [
  { label: "Any", value: 0 },
  { label: "≥ 0.45", value: 0.45 },
  { label: "≥ 0.60", value: 0.6 },
  { label: "≥ 0.80", value: 0.8 },
];

export function LogFilters({
  filters,
  onChange,
  keys,
  resultCount,
  totalCount,
}: {
  filters: LogFilterState;
  onChange: (next: LogFilterState) => void;
  keys: ApiKey[];
  resultCount: number;
  totalCount: number;
}) {
  const set = <K extends keyof LogFilterState>(k: K, v: LogFilterState[K]) =>
    onChange({ ...filters, [k]: v });

  return (
    <div className="flex flex-wrap items-end gap-3 rounded-[var(--radius-lg)] border border-[var(--color-line)] bg-[var(--color-surface)] p-4">
      <Field label="Search">
        <input
          value={filters.query}
          onChange={(e) => set("query", e.target.value)}
          placeholder="prompt text or id…"
          className={cn(selectCls, "w-56")}
        />
      </Field>

      <Field label="Verdict">
        <select
          className={selectCls}
          value={filters.verdict}
          onChange={(e) => set("verdict", e.target.value as LogFilterState["verdict"])}
        >
          <option value="all">All</option>
          <option value="block">Block</option>
          <option value="flag">Flag</option>
          <option value="pass">Pass</option>
        </select>
      </Field>

      <Field label="Direction">
        <select
          className={selectCls}
          value={filters.direction}
          onChange={(e) => set("direction", e.target.value as LogFilterState["direction"])}
        >
          <option value="all">All</option>
          <option value="ingress">Ingress</option>
          <option value="egress">Egress</option>
        </select>
      </Field>

      <Field label="Blocked at">
        <select
          className={selectCls}
          value={filters.layer}
          onChange={(e) => set("layer", e.target.value as LogFilterState["layer"])}
        >
          <option value="all">Any layer</option>
          <option value="heuristics">L1 · Heuristics</option>
          <option value="ml_classifier">L2 · ML Classifier</option>
          <option value="llm_judge">L3 · LLM Judge</option>
        </select>
      </Field>

      <Field label="API key">
        <select
          className={selectCls}
          value={filters.apiKeyId}
          onChange={(e) => set("apiKeyId", e.target.value)}
        >
          <option value="all">All keys</option>
          {keys.map((k) => (
            <option key={k.id} value={k.id}>
              {k.label}
            </option>
          ))}
        </select>
      </Field>

      <Field label="Min risk">
        <div className="flex overflow-hidden rounded-[var(--radius)] border border-[var(--color-line-strong)]">
          {RISK_PRESETS.map((p, i) => (
            <button
              key={p.value}
              type="button"
              onClick={() => set("minRisk", p.value)}
              className={cn(
                "h-9 px-2.5 font-[family-name:var(--font-mono)] text-xs",
                i > 0 && "border-l border-[var(--color-line-strong)]",
                filters.minRisk === p.value
                  ? "bg-[var(--color-brand)] text-white"
                  : "bg-[var(--color-surface)] text-[var(--color-muted)] hover:bg-[var(--color-surface-sunken)]",
              )}
            >
              {p.label}
            </button>
          ))}
        </div>
      </Field>

      <div className="ml-auto self-end pb-1 font-[family-name:var(--font-mono)] text-xs text-[var(--color-muted)]">
        <span className="tnum text-[var(--color-ink)]">{resultCount.toLocaleString()}</span>{" "}
        / {totalCount.toLocaleString()} events
      </div>
    </div>
  );
}

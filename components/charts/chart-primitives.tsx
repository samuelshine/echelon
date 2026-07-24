"use client";

import { categoryColor, categoryLabel } from "@/lib/viz";

/** Format an ISO ts to an hour tick like "14:00". */
export function hourTick(iso: string): string {
  return new Date(iso).toLocaleTimeString("en-US", {
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
}

interface TooltipRow {
  key: string;
  value: number;
  color?: string;
}

/** Shared tooltip — ink text, a color swatch carries identity (never color-alone). */
export function VizTooltip({
  label,
  rows,
  total,
  valueFormat = (v) => v.toLocaleString(),
}: {
  label: string;
  rows: TooltipRow[];
  total?: number;
  valueFormat?: (v: number) => string;
}) {
  return (
    <div className="min-w-[180px] rounded-[var(--radius)] border border-[var(--color-line-strong)] bg-[var(--color-surface)] p-3 shadow-lg">
      <div className="eyebrow mb-2">{label}</div>
      <ul className="space-y-1">
        {rows.map((r) => (
          <li key={r.key} className="flex items-center justify-between gap-4 text-xs">
            <span className="flex items-center gap-2 text-[var(--color-ink-soft)]">
              {r.color ? (
                <span
                  className="inline-block h-2.5 w-2.5 rounded-[2px]"
                  style={{ background: r.color }}
                  aria-hidden
                />
              ) : null}
              {r.key}
            </span>
            <span className="tnum font-[family-name:var(--font-mono)] text-[var(--color-ink)]">
              {valueFormat(r.value)}
            </span>
          </li>
        ))}
      </ul>
      {total !== undefined ? (
        <div className="mt-2 flex items-center justify-between border-t border-[var(--color-line)] pt-2 text-xs">
          <span className="text-[var(--color-muted)]">Total</span>
          <span className="tnum font-[family-name:var(--font-mono)]">
            {valueFormat(total)}
          </span>
        </div>
      ) : null}
    </div>
  );
}

/** Always-on legend so identity is never carried by color alone. */
export function CategoryLegend({ categories }: { categories: string[] }) {
  return (
    <ul className="flex flex-wrap gap-x-4 gap-y-1.5">
      {categories.map((c) => (
        <li key={c} className="flex items-center gap-1.5 text-xs text-[var(--color-muted)]">
          <span
            className="inline-block h-2.5 w-2.5 rounded-[2px]"
            style={{ background: categoryColor(c) }}
            aria-hidden
          />
          {categoryLabel(c)}
        </li>
      ))}
    </ul>
  );
}

export const AXIS_TICK = {
  fontSize: 11,
  fill: "var(--color-muted)",
  fontFamily: "var(--font-mono)",
};

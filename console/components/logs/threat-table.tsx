"use client";

import { useRef, useMemo, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { cn } from "@/lib/cn";
import {
  CATEGORY_LABELS,
  formatLatency,
  formatRelativeTime,
  formatScore,
} from "@/lib/format";
import { riskColor } from "@/lib/logs";
import { VerdictChip } from "./verdict-chip";
import { AssayStrip } from "@/components/cascade/assay-strip";
import type { PromptEvent } from "@/types/echelon";

type SortKey = "ts" | "riskScore" | "latencyOverheadUs";

const GRID =
  "grid grid-cols-[104px_76px_76px_120px_92px_64px_136px_88px_minmax(140px,1fr)] items-center gap-3 px-4";

function SortHeader({
  label,
  active,
  dir,
  onClick,
  className,
}: {
  label: string;
  active: boolean;
  dir: "asc" | "desc";
  onClick: () => void;
  className?: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "eyebrow flex items-center gap-1 text-left hover:text-[var(--color-ink)]",
        active && "text-[var(--color-ink)]",
        className,
      )}
    >
      {label}
      <span aria-hidden className="text-[9px]">
        {active ? (dir === "desc" ? "▼" : "▲") : ""}
      </span>
    </button>
  );
}

export function ThreatTable({
  events,
  selectedId,
  onSelect,
  freshIds,
}: {
  events: PromptEvent[];
  selectedId?: string;
  onSelect: (e: PromptEvent) => void;
  freshIds?: Set<string>;
}) {
  const [sort, setSort] = useState<{ key: SortKey; dir: "asc" | "desc" }>({
    key: "ts",
    dir: "desc",
  });
  const parentRef = useRef<HTMLDivElement>(null);

  const rows = useMemo(() => {
    const sorted = [...events].sort((a, b) => {
      const av = sort.key === "ts" ? new Date(a.ts).getTime() : a[sort.key];
      const bv = sort.key === "ts" ? new Date(b.ts).getTime() : b[sort.key];
      return sort.dir === "desc" ? bv - av : av - bv;
    });
    return sorted;
  }, [events, sort]);

  const virt = useVirtualizer({
    count: rows.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 48,
    overscan: 12,
  });

  const toggleSort = (key: SortKey) =>
    setSort((s) =>
      s.key === key ? { key, dir: s.dir === "desc" ? "asc" : "desc" } : { key, dir: "desc" },
    );

  return (
    <div className="overflow-hidden rounded-[var(--radius-lg)] border border-[var(--color-line)] bg-[var(--color-surface)]">
      {/* Header */}
      <div
        className={cn(
          GRID,
          "h-10 border-b border-[var(--color-line)] bg-[var(--color-surface-sunken)]",
        )}
      >
        <SortHeader label="Time" active={sort.key === "ts"} dir={sort.dir} onClick={() => toggleSort("ts")} />
        <span className="eyebrow">Dir</span>
        <span className="eyebrow">Provider</span>
        <span className="eyebrow">Category</span>
        <span className="eyebrow">Verdict</span>
        <SortHeader
          label="Risk"
          active={sort.key === "riskScore"}
          dir={sort.dir}
          onClick={() => toggleSort("riskScore")}
        />
        <span className="eyebrow">Cascade</span>
        <SortHeader
          label="Overhead"
          active={sort.key === "latencyOverheadUs"}
          dir={sort.dir}
          onClick={() => toggleSort("latencyOverheadUs")}
          className="justify-end"
        />
        <span className="eyebrow">Prompt</span>
      </div>

      {/* Virtualized body */}
      {rows.length === 0 ? (
        <div className="p-12 text-center text-sm text-[var(--color-muted)]">
          No events match these filters. Loosen a filter to see traffic.
        </div>
      ) : (
        <div ref={parentRef} className="h-[560px] overflow-y-auto">
          <div style={{ height: virt.getTotalSize(), position: "relative" }}>
            {virt.getVirtualItems().map((vi) => {
              const e = rows[vi.index];
              const selected = e.id === selectedId;
              const fresh = freshIds?.has(e.id);
              return (
                <button
                  type="button"
                  key={e.id}
                  onClick={() => onSelect(e)}
                  className={cn(
                    GRID,
                    "absolute left-0 top-0 h-12 w-full border-b border-[var(--color-line)] text-left transition-colors",
                    selected
                      ? "bg-[var(--color-brand-wash)]"
                      : fresh
                        ? "bg-[var(--color-pass-wash)]"
                        : "hover:bg-[var(--color-surface-sunken)]",
                  )}
                  style={{
                    transform: `translateY(${vi.start}px)`,
                    boxShadow: fresh ? "inset 3px 0 0 var(--color-pass)" : undefined,
                  }}
                >
                  <span className="font-[family-name:var(--font-mono)] text-xs text-[var(--color-muted)]">
                    {formatRelativeTime(e.ts)}
                  </span>
                  <span className="text-xs capitalize text-[var(--color-ink-soft)]">
                    {e.direction}
                  </span>
                  <span className="text-xs capitalize text-[var(--color-ink-soft)]">
                    {e.provider || "—"}
                  </span>
                  <span className="truncate text-xs text-[var(--color-ink-soft)]">
                    {CATEGORY_LABELS[e.category]}
                  </span>
                  <span>
                    <VerdictChip verdict={e.finalVerdict} />
                  </span>
                  <span
                    className="tnum font-[family-name:var(--font-mono)] text-xs"
                    style={{ color: riskColor(e.riskScore) }}
                  >
                    {formatScore(e.riskScore)}
                  </span>
                  <span onClick={(ev) => ev.stopPropagation()}>
                    <AssayStrip
                      variant="compact"
                      layers={e.layers}
                      finalVerdict={e.finalVerdict}
                      blockedAtLayer={e.blockedAtLayer}
                      riskScore={e.riskScore}
                      direction={e.direction}
                    />
                  </span>
                  <span className="tnum text-right font-[family-name:var(--font-mono)] text-xs text-[var(--color-muted)]">
                    {formatLatency(e.latencyOverheadUs)}
                  </span>
                  <span className="truncate text-xs text-[var(--color-faint)]">
                    {e.excerpt}
                  </span>
                </button>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

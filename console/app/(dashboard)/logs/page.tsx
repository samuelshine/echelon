"use client";

import { useMemo, useState } from "react";
import { PageHeader } from "@/components/page-header";
import { LogFilters } from "@/components/logs/log-filters";
import { ThreatTable } from "@/components/logs/threat-table";
import { DrillDown } from "@/components/logs/drill-down";
import { useEvents, useApiKeys } from "@/lib/hooks/useEchelon";
import { useLiveTail } from "@/lib/hooks/useLiveTail";
import { applyFilters, DEFAULT_FILTERS } from "@/lib/logs";
import { cn } from "@/lib/cn";
import type { PromptEvent } from "@/types/echelon";

export default function LogsPage() {
  const { data: events, isLoading } = useEvents(500);
  const { data: keys } = useApiKeys();
  const [filters, setFilters] = useState(DEFAULT_FILTERS);
  const [selected, setSelected] = useState<PromptEvent | null>(null);
  const [live, setLive] = useState(false);
  const { streamed, freshIds } = useLiveTail({ enabled: live });

  const merged = useMemo(
    () => [...streamed, ...(events ?? [])],
    [streamed, events],
  );

  const filtered = useMemo(
    () => applyFilters(merged, filters),
    [merged, filters],
  );

  return (
    <>
      <PageHeader eyebrow="Module 01 · Forensics" title="Threat Audit">
        <button
          type="button"
          onClick={() => setLive((v) => !v)}
          aria-pressed={live}
          className={cn(
            "flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-medium transition-colors",
            live
              ? "border-[var(--color-pass)] bg-[var(--color-pass-wash)] text-[var(--color-pass)]"
              : "border-[var(--color-line-strong)] text-[var(--color-muted)] hover:bg-[var(--color-surface-sunken)]",
          )}
        >
          <span
            className={cn(
              "h-2 w-2 rounded-full",
              live ? "animate-pulse bg-[var(--color-pass)]" : "bg-[var(--color-faint)]",
            )}
          />
          {live ? `Live · ${streamed.length} streamed` : "Live-tail off"}
        </button>
      </PageHeader>

      <div className="space-y-4 p-8">
        <LogFilters
          filters={filters}
          onChange={setFilters}
          keys={keys ?? []}
          resultCount={filtered.length}
          totalCount={merged.length}
        />

        {isLoading ? (
          <div className="h-[600px] animate-pulse rounded-[var(--radius-lg)] bg-[var(--color-surface-sunken)]" />
        ) : (
          <ThreatTable
            events={filtered}
            selectedId={selected?.id}
            onSelect={setSelected}
            freshIds={freshIds}
          />
        )}
      </div>

      <DrillDown event={selected} onClose={() => setSelected(null)} />
    </>
  );
}

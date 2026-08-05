"use client";

import { useMemo, useState } from "react";
import { PageHeader } from "@/components/page-header";
import { LogFilters } from "@/components/logs/log-filters";
import { ThreatTable } from "@/components/logs/threat-table";
import { DrillDown } from "@/components/logs/drill-down";
import { useEventsInfinite, useApiKeys } from "@/lib/hooks/useEchelon";
import { useLiveTail } from "@/lib/hooks/useLiveTail";
import { DEFAULT_FILTERS } from "@/lib/logs";
import { cn } from "@/lib/cn";
import type { PromptEvent } from "@/types/echelon";

export default function LogsPage() {
  const [filters, setFilters] = useState(DEFAULT_FILTERS);
  const {
    data,
    isLoading,
    hasNextPage,
    isFetchingNextPage,
    fetchNextPage,
  } = useEventsInfinite(filters);
  const { data: keys } = useApiKeys();
  const [selected, setSelected] = useState<PromptEvent | null>(null);
  const [live, setLive] = useState(false);
  const { streamed, freshIds } = useLiveTail({ enabled: live });

  // Filtering + pagination are now server-side: flatten whatever pages we've
  // loaded so far. Live-tail's streamed events are still prepended ahead of the
  // fetched list, exactly as before.
  const events = useMemo(
    () => (data?.pages ?? []).flatMap((p) => p.events),
    [data],
  );

  const merged = useMemo(
    () => [...streamed, ...events],
    [streamed, events],
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
          loadedCount={merged.length}
          hasMore={hasNextPage}
        />

        {isLoading ? (
          <div className="h-[600px] animate-pulse rounded-[var(--radius-lg)] bg-[var(--color-surface-sunken)]" />
        ) : (
          <>
            <ThreatTable
              events={merged}
              selectedId={selected?.id}
              onSelect={setSelected}
              freshIds={freshIds}
            />
            {hasNextPage && (
              <div className="flex justify-center">
                <button
                  type="button"
                  onClick={() => fetchNextPage()}
                  disabled={isFetchingNextPage}
                  className={cn(
                    "rounded-full border border-[var(--color-line-strong)] px-4 py-1.5 text-xs font-medium text-[var(--color-muted)] transition-colors hover:bg-[var(--color-surface-sunken)]",
                    isFetchingNextPage && "cursor-not-allowed opacity-60",
                  )}
                >
                  {isFetchingNextPage ? "Loading…" : "Load older events"}
                </button>
              </div>
            )}
          </>
        )}
      </div>

      <DrillDown event={selected} onClose={() => setSelected(null)} />
    </>
  );
}

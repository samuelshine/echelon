"use client";

import { useEffect, useRef } from "react";
import { useFocusTrap } from "@/lib/hooks/useFocusTrap";
import { LAYER_LABELS, formatLatency, formatScore, CATEGORY_LABELS } from "@/lib/format";
import { VerdictChip } from "./verdict-chip";
import { AssayStrip } from "@/components/cascade/assay-strip";
import { RawJson } from "./raw-json";
import type { PromptEvent } from "@/types/echelon";

function MetaField({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="eyebrow">{label}</div>
      <div className="mt-1 text-sm">{children}</div>
    </div>
  );
}

export function DrillDown({
  event,
  onClose,
}: {
  event: PromptEvent | null;
  onClose: () => void;
}) {
  const closeRef = useRef<HTMLButtonElement>(null);
  const panelRef = useRef<HTMLElement>(null);
  useFocusTrap(panelRef, !!event);

  useEffect(() => {
    if (!event) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    // Move focus into the dialog for keyboard + screen-reader users.
    closeRef.current?.focus();
    return () => window.removeEventListener("keydown", onKey);
  }, [event, onClose]);

  if (!event) return null;

  const headline =
    event.finalVerdict === "block" && event.blockedAtLayer
      ? `Blocked at ${LAYER_LABELS[event.blockedAtLayer]}`
      : event.finalVerdict === "flag"
        ? "Flagged for review"
        : "Passed all layers";

  return (
    <>
      <div
        className="fixed inset-0 z-40 bg-black/25"
        onClick={onClose}
        aria-hidden
      />
      <aside
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-label="Prompt event detail"
        className="fixed right-0 top-0 z-50 flex h-screen w-full max-w-[480px] flex-col border-l border-[var(--color-line)] bg-[var(--color-surface)] shadow-2xl"
      >
        {/* Layer 1 — the one-line verdict */}
        <header className="border-b border-[var(--color-line)] p-6">
          <div className="flex items-start justify-between gap-4">
            <div>
              <div className="flex items-center gap-2.5">
                <VerdictChip verdict={event.finalVerdict} size="md" />
                <span className="font-[family-name:var(--font-mono)] text-xs text-[var(--color-muted)]">
                  risk {formatScore(event.riskScore)}
                </span>
              </div>
              <h2 className="mt-2 font-[family-name:var(--font-display)] text-2xl tracking-tight">
                {headline}
              </h2>
              <p className="mt-1 font-[family-name:var(--font-mono)] text-[11px] text-[var(--color-faint)]">
                {event.id}
              </p>
            </div>
            <button
              ref={closeRef}
              type="button"
              onClick={onClose}
              aria-label="Close detail"
              className="rounded-[var(--radius)] px-2 py-1 text-[var(--color-muted)] hover:bg-[var(--color-surface-sunken)]"
            >
              ✕
            </button>
          </div>
        </header>

        <div className="flex-1 space-y-6 overflow-y-auto p-6">
          {/* The prompt excerpt */}
          <blockquote className="rounded-[var(--radius)] border-l-2 border-[var(--color-line-strong)] bg-[var(--color-surface-sunken)] px-4 py-3 text-sm leading-relaxed text-[var(--color-ink-soft)]">
            “{event.excerpt}”
          </blockquote>

          {/* Meta grid */}
          <div className="grid grid-cols-2 gap-4">
            <MetaField label="Direction">
              <span className="capitalize">{event.direction}</span>
            </MetaField>
            <MetaField label="Provider">
              <span className="capitalize">{event.provider || "—"}</span>
            </MetaField>
            <MetaField label="Category">
              {CATEGORY_LABELS[event.category]}
            </MetaField>
            <MetaField label="Tokens">
              <span className="font-[family-name:var(--font-mono)] text-xs">
                {event.tokens.in} in · {event.tokens.out} out
              </span>
            </MetaField>
            <MetaField label="Latency overhead">
              <span className="font-[family-name:var(--font-mono)] text-xs">
                {formatLatency(event.latencyOverheadUs)}
              </span>
            </MetaField>
            <MetaField label="API key">
              <span className="font-[family-name:var(--font-mono)] text-xs">
                {event.apiKeyId}
              </span>
            </MetaField>
            <MetaField label="Timestamp">
              <span className="font-[family-name:var(--font-mono)] text-xs">
                {new Date(event.ts).toLocaleString("en-US", { hour12: false })}
              </span>
            </MetaField>
          </div>

          {/* Layer 2 — the cascade trace, as the signature Assay Strip */}
          <div>
            <div className="eyebrow mb-3">
              {event.direction === "egress" ? "Egress Scan Trace" : "3-Fold Cascade Trace"}
            </div>
            <AssayStrip
              layers={event.layers}
              finalVerdict={event.finalVerdict}
              blockedAtLayer={event.blockedAtLayer}
              riskScore={event.riskScore}
              direction={event.direction}
            />
          </div>

          {/* Layer 3 — raw JSON, collapsed by default */}
          <RawJson data={event} />
        </div>
      </aside>
    </>
  );
}

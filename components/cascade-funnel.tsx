import { formatCompact, formatPct, LAYER_LABELS, LAYER_ORDINAL } from "@/lib/format";
import type { CascadeLayer } from "@/types/echelon";

/**
 * Where threats were caught across the 3-fold cascade. A precursor to the
 * signature "Cascade Assay Strip" (Phase 3) — for now, an honest bar breakdown.
 */
export function CascadeFunnel({
  caughtByLayer,
}: {
  caughtByLayer: Record<CascadeLayer, number>;
}) {
  const layers = Object.entries(caughtByLayer) as [CascadeLayer, number][];
  const total = layers.reduce((a, [, n]) => a + n, 0);

  return (
    <section className="rounded-[var(--radius-lg)] border border-[var(--color-line)] bg-[var(--color-surface)] p-6">
      <div className="flex items-baseline justify-between">
        <div>
          <div className="eyebrow">3-Fold Ingress Cascade</div>
          <h2 className="mt-1 font-[family-name:var(--font-display)] text-xl">
            Where threats were caught
          </h2>
        </div>
        <div className="tnum text-sm text-[var(--color-muted)]">
          {formatCompact(total)} blocked
        </div>
      </div>

      <div className="mt-6 space-y-4">
        {layers.map(([layer, count]) => {
          const pct = total ? count / total : 0;
          return (
            <div key={layer} className="flex items-center gap-4">
              <div className="w-32 shrink-0">
                <span className="font-[family-name:var(--font-mono)] text-xs text-[var(--color-brand)]">
                  {LAYER_ORDINAL[layer]}
                </span>
                <span className="ml-2 text-sm">{LAYER_LABELS[layer]}</span>
              </div>
              <div className="h-6 flex-1 overflow-hidden rounded-[var(--radius-sm)] bg-[var(--color-surface-sunken)]">
                <div
                  className="h-full bg-[var(--color-brand)]"
                  style={{ width: `${Math.max(pct * 100, 2)}%` }}
                />
              </div>
              <div className="tnum w-24 shrink-0 text-right text-sm">
                {formatCompact(count)}
                <span className="ml-2 text-xs text-[var(--color-faint)]">
                  {formatPct(pct, 0)}
                </span>
              </div>
            </div>
          );
        })}
      </div>

      <p className="mt-6 border-t border-[var(--color-line)] pt-4 text-xs leading-relaxed text-[var(--color-muted)]">
        Cheap heuristics catch the majority at L1; the DistilBERT classifier and
        LLM judge handle progressively subtler attacks that slip past.
      </p>
    </section>
  );
}

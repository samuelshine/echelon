"use client";

import { useEffect, useMemo, useState } from "react";
import { PageHeader } from "@/components/page-header";
import { LayerControl } from "@/components/config/layer-control";
import { EgressControl } from "@/components/config/egress-control";
import { WhatIfBar } from "@/components/config/what-if-bar";
import { useConfig, useEvents } from "@/lib/hooks/useEchelon";
import { DEFAULT_CONFIG } from "@/lib/api/mock";
import { computeImpact, configsEqual } from "@/lib/whatif";
import type { CascadeLayer, EchelonConfig, LayerConfig } from "@/types/echelon";

const DEFAULT_THRESHOLDS = Object.fromEntries(
  DEFAULT_CONFIG.ingress.map((c) => [c.layer, c.threshold]),
) as Record<CascadeLayer, number>;

export default function ConfigPage() {
  const { data: loaded } = useConfig();
  const { data: events } = useEvents(500);

  const [saved, setSaved] = useState<EchelonConfig | null>(null);
  const [pending, setPending] = useState<EchelonConfig | null>(null);

  // Seed local state once the saved config arrives.
  useEffect(() => {
    if (loaded && !saved) {
      setSaved(loaded);
      setPending(loaded);
    }
  }, [loaded, saved]);

  // Per-layer recent scores for the distribution strips.
  const scoresByLayer = useMemo(() => {
    const map: Record<string, number[]> = {
      heuristics: [],
      ml_classifier: [],
      llm_judge: [],
    };
    for (const e of events ?? []) {
      for (const l of e.layers) map[l.layer]?.push(l.score);
    }
    return map;
  }, [events]);

  const impact = useMemo(
    () =>
      saved && pending && events
        ? computeImpact(events, saved, pending)
        : null,
    [saved, pending, events],
  );

  if (!saved || !pending) {
    return (
      <>
        <PageHeader eyebrow="Module 02 · Policy" title="Thresholds" />
        <div className="p-8">
          <div className="h-96 animate-pulse rounded-[var(--radius-lg)] bg-[var(--color-surface-sunken)]" />
        </div>
      </>
    );
  }

  const setLayer = (next: LayerConfig) =>
    setPending({
      ...pending,
      ingress: pending.ingress.map((c) => (c.layer === next.layer ? next : c)),
    });

  const dirty = !configsEqual(saved, pending);

  return (
    <>
      <PageHeader eyebrow="Module 02 · Policy" title="Thresholds">
        {dirty ? (
          <span className="rounded-full bg-[var(--color-flag-wash)] px-3 py-1 text-xs font-medium text-[var(--color-flag)]">
            Unsaved changes
          </span>
        ) : (
          <span className="rounded-full border border-[var(--color-line-strong)] px-3 py-1 text-xs text-[var(--color-muted)]">
            All changes saved
          </span>
        )}
      </PageHeader>

      <div className="space-y-8 p-8 pb-28">
        <section>
          <div className="mb-4">
            <div className="eyebrow">Ingress · 3-fold cascade</div>
            <h2 className="mt-1 font-[family-name:var(--font-display)] text-xl">
              Routing thresholds
            </h2>
            <p className="mt-1 max-w-2xl text-sm text-[var(--color-muted)]">
              A prompt is blocked when a layer&apos;s risk score meets its threshold.
              Lower catches more (and adds false positives); higher lets more
              through. The histogram shows where recent traffic actually scores.
            </p>
          </div>
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            {pending.ingress.map((c) => (
              <LayerControl
                key={c.layer}
                config={c}
                defaultThreshold={DEFAULT_THRESHOLDS[c.layer]}
                scores={scoresByLayer[c.layer] ?? []}
                onChange={setLayer}
              />
            ))}
          </div>
        </section>

        <section>
          <div className="mb-4">
            <div className="eyebrow">Egress · response scanning</div>
            <h2 className="mt-1 font-[family-name:var(--font-display)] text-xl">
              What Echelon inspects on the way out
            </h2>
          </div>
          <EgressControl
            config={pending.egress}
            onChange={(egress) => setPending({ ...pending, egress })}
          />
        </section>

        {impact ? (
          <WhatIfBar
            impact={impact}
            dirty={dirty}
            onSave={() => setSaved(pending)}
            onReset={() => setPending(saved)}
          />
        ) : null}
      </div>
    </>
  );
}

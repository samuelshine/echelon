"use client";

import { PageHeader } from "@/components/page-header";
import { CascadeFunnel } from "@/components/cascade-funnel";
import { AttackVectorsChart } from "@/components/charts/attack-vectors-chart";
import { LatencyChart } from "@/components/charts/latency-chart";
import { CreditBurndown } from "@/components/charts/credit-burndown";
import { AssayStrip } from "@/components/cascade/assay-strip";
import { useDashboardSummary, useEvents } from "@/lib/hooks/useEchelon";
import {
  formatCompact,
  formatCredits,
  formatLatency,
  formatPct,
} from "@/lib/format";

export default function OverviewPage() {
  const { data: s } = useDashboardSummary();
  const { data: events } = useEvents(500);
  const latestBlock = events?.find((e) => e.finalVerdict === "block");

  if (!s) {
    return (
      <>
        <PageHeader eyebrow="Module 00 · Global" title="Overview" />
        <div className="p-8">
          <div className="h-96 animate-pulse rounded-[var(--radius-lg)] bg-[var(--color-surface-sunken)]" />
        </div>
      </>
    );
  }

  const kpis = [
    { label: "API calls", value: formatCompact(s.totalCalls), note: s.windowLabel },
    {
      label: "Blocked",
      value: formatPct(s.blockedPct),
      note: "of all traffic",
      tone: "block" as const,
    },
    {
      label: "Latency overhead",
      value: formatLatency(s.avgLatencyOverheadUs),
      note: "avg, added by Echelon",
    },
    {
      label: "Credits used",
      value: formatCredits(s.creditsUsed),
      note: `of ${formatCredits(s.creditsBudget)} budget`,
    },
  ];

  return (
    <>
      <PageHeader eyebrow="Module 00 · Global" title="Overview">
        <span className="rounded-full border border-[var(--color-line-strong)] px-3 py-1 text-xs text-[var(--color-muted)]">
          {s.windowLabel}
        </span>
      </PageHeader>

      <div className="space-y-8 p-8">
        {/* KPI row */}
        <section
          aria-label="Key metrics"
          className="grid grid-cols-1 gap-px overflow-hidden rounded-[var(--radius-lg)] border border-[var(--color-line)] bg-[var(--color-line)] sm:grid-cols-2 lg:grid-cols-4"
        >
          {kpis.map((k) => (
            <div key={k.label} className="bg-[var(--color-surface)] p-6">
              <div className="eyebrow">{k.label}</div>
              <div
                className="tnum mt-3 font-[family-name:var(--font-display)] text-4xl tracking-tight"
                style={
                  k.tone === "block" ? { color: "var(--color-block)" } : undefined
                }
              >
                {k.value}
              </div>
              <div className="mt-1 text-xs text-[var(--color-muted)]">{k.note}</div>
            </div>
          ))}
        </section>

        {/* Signature component showcase — most recent block */}
        {latestBlock ? (
          <section className="rounded-[var(--radius-lg)] border border-[var(--color-line)] bg-[var(--color-surface)] p-6">
            <div className="mb-4 flex items-baseline justify-between">
              <div>
                <div className="eyebrow">Most recent block</div>
                <h2 className="mt-1 font-[family-name:var(--font-display)] text-xl">
                  “{latestBlock.excerpt}”
                </h2>
              </div>
              <span className="font-[family-name:var(--font-mono)] text-xs text-[var(--color-muted)]">
                {latestBlock.id}
              </span>
            </div>
            <AssayStrip
              layers={latestBlock.layers}
              finalVerdict={latestBlock.finalVerdict}
              blockedAtLayer={latestBlock.blockedAtLayer}
              riskScore={latestBlock.riskScore}
              direction={latestBlock.direction}
            />
          </section>
        ) : null}

        {/* Primary chart — attack vectors */}
        <AttackVectorsChart />

        {/* Secondary row */}
        <div className="grid grid-cols-1 gap-8 lg:grid-cols-2">
          <LatencyChart />
          <CreditBurndown />
        </div>

        {/* Cascade breakdown */}
        <div className="grid grid-cols-1 gap-8 lg:grid-cols-2">
          <CascadeFunnel caughtByLayer={s.caughtByLayer} />
          <CascadeFunnel
            caughtByLayer={s.caughtByEgressLayer}
            eyebrow="Egress Scan Outcomes"
            title="Where responses were caught"
            footnote="PII masking and the canary check are deterministic and always on; the response classifier and judge adjudicate toxicity and malicious code in what the model sends back."
          />
        </div>
      </div>
    </>
  );
}

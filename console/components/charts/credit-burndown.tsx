"use client";

import {
  Area,
  AreaChart,
  CartesianGrid,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { useMetricSeries } from "@/lib/hooks/useEchelon";
import { formatCredits } from "@/lib/format";
import { ChartCard, ChartSkeleton } from "./chart-card";
import { AXIS_TICK, VizTooltip, hourTick } from "./chart-primitives";

const BUDGET = 1_000_000;

export function CreditBurndown() {
  const { data, isLoading } = useMetricSeries(24);

  // Cumulative credits consumed across the window.
  const cumulative = (() => {
    if (!data) return [];
    let running = 0;
    return data.map((p) => {
      running += p.creditsUsed;
      return { ts: p.ts, used: running };
    });
  })();

  const spent = cumulative.at(-1)?.used ?? 0;

  return (
    <ChartCard
      eyebrow="Gateway · last 24h"
      title="Credit burn-down"
      subtitle={`${formatCredits(spent)} of ${formatCredits(BUDGET)} daily budget consumed`}
    >
      {isLoading || !data ? (
        <ChartSkeleton height={200} />
      ) : (
        <div style={{ height: 200 }}>
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart
              data={cumulative}
              margin={{ top: 4, right: 8, bottom: 0, left: 4 }}
            >
              <defs>
                <linearGradient id="creditFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="var(--color-brand-soft)" stopOpacity={0.25} />
                  <stop offset="100%" stopColor="var(--color-brand-soft)" stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke="var(--color-line)" vertical={false} />
              <XAxis
                dataKey="ts"
                tickFormatter={hourTick}
                tick={AXIS_TICK}
                tickLine={false}
                axisLine={{ stroke: "var(--color-line-strong)" }}
                minTickGap={40}
              />
              <YAxis
                tick={AXIS_TICK}
                tickLine={false}
                axisLine={false}
                width={48}
                domain={[0, BUDGET]}
                tickFormatter={(v) => formatCredits(Number(v))}
              />
              <ReferenceLine
                y={BUDGET}
                stroke="var(--color-flag)"
                strokeDasharray="4 4"
                label={{
                  value: "budget",
                  position: "insideTopRight",
                  fontSize: 10,
                  fill: "var(--color-flag)",
                }}
              />
              <Tooltip
                cursor={{ stroke: "var(--color-line-strong)" }}
                content={({ active, payload, label }) =>
                  active && payload?.length ? (
                    <VizTooltip
                      label={hourTick(String(label))}
                      valueFormat={(v) => formatCredits(v)}
                      rows={[
                        {
                          key: "Cumulative credits",
                          value: Number(payload[0].value) || 0,
                          color: "var(--color-brand-soft)",
                        },
                      ]}
                    />
                  ) : null
                }
              />
              <Area
                type="monotone"
                dataKey="used"
                stroke="var(--color-brand-soft)"
                strokeWidth={2}
                fill="url(#creditFill)"
                isAnimationActive={false}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      )}
    </ChartCard>
  );
}

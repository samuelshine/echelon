"use client";

import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { useMetricSeries } from "@/lib/hooks/useEchelon";
import { formatLatency } from "@/lib/format";
import { ChartCard, ChartSkeleton } from "./chart-card";
import { AXIS_TICK, VizTooltip, hourTick } from "./chart-primitives";

export function LatencyChart() {
  const { data, isLoading } = useMetricSeries(24);

  return (
    <ChartCard
      eyebrow="Overhead · last 24h"
      title="Latency Echelon adds"
      subtitle="Average per-call overhead — the number that must stay small"
    >
      {isLoading || !data ? (
        <ChartSkeleton height={200} />
      ) : (
        <div style={{ height: 200 }}>
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart
              data={data}
              margin={{ top: 4, right: 8, bottom: 0, left: -4 }}
            >
              <defs>
                <linearGradient id="latencyFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="var(--color-brand)" stopOpacity={0.22} />
                  <stop offset="100%" stopColor="var(--color-brand)" stopOpacity={0.02} />
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
                width={56}
                tickFormatter={(v) => formatLatency(Number(v))}
              />
              <Tooltip
                cursor={{ stroke: "var(--color-line-strong)" }}
                content={({ active, payload, label }) =>
                  active && payload?.length ? (
                    <VizTooltip
                      label={hourTick(String(label))}
                      valueFormat={(v) => formatLatency(v)}
                      rows={[
                        {
                          key: "Avg overhead",
                          value: Number(payload[0].value) || 0,
                          color: "var(--color-brand)",
                        },
                      ]}
                    />
                  ) : null
                }
              />
              <Area
                type="monotone"
                dataKey="avgLatencyOverheadUs"
                stroke="var(--color-brand)"
                strokeWidth={2}
                fill="url(#latencyFill)"
                isAnimationActive={false}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      )}
    </ChartCard>
  );
}

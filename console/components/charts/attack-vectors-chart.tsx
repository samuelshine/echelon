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
import { ATTACK_ORDER, categoryColor, categoryLabel } from "@/lib/viz";
import { ChartCard, ChartSkeleton } from "./chart-card";
import {
  AXIS_TICK,
  CategoryLegend,
  VizTooltip,
  hourTick,
} from "./chart-primitives";

export function AttackVectorsChart() {
  const { data, isLoading } = useMetricSeries(24);

  return (
    <ChartCard
      eyebrow="Ingress · last 24h"
      title="Attack vectors over time"
      subtitle="Blocked & flagged prompts, stacked by threat category"
      action={<CategoryLegend categories={ATTACK_ORDER} />}
    >
      {isLoading || !data ? (
        <ChartSkeleton height={260} />
      ) : (
        <div style={{ height: 260 }}>
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart
              data={data.map((p) => ({ ts: p.ts, ...p.byCategory }))}
              margin={{ top: 4, right: 8, bottom: 0, left: -12 }}
            >
              <CartesianGrid
                stroke="var(--color-line)"
                strokeDasharray="0"
                vertical={false}
              />
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
                width={44}
              />
              <Tooltip
                cursor={{ stroke: "var(--color-line-strong)" }}
                content={({ active, payload, label }) =>
                  active && payload?.length ? (
                    <VizTooltip
                      label={hourTick(String(label))}
                      total={payload.reduce(
                        (s, p) => s + (Number(p.value) || 0),
                        0,
                      )}
                      rows={[...payload]
                        .reverse()
                        .map((p) => ({
                          key: categoryLabel(String(p.dataKey)),
                          value: Number(p.value) || 0,
                          color: categoryColor(String(p.dataKey)),
                        }))}
                    />
                  ) : null
                }
              />
              {ATTACK_ORDER.map((c) => (
                <Area
                  key={c}
                  type="monotone"
                  dataKey={c}
                  stackId="threats"
                  stroke="var(--color-surface)"
                  strokeWidth={2}
                  fill={categoryColor(c)}
                  fillOpacity={0.9}
                  isAnimationActive={false}
                />
              ))}
            </AreaChart>
          </ResponsiveContainer>
        </div>
      )}
    </ChartCard>
  );
}

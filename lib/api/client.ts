import {
  DEFAULT_CONFIG,
  KEYS,
  generateEvents,
  generateMetricSeries,
  getDashboardSummary,
} from "@/lib/api/mock";
import { promptEventSchema } from "@/lib/api/schemas";
import type {
  ApiKey,
  DashboardSummary,
  EchelonConfig,
  MetricPoint,
  PromptEvent,
} from "@/types/echelon";

/**
 * The single seam between the UI and the backend. Today every call resolves from
 * the seeded mock; swap the bodies for `fetch(...)` against the real Echelon API
 * and nothing downstream changes. Payloads are Zod-validated at this boundary so
 * malformed data never reaches a component.
 */

// Simulate a fast network so loading states are exercisable in dev.
const latency = () => new Promise((r) => setTimeout(r, 120));

export async function fetchDashboardSummary(): Promise<DashboardSummary> {
  await latency();
  return getDashboardSummary();
}

export async function fetchMetricSeries(hours = 24): Promise<MetricPoint[]> {
  await latency();
  return generateMetricSeries(hours);
}

export async function fetchEvents(count = 500): Promise<PromptEvent[]> {
  await latency();
  // Validate at the boundary — this is where the real API's shape gets enforced.
  return generateEvents(count).map((e) => promptEventSchema.parse(e));
}

export async function fetchApiKeys(): Promise<ApiKey[]> {
  await latency();
  return KEYS;
}

export async function fetchConfig(): Promise<EchelonConfig> {
  await latency();
  return DEFAULT_CONFIG;
}

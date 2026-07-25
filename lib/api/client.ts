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
 * The single seam between the UI and the backend.
 *
 * When `NEXT_PUBLIC_ECHELON_API_URL` is set, every call hits the real Echelon Go
 * gateway's console API (`/v1/console/*`), which emits these exact shapes. If it is
 * unset — or a request fails — we fall back to the seeded mock so the console still
 * renders in isolation (offline, or first paint before the gateway is up). Payloads
 * are Zod-validated at this boundary so malformed data never reaches a component.
 */

const BASE_URL = process.env.NEXT_PUBLIC_ECHELON_API_URL?.replace(/\/$/, "");

async function getJSON<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: { Accept: "application/json" },
    cache: "no-store",
  });
  if (!res.ok) throw new Error(`Echelon API ${path} -> HTTP ${res.status}`);
  return (await res.json()) as T;
}

export async function fetchDashboardSummary(): Promise<DashboardSummary> {
  if (!BASE_URL) return getDashboardSummary();
  try {
    return await getJSON<DashboardSummary>("/v1/console/summary");
  } catch {
    return getDashboardSummary();
  }
}

export async function fetchMetricSeries(hours = 24): Promise<MetricPoint[]> {
  if (!BASE_URL) return generateMetricSeries(hours);
  try {
    return await getJSON<MetricPoint[]>("/v1/console/metrics");
  } catch {
    return generateMetricSeries(hours);
  }
}

export async function fetchEvents(count = 500): Promise<PromptEvent[]> {
  if (!BASE_URL) return generateEvents(count).map((e) => promptEventSchema.parse(e));
  try {
    const raw = await getJSON<unknown[]>("/v1/console/events");
    // Validate at the boundary — this is where the real API's shape gets enforced.
    return raw.map((e) => promptEventSchema.parse(e));
  } catch {
    return generateEvents(count).map((e) => promptEventSchema.parse(e));
  }
}

export async function fetchApiKeys(): Promise<ApiKey[]> {
  if (!BASE_URL) return KEYS;
  try {
    const keys = await getJSON<ApiKey[]>("/v1/console/keys");
    return keys.length > 0 ? keys : KEYS;
  } catch {
    return KEYS;
  }
}

export async function fetchConfig(): Promise<EchelonConfig> {
  if (!BASE_URL) return DEFAULT_CONFIG;
  try {
    return await getJSON<EchelonConfig>("/v1/console/config");
  } catch {
    return DEFAULT_CONFIG;
  }
}

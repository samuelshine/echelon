import {
  DEFAULT_CONFIG,
  KEYS,
  generateEvents,
  generateMetricSeries,
  getDashboardSummary,
} from "@/lib/api/mock";
import {
  apiKeySchema,
  createKeyResponseSchema,
  echelonConfigSchema,
  eventsResponseSchema,
  promptEventSchema,
} from "@/lib/api/schemas";
import { applyFilters, type LogFilterState } from "@/lib/logs";
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

/**
 * Mutating request. Unlike the read helpers above, this NEVER falls back to mock
 * data: a write that silently "succeeds" against no backend would lie to the
 * operator that their change took effect. If the gateway URL is unset or the
 * request fails, it throws — the calling page must catch, roll back its
 * optimistic update, and surface the error.
 */
async function mutateJSON<T>(method: string, path: string, body?: unknown): Promise<T> {
  if (!BASE_URL) {
    throw new Error(
      "This action requires a live Echelon gateway (NEXT_PUBLIC_ECHELON_API_URL is not set).",
    );
  }
  const res = await fetch(`${BASE_URL}${path}`, {
    method,
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    cache: "no-store",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`Echelon API ${method} ${path} -> HTTP ${res.status}`);
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

export interface EventsPage {
  events: PromptEvent[];
  nextCursor: string | null;
  hasMore: boolean;
}

/**
 * Map the log filter state (+ an optional resume cursor) to the query string the
 * gateway's GET /v1/console/events now expects. Field names are 1:1 with the
 * gateway params (`verdict`, `direction`, `layer`, `apiKeyId`, `q`, `minRisk`,
 * `before`, `limit`); "all"/empty/zero dimensions are omitted (they mean "no
 * filter" on both sides). Pure and exported so it can be unit-tested directly.
 */
export function buildEventsQuery(
  filters: LogFilterState,
  cursor?: string | null,
  limit = 100,
): string {
  const params = new URLSearchParams();
  if (filters.verdict !== "all") params.set("verdict", filters.verdict);
  if (filters.direction !== "all") params.set("direction", filters.direction);
  if (filters.layer !== "all") params.set("layer", filters.layer);
  if (filters.apiKeyId !== "all") params.set("apiKeyId", filters.apiKeyId);
  const q = filters.query.trim();
  if (q) params.set("q", q);
  if (filters.minRisk > 0) params.set("minRisk", String(filters.minRisk));
  if (cursor) params.set("before", cursor);
  params.set("limit", String(limit));
  return params.toString();
}

/**
 * One filtered, cursor-paginated page of events. Against a live gateway this is a
 * true server-side query. Offline (no gateway URL, or on failure) it falls back to
 * running the same filter predicate over the seeded mock and synthesizes a single
 * page — so callers need no separate offline code path.
 */
export async function fetchEventsPage(
  filters: LogFilterState,
  cursor?: string | null,
): Promise<EventsPage> {
  if (!BASE_URL) return mockEventsPage(filters);
  try {
    const raw = await getJSON<unknown>(`/v1/console/events?${buildEventsQuery(filters, cursor)}`);
    const parsed = eventsResponseSchema.parse(raw);
    return { events: parsed.events, nextCursor: parsed.nextCursor, hasMore: parsed.hasMore };
  } catch {
    return mockEventsPage(filters);
  }
}

function mockEventsPage(filters: LogFilterState): EventsPage {
  const all = generateEvents(500).map((e) => promptEventSchema.parse(e));
  return { events: applyFilters(all, filters), nextCursor: null, hasMore: false };
}

/**
 * A flat batch of the most-recent events (unfiltered), used by the dashboard and
 * config pages. Consumes the same wrapped wire shape as fetchEventsPage and
 * returns just the events array.
 */
export async function fetchEvents(count = 500): Promise<PromptEvent[]> {
  if (!BASE_URL) return generateEvents(count).map((e) => promptEventSchema.parse(e));
  try {
    const params = new URLSearchParams({ limit: String(Math.min(count, 500)) });
    const raw = await getJSON<unknown>(`/v1/console/events?${params.toString()}`);
    return eventsResponseSchema.parse(raw).events;
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

// --- Mutations (throw on failure; never fall back to mock) --------------------

export async function createApiKey(label: string): Promise<{ key: ApiKey; secret: string }> {
  const raw = await mutateJSON<unknown>("POST", "/v1/console/keys", { label });
  return createKeyResponseSchema.parse(raw);
}

export async function updateApiKeyLimits(
  id: string,
  rateLimitRpm: number,
  creditBudget: number,
): Promise<ApiKey> {
  const raw = await mutateJSON<unknown>("PATCH", `/v1/console/keys/${id}`, {
    rateLimitRpm,
    creditBudget,
  });
  return apiKeySchema.parse(raw);
}

export async function revokeApiKey(id: string): Promise<ApiKey> {
  const raw = await mutateJSON<unknown>("DELETE", `/v1/console/keys/${id}`);
  return apiKeySchema.parse(raw);
}

export async function updateConfig(config: EchelonConfig): Promise<EchelonConfig> {
  const raw = await mutateJSON<unknown>("PATCH", "/v1/console/config", config);
  return echelonConfigSchema.parse(raw);
}

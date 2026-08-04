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
  promptEventSchema,
} from "@/lib/api/schemas";
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

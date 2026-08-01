/**
 * Echelon domain model.
 *
 * These types are the contract the whole console is built against. They are
 * provisional until the backend publishes an OpenAPI spec — the Zod schemas in
 * `lib/api/schemas.ts` are the runtime source of truth and these types are
 * inferred from them where possible.
 */

/** The three stages of the ingress cascade, in evaluation order. */
export type IngressLayer = "heuristics" | "ml_classifier" | "llm_judge";

/** The egress (response-side) scanner stages, in evaluation order. */
export type EgressLayer = "pii" | "response_policy" | "response_classifier" | "response_judge";

/** Any stage in either cascade — the shape a single event's `layers` array uses. */
export type CascadeLayer = IngressLayer | EgressLayer;

/** A single stage's ruling. */
export type Verdict = "pass" | "flag" | "block";

/** Which side of the firewall an event came from. */
export type Direction = "ingress" | "egress";

/** The categories of threat Echelon recognizes (used for charting attack vectors). */
export type ThreatCategory =
  | "prompt_injection"
  | "jailbreak"
  | "pii_leak"
  | "toxicity"
  | "policy_violation"
  | "data_exfiltration"
  | "malicious_code"
  | "clean";

export interface LayerResult {
  layer: CascadeLayer;
  verdict: Verdict;
  /** Normalized 0..1 confidence/risk for this stage. */
  score: number;
  /** The routing threshold that was in force when this stage ran. */
  threshold: number;
  /** e.g. "DistilBERT-injection-v2" or "claude-judge". */
  model?: string;
  latencyUs: number;
  /** Raw, stage-specific detail — surfaced in the JSON drill-down. */
  detail: Record<string, unknown>;
}

export interface PromptEvent {
  id: string;
  /** ISO timestamp. */
  ts: string;
  direction: Direction;
  finalVerdict: Verdict;
  /** Aggregate risk score, 0..1. */
  riskScore: number;
  category: ThreatCategory;
  /** Which layer produced the terminal verdict, if blocked/flagged. */
  blockedAtLayer?: CascadeLayer;
  layers: LayerResult[];
  tokens: { in: number; out: number };
  /** The headline metric: overhead Echelon added, in microseconds. */
  latencyOverheadUs: number;
  apiKeyId: string;
  /** Truncated preview of the prompt/response for the log row. */
  excerpt: string;
  /** The upstream provider that served this request (e.g. openai, gemini) */
  provider?: string;
}

export interface MetricPoint {
  /** ISO timestamp (bucket start). */
  ts: string;
  calls: number;
  blocked: number;
  flagged: number;
  byCategory: Record<Exclude<ThreatCategory, "clean">, number>;
  avgLatencyOverheadUs: number;
  creditsUsed: number;
}

export interface DashboardSummary {
  totalCalls: number;
  blockedPct: number;
  avgLatencyOverheadUs: number;
  creditsUsed: number;
  creditsBudget: number;
  /** Counts caught at each ingress cascade stage (funnel). */
  caughtByLayer: Record<IngressLayer, number>;
  /** Counts caught at each egress scanner stage (funnel). */
  caughtByEgressLayer: Record<EgressLayer, number>;
  windowLabel: string;
}

export interface ApiKey {
  id: string;
  label: string;
  /** Only ever the last 4 chars are retained after creation. */
  last4: string;
  createdAt: string;
  lastUsedAt?: string;
  status: "active" | "revoked";
  rateLimitRpm: number;
  creditBudget: number;
  creditsUsed: number;
}

export interface LayerConfig {
  layer: IngressLayer;
  enabled: boolean;
  /** Routing threshold, 0..1 — scores at or above escalate/block. */
  threshold: number;
  model?: string;
}

export interface EgressConfig {
  piiMasking: boolean;
  toxicityScan: boolean;
  policyEnforcement: boolean;
  maliciousCodeScan: boolean;
}

export interface EchelonConfig {
  ingress: LayerConfig[];
  egress: EgressConfig;
  providers?: string[];
}

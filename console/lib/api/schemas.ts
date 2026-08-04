import { z } from "zod";

/**
 * Runtime validation for every Echelon payload. These are the source of truth;
 * the hand-written types in `types/echelon.ts` mirror them. When the real API
 * ships, these schemas guard the boundary so bad data never reaches the UI.
 */

export const ingressLayerSchema = z.enum(["heuristics", "ml_classifier", "llm_judge"]);
export const egressLayerSchema = z.enum([
  "pii",
  "response_policy",
  "response_classifier",
  "response_judge",
]);
export const cascadeLayerSchema = z.enum([
  "heuristics",
  "ml_classifier",
  "llm_judge",
  "pii",
  "response_policy",
  "response_classifier",
  "response_judge",
]);

export const verdictSchema = z.enum(["pass", "flag", "block"]);
export const directionSchema = z.enum(["ingress", "egress"]);

export const threatCategorySchema = z.enum([
  "prompt_injection",
  "jailbreak",
  "pii_leak",
  "toxicity",
  "policy_violation",
  "data_exfiltration",
  "malicious_code",
  "clean",
]);

export const layerResultSchema = z.object({
  layer: cascadeLayerSchema,
  verdict: verdictSchema,
  score: z.number().min(0).max(1),
  threshold: z.number().min(0).max(1),
  model: z.string().optional(),
  latencyUs: z.number().nonnegative(),
  detail: z.record(z.unknown()),
});

export const promptEventSchema = z.object({
  id: z.string(),
  ts: z.string(),
  direction: directionSchema,
  finalVerdict: verdictSchema,
  riskScore: z.number().min(0).max(1),
  category: threatCategorySchema,
  blockedAtLayer: cascadeLayerSchema.optional(),
  layers: z.array(layerResultSchema),
  tokens: z.object({ in: z.number(), out: z.number() }),
  latencyOverheadUs: z.number().nonnegative(),
  apiKeyId: z.string(),
  provider: z.string().optional(),
  excerpt: z.string(),
});

export const apiKeySchema = z.object({
  id: z.string(),
  label: z.string(),
  last4: z.string(),
  createdAt: z.string(),
  lastUsedAt: z.string().optional(),
  status: z.enum(["active", "revoked"]),
  rateLimitRpm: z.number().int().positive(),
  creditBudget: z.number().nonnegative(),
  creditsUsed: z.number().nonnegative(),
});

export const layerConfigSchema = z.object({
  layer: ingressLayerSchema,
  enabled: z.boolean(),
  threshold: z.number().min(0).max(1),
  model: z.string().optional(),
});

export const echelonConfigSchema = z.object({
  ingress: z.array(layerConfigSchema),
  egress: z.object({
    piiMasking: z.boolean(),
    toxicityScan: z.boolean(),
    policyEnforcement: z.boolean(),
    maliciousCodeScan: z.boolean(),
  }),
  providers: z.array(z.string()).optional(),
});

// POST /v1/console/keys returns the created key plus its plaintext secret,
// shown to the operator exactly once.
export const createKeyResponseSchema = z.object({
  key: apiKeySchema,
  secret: z.string(),
});

export type PromptEventDTO = z.infer<typeof promptEventSchema>;
export type ApiKeyDTO = z.infer<typeof apiKeySchema>;
export type EchelonConfigDTO = z.infer<typeof echelonConfigSchema>;
export type CreateKeyResponseDTO = z.infer<typeof createKeyResponseSchema>;

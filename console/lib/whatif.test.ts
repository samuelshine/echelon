import { describe, expect, it } from "vitest";
import { computeImpact, configsEqual, recomputeVerdict } from "@/lib/whatif";
import type { EchelonConfig, LayerResult, PromptEvent } from "@/types/echelon";

function layer(l: LayerResult["layer"], score: number): LayerResult {
  return { layer: l, verdict: "pass", score, threshold: 0.6, latencyUs: 100, detail: {} };
}

function event(partial: Partial<PromptEvent> & { layers: LayerResult[] }): PromptEvent {
  return {
    id: "evt_1",
    ts: new Date().toISOString(),
    direction: "ingress",
    finalVerdict: "block",
    riskScore: 0.9,
    category: "prompt_injection",
    tokens: { in: 10, out: 0 },
    latencyOverheadUs: 100,
    apiKeyId: "key_1",
    excerpt: "x",
    ...partial,
  };
}

const config = (thr: Record<string, number>, disabled: string[] = []): EchelonConfig => ({
  ingress: (["heuristics", "ml_classifier", "llm_judge"] as const).map((layer) => ({
    layer,
    enabled: !disabled.includes(layer),
    threshold: thr[layer] ?? 0.6,
  })),
  egress: { piiMasking: true, toxicityScan: true, policyEnforcement: false, maliciousCodeScan: false },
});

const base = config({ heuristics: 0.7, ml_classifier: 0.6, llm_judge: 0.5 });

describe("recomputeVerdict", () => {
  it("blocks at the first layer whose score meets the threshold", () => {
    const e = event({ layers: [layer("heuristics", 0.2), layer("ml_classifier", 0.89)] });
    expect(recomputeVerdict(e, base.ingress)).toEqual({ verdict: "block", blockedAt: "ml_classifier" });
  });

  it("flags when a score is within 0.15 below the threshold", () => {
    const e = event({ layers: [layer("ml_classifier", 0.5)] }); // thresh 0.6, band 0.45–0.6
    expect(recomputeVerdict(e, base.ingress).verdict).toBe("flag");
  });

  it("passes when all scores are comfortably below threshold", () => {
    const e = event({ layers: [layer("heuristics", 0.1), layer("ml_classifier", 0.2)] });
    expect(recomputeVerdict(e, base.ingress).verdict).toBe("pass");
  });

  it("ignores a disabled layer even if its score would block", () => {
    const off = config({ ml_classifier: 0.6 }, ["ml_classifier"]);
    const e = event({ layers: [layer("ml_classifier", 0.99)] });
    expect(recomputeVerdict(e, off.ingress).verdict).toBe("pass");
  });
});

describe("computeImpact (the guardrail)", () => {
  const attackAt = (score: number, category: PromptEvent["category"] = "prompt_injection") =>
    event({ category, layers: [layer("heuristics", 0.2), layer("ml_classifier", score)] });

  const events = [attackAt(0.72), attackAt(0.66, "jailbreak"), event({ category: "clean", layers: [layer("ml_classifier", 0.05)] })];

  it("counts regressions when raising a threshold frees known attacks", () => {
    const raised = config({ heuristics: 0.7, ml_classifier: 0.8, llm_judge: 0.5 });
    const impact = computeImpact(events, base, raised);
    expect(impact.newlyAllowed).toBe(2);
    expect(impact.regressions).toBe(2);
    expect(impact.regressionSamples.length).toBe(2);
  });

  it("reports no regression when lowering a threshold", () => {
    const lowered = config({ heuristics: 0.7, ml_classifier: 0.5, llm_judge: 0.5 });
    expect(computeImpact(events, base, lowered).regressions).toBe(0);
  });

  it("counts a disabled layer as freeing attacks", () => {
    const off = config({ heuristics: 0.7, ml_classifier: 0.6, llm_judge: 0.5 }, ["ml_classifier"]);
    expect(computeImpact(events, base, off).regressions).toBe(2);
  });

  it("is all-zero when nothing changes", () => {
    const impact = computeImpact(events, base, base);
    expect(impact.newlyAllowed).toBe(0);
    expect(impact.newlyBlocked).toBe(0);
    expect(impact.regressions).toBe(0);
  });

  it("does not count a freed clean prompt as a regression", () => {
    const nearClean = event({ category: "clean", layers: [layer("ml_classifier", 0.62)] });
    const raised = config({ heuristics: 0.7, ml_classifier: 0.8, llm_judge: 0.5 });
    const impact = computeImpact([nearClean], base, raised);
    expect(impact.newlyAllowed).toBe(1);
    expect(impact.regressions).toBe(0);
  });
});

describe("configsEqual", () => {
  it("is true for identical configs and false after an edit", () => {
    expect(configsEqual(base, config({ heuristics: 0.7, ml_classifier: 0.6, llm_judge: 0.5 }))).toBe(true);
    expect(configsEqual(base, config({ heuristics: 0.9, ml_classifier: 0.6, llm_judge: 0.5 }))).toBe(false);
  });
});

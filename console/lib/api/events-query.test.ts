import { describe, expect, it } from "vitest";
import { buildEventsQuery } from "@/lib/api/client";
import { DEFAULT_FILTERS, type LogFilterState } from "@/lib/logs";

const f = (over: Partial<LogFilterState>): LogFilterState => ({ ...DEFAULT_FILTERS, ...over });

// Parse the produced query string back into a plain object for order-independent
// assertions.
function parse(qs: string): Record<string, string> {
  return Object.fromEntries(new URLSearchParams(qs));
}

describe("buildEventsQuery", () => {
  it("omits every 'all'/empty/zero dimension, always sets a limit", () => {
    expect(parse(buildEventsQuery(DEFAULT_FILTERS))).toEqual({ limit: "100" });
  });

  it("maps each filter dimension to its gateway param name", () => {
    const qs = parse(
      buildEventsQuery(
        f({
          verdict: "block",
          direction: "egress",
          layer: "ml_classifier",
          apiKeyId: "key_1",
          query: "  ignore  ",
          minRisk: 0.6,
        }),
      ),
    );
    expect(qs).toEqual({
      verdict: "block",
      direction: "egress",
      layer: "ml_classifier",
      apiKeyId: "key_1",
      q: "ignore",
      minRisk: "0.6",
      limit: "100",
    });
  });

  it("trims the query and omits it when blank", () => {
    expect(parse(buildEventsQuery(f({ query: "   " }))).q).toBeUndefined();
  });

  it("omits minRisk when zero and includes it when positive", () => {
    expect(parse(buildEventsQuery(f({ minRisk: 0 }))).minRisk).toBeUndefined();
    expect(parse(buildEventsQuery(f({ minRisk: 0.45 }))).minRisk).toBe("0.45");
  });

  it("adds the before cursor only when provided", () => {
    expect(parse(buildEventsQuery(DEFAULT_FILTERS, "evt_42")).before).toBe("evt_42");
    expect(parse(buildEventsQuery(DEFAULT_FILTERS, null)).before).toBeUndefined();
    expect(parse(buildEventsQuery(DEFAULT_FILTERS, undefined)).before).toBeUndefined();
  });

  it("honors a custom page limit", () => {
    expect(parse(buildEventsQuery(DEFAULT_FILTERS, null, 25)).limit).toBe("25");
  });

  it("url-encodes special characters in the query", () => {
    const qs = buildEventsQuery(f({ query: "a&b=c" }));
    expect(parse(qs).q).toBe("a&b=c");
  });
});

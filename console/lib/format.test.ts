import { describe, expect, it } from "vitest";
import { formatLatency, formatPct, formatScore, formatRelativeTime } from "@/lib/format";

describe("formatLatency", () => {
  it("renders sub-millisecond values in microseconds", () => {
    expect(formatLatency(247)).toBe("247 µs");
    expect(formatLatency(999)).toBe("999 µs");
  });
  it("renders millisecond values with the right precision", () => {
    expect(formatLatency(1860)).toBe("1.86 ms");
    expect(formatLatency(12000)).toBe("12.0 ms");
  });
});

describe("formatPct / formatScore", () => {
  it("formats a fraction as a percentage", () => {
    expect(formatPct(0.064)).toBe("6.4%");
    expect(formatPct(0.5, 0)).toBe("50%");
  });
  it("formats a score to two decimals", () => {
    expect(formatScore(0.9)).toBe("0.90");
    expect(formatScore(0.891)).toBe("0.89");
  });
});

describe("formatRelativeTime", () => {
  const now = new Date("2026-07-22T12:00:00Z").getTime();
  it("renders seconds, minutes, hours, days ago", () => {
    expect(formatRelativeTime(new Date(now - 10_000).toISOString(), now)).toBe("10s ago");
    expect(formatRelativeTime(new Date(now - 120_000).toISOString(), now)).toBe("2m ago");
    expect(formatRelativeTime(new Date(now - 3 * 3_600_000).toISOString(), now)).toBe("3h ago");
    expect(formatRelativeTime(new Date(now - 2 * 86_400_000).toISOString(), now)).toBe("2d ago");
  });
});

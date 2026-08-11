import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { renderHook, act, waitFor } from "@testing-library/react";
import { useLiveTail } from "./useLiveTail";

// BASE_URL inside useLiveTail.ts is read from process.env once at module load,
// so exercising the "real transport" branch requires setting the env var and
// re-importing a fresh module instance rather than reusing the static import.

describe("useLiveTail (simulated fallback, no NEXT_PUBLIC_ECHELON_API_URL)", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("streams nothing while disabled", () => {
    const { result } = renderHook(() => useLiveTail({ enabled: false }));
    expect(result.current.streamed).toEqual([]);
  });

  it("emits a simulated event on each interval tick once enabled", () => {
    const { result } = renderHook(() => useLiveTail({ enabled: true, intervalMs: 1000 }));
    expect(result.current.streamed).toHaveLength(0);

    act(() => {
      vi.advanceTimersByTime(1000);
    });
    expect(result.current.streamed).toHaveLength(1);

    act(() => {
      vi.advanceTimersByTime(2000);
    });
    expect(result.current.streamed).toHaveLength(3);
  });

  it("caps the buffer at max and marks new events fresh until freshMs elapses", () => {
    const { result } = renderHook(() =>
      useLiveTail({ enabled: true, intervalMs: 100, max: 2, freshMs: 500 }),
    );

    act(() => {
      vi.advanceTimersByTime(300);
    });
    expect(result.current.streamed.length).toBeLessThanOrEqual(2);
    const newestId = result.current.streamed[0].id;
    expect(result.current.freshIds.has(newestId)).toBe(true);

    act(() => {
      vi.advanceTimersByTime(500);
    });
    expect(result.current.freshIds.has(newestId)).toBe(false);
  });

  it("clear() empties both the stream and the fresh set", () => {
    const { result } = renderHook(() => useLiveTail({ enabled: true, intervalMs: 100 }));
    act(() => {
      vi.advanceTimersByTime(300);
    });
    expect(result.current.streamed.length).toBeGreaterThan(0);

    act(() => {
      result.current.clear();
    });
    expect(result.current.streamed).toEqual([]);
    expect(result.current.freshIds.size).toBe(0);
  });

  it("stops emitting once disabled again", () => {
    const { result, rerender } = renderHook(
      ({ enabled }) => useLiveTail({ enabled, intervalMs: 100 }),
      { initialProps: { enabled: true } },
    );
    act(() => {
      vi.advanceTimersByTime(300);
    });
    const countWhileLive = result.current.streamed.length;
    expect(countWhileLive).toBeGreaterThan(0);

    rerender({ enabled: false });
    act(() => {
      vi.advanceTimersByTime(1000);
    });
    expect(result.current.streamed.length).toBe(countWhileLive);
  });
});

describe("useLiveTail (real SSE transport)", () => {
  const ORIGINAL_URL = process.env.NEXT_PUBLIC_ECHELON_API_URL;
  let openedUrls: string[];
  let sources: FakeEventSource[];
  let useLiveTailReal: typeof useLiveTail;

  class FakeEventSource {
    url: string;
    onmessage: ((ev: MessageEvent) => void) | null = null;
    onerror: (() => void) | null = null;
    closed = false;

    constructor(url: string) {
      this.url = url;
      openedUrls.push(url);
      sources.push(this);
    }

    emit(data: unknown) {
      this.onmessage?.({ data: JSON.stringify(data) } as MessageEvent);
    }

    close() {
      this.closed = true;
    }
  }

  beforeEach(async () => {
    process.env.NEXT_PUBLIC_ECHELON_API_URL = "https://gateway.example.com";
    openedUrls = [];
    sources = [];
    vi.stubGlobal("EventSource", FakeEventSource as unknown as typeof EventSource);
    vi.resetModules();
    ({ useLiveTail: useLiveTailReal } = await import("./useLiveTail"));
  });

  afterEach(() => {
    process.env.NEXT_PUBLIC_ECHELON_API_URL = ORIGINAL_URL;
    vi.unstubAllGlobals();
    vi.resetModules();
  });

  function validEvent(id: string) {
    return {
      id,
      ts: new Date().toISOString(),
      direction: "ingress",
      finalVerdict: "pass",
      riskScore: 0.1,
      category: "clean",
      layers: [],
      tokens: { in: 10, out: 5 },
      latencyOverheadUs: 100,
      apiKeyId: "key_1",
      excerpt: "hello",
    };
  }

  it("opens the gateway's SSE stream at the configured base URL, not the sim interval", () => {
    renderHook(() => useLiveTailReal({ enabled: true }));
    expect(openedUrls).toEqual(["https://gateway.example.com/v1/console/events/stream"]);
  });

  it("feeds a validated SSE frame into streamed", async () => {
    const { result } = renderHook(() => useLiveTailReal({ enabled: true }));
    act(() => {
      sources[0].emit(validEvent("evt_real_1"));
    });
    await waitFor(() => expect(result.current.streamed).toHaveLength(1));
    expect(result.current.streamed[0].id).toBe("evt_real_1");
  });

  it("silently drops a frame that fails schema validation", async () => {
    const { result } = renderHook(() => useLiveTailReal({ enabled: true }));
    act(() => {
      sources[0].emit({ not: "a valid event" });
    });
    // Give any (incorrect) async update a chance to land, then assert nothing did.
    await act(async () => {
      await Promise.resolve();
    });
    expect(result.current.streamed).toHaveLength(0);
  });

  it("closes the EventSource on unmount", () => {
    const { unmount } = renderHook(() => useLiveTailReal({ enabled: true }));
    expect(sources[0].closed).toBe(false);
    unmount();
    expect(sources[0].closed).toBe(true);
  });

  it("closes without reconnecting on a stream error (documented v1 limitation)", () => {
    renderHook(() => useLiveTailReal({ enabled: true }));
    act(() => {
      sources[0].onerror?.();
    });
    expect(sources[0].closed).toBe(true);
    expect(sources).toHaveLength(1);
  });
});

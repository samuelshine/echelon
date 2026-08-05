"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { makeEvent } from "@/lib/api/mock";
import { promptEventSchema } from "@/lib/api/schemas";
import type { PromptEvent } from "@/types/echelon";

const BASE_URL = process.env.NEXT_PUBLIC_ECHELON_API_URL?.replace(/\/$/, "");

/**
 * Live-tail of newly-recorded events.
 *
 * When `NEXT_PUBLIC_ECHELON_API_URL` is set, this opens a real SSE subscription to
 * the gateway's `/v1/console/events/stream` and feeds each validated frame into the
 * same streamed/freshIds state the simulated path uses. When it is unset, behavior
 * is unchanged: a `Math.random`-driven interval fabricates events so the console
 * still demos offline. Either way the return shape is identical.
 *
 * Simplification (v1): on an SSE error we simply close the connection — there is no
 * reconnect/backoff. The operator re-enables live-tail to reopen it.
 */
export function useLiveTail({
  enabled,
  intervalMs = 2200,
  max = 50,
  freshMs = 2600,
}: {
  enabled: boolean;
  intervalMs?: number;
  max?: number;
  freshMs?: number;
}) {
  const [streamed, setStreamed] = useState<PromptEvent[]>([]);
  const [fresh, setFresh] = useState<Set<string>>(new Set());
  const timers = useRef<ReturnType<typeof setTimeout>[]>([]);

  // Shared ingest path for both the real SSE stream and the simulated interval:
  // prepend the event, cap the buffer, mark it fresh, and schedule fresh-expiry.
  const push = useCallback(
    (e: PromptEvent) => {
      setStreamed((prev) => [e, ...prev].slice(0, max));
      setFresh((prev) => new Set(prev).add(e.id));
      const t = setTimeout(() => {
        setFresh((prev) => {
          const next = new Set(prev);
          next.delete(e.id);
          return next;
        });
      }, freshMs);
      timers.current.push(t);
    },
    [max, freshMs],
  );

  useEffect(() => {
    if (!enabled) return;

    // Real transport: subscribe to the gateway's SSE feed of recorded events.
    if (BASE_URL) {
      const source = new EventSource(`${BASE_URL}/v1/console/events/stream`);
      source.onmessage = (ev) => {
        try {
          const parsed = promptEventSchema.parse(JSON.parse(ev.data));
          push(parsed);
        } catch {
          // Ignore malformed frames rather than tearing down the whole stream.
        }
      };
      source.onerror = () => {
        // v1: no reconnect/backoff — close and wait for the operator to re-enable.
        source.close();
      };
      return () => {
        source.close();
        timers.current.forEach(clearTimeout);
        timers.current = [];
      };
    }

    // Offline fallback: unchanged simulated stream.
    const id = setInterval(() => {
      push(
        makeEvent(
          Math.random,
          `evt_live_${Date.now().toString(36)}${Math.floor(Math.random() * 1e4)}`,
          Date.now(),
        ),
      );
    }, intervalMs);

    return () => {
      clearInterval(id);
      timers.current.forEach(clearTimeout);
      timers.current = [];
    };
  }, [enabled, intervalMs, push]);

  const clear = useCallback(() => {
    setStreamed([]);
    setFresh(new Set());
  }, []);

  return { streamed, freshIds: fresh, clear };
}

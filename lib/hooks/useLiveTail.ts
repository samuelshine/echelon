"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { makeEvent } from "@/lib/api/mock";
import type { PromptEvent } from "@/types/echelon";

/**
 * Simulated live-tail. This is the abstraction seam for the real stream — swap
 * the interval for an EventSource/WebSocket subscription and the return shape
 * (streamed events + freshly-arrived ids) stays identical.
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

  useEffect(() => {
    if (!enabled) return;
    const id = setInterval(() => {
      const e = makeEvent(
        Math.random,
        `evt_live_${Date.now().toString(36)}${Math.floor(Math.random() * 1e4)}`,
        Date.now(),
      );
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
    }, intervalMs);

    return () => {
      clearInterval(id);
      timers.current.forEach(clearTimeout);
      timers.current = [];
    };
  }, [enabled, intervalMs, max, freshMs]);

  const clear = useCallback(() => {
    setStreamed([]);
    setFresh(new Set());
  }, []);

  return { streamed, freshIds: fresh, clear };
}

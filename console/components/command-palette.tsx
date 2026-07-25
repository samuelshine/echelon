"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { NAV_ITEMS } from "@/components/nav";
import { toggleTheme } from "@/lib/theme";
import { useFocusTrap } from "@/lib/hooks/useFocusTrap";
import { cn } from "@/lib/cn";

interface Command {
  id: string;
  label: string;
  hint: string;
  group: string;
  run: () => void;
}

export function CommandPalette() {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const dialogRef = useRef<HTMLDivElement>(null);
  useFocusTrap(dialogRef, open);

  const commands: Command[] = useMemo(() => {
    const nav: Command[] = NAV_ITEMS.map((item) => ({
      id: `nav-${item.href}`,
      label: `Go to ${item.label}`,
      hint: item.description,
      group: "Navigate",
      run: () => router.push(item.href),
    }));
    return [
      ...nav,
      {
        id: "logs-blocked",
        label: "View blocked prompts",
        hint: "Open the Threat Audit log",
        group: "Navigate",
        run: () => router.push("/logs"),
      },
      {
        id: "theme",
        label: "Toggle light / dark theme",
        hint: "Switch the console theme",
        group: "Preferences",
        run: () => toggleTheme(),
      },
    ];
  }, [router]);

  const results = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return commands;
    return commands.filter(
      (c) => c.label.toLowerCase().includes(q) || c.hint.toLowerCase().includes(q),
    );
  }, [commands, query]);

  // Global ⌘K / Ctrl-K
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen((o) => !o);
      }
      if (e.key === "Escape") setOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  useEffect(() => {
    if (open) {
      setQuery("");
      setActive(0);
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [open]);

  useEffect(() => setActive(0), [query]);

  if (!open) return null;

  const run = (c: Command) => {
    c.run();
    setOpen(false);
  };

  return (
    <div
      className="fixed inset-0 z-[60] flex items-start justify-center bg-black/30 pt-[15vh]"
      onClick={() => setOpen(false)}
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-label="Command palette"
        onClick={(e) => e.stopPropagation()}
        onKeyDown={(e) => {
          if (e.key === "ArrowDown") {
            e.preventDefault();
            setActive((a) => Math.min(a + 1, results.length - 1));
          } else if (e.key === "ArrowUp") {
            e.preventDefault();
            setActive((a) => Math.max(a - 1, 0));
          } else if (e.key === "Enter" && results[active]) {
            e.preventDefault();
            run(results[active]);
          }
        }}
        className="w-full max-w-[560px] overflow-hidden rounded-[var(--radius-lg)] border border-[var(--color-line-strong)] bg-[var(--color-surface)] shadow-2xl"
      >
        <input
          ref={inputRef}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search commands…"
          className="w-full border-b border-[var(--color-line)] bg-transparent px-4 py-3.5 text-sm outline-none placeholder:text-[var(--color-faint)]"
        />
        <ul className="max-h-[320px] overflow-y-auto p-2">
          {results.length === 0 ? (
            <li className="px-3 py-6 text-center text-sm text-[var(--color-muted)]">
              No matching commands.
            </li>
          ) : (
            results.map((c, i) => (
              <li key={c.id}>
                <button
                  type="button"
                  onMouseEnter={() => setActive(i)}
                  onClick={() => run(c)}
                  className={cn(
                    "flex w-full items-center justify-between gap-4 rounded-[var(--radius)] px-3 py-2.5 text-left",
                    i === active ? "bg-[var(--color-brand-wash)]" : "",
                  )}
                >
                  <span>
                    <span className="text-sm">{c.label}</span>
                    <span className="ml-2 text-xs text-[var(--color-muted)]">{c.hint}</span>
                  </span>
                  <span className="eyebrow shrink-0">{c.group}</span>
                </button>
              </li>
            ))
          )}
        </ul>
        <div className="flex items-center gap-3 border-t border-[var(--color-line)] px-4 py-2 font-[family-name:var(--font-mono)] text-[10px] text-[var(--color-faint)]">
          <span>↑↓ navigate</span>
          <span>↵ run</span>
          <span>esc close</span>
        </div>
      </div>
    </div>
  );
}

"use client";

import { useState } from "react";

/** Minimal, dependency-free JSON syntax coloring for the drill-down. */
function highlight(json: string): string {
  return json
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(
      /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g,
      (match) => {
        let cls = "num";
        if (/^"/.test(match)) cls = /:$/.test(match) ? "key" : "str";
        else if (/true|false/.test(match)) cls = "bool";
        else if (/null/.test(match)) cls = "null";
        return `<span class="jt-${cls}">${match}</span>`;
      },
    );
}

export function RawJson({ data }: { data: unknown }) {
  const [open, setOpen] = useState(false);
  const json = JSON.stringify(data, null, 2);

  return (
    <div className="rounded-[var(--radius)] border border-[var(--color-line)]">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        className="flex w-full items-center gap-2 px-3 py-2.5 text-left"
      >
        <span
          className="font-[family-name:var(--font-mono)] text-xs text-[var(--color-muted)] transition-transform"
          style={{ transform: open ? "rotate(90deg)" : "none" }}
          aria-hidden
        >
          ▸
        </span>
        <span className="text-sm font-medium">Raw event JSON</span>
        <span className="ml-auto font-[family-name:var(--font-mono)] text-[11px] text-[var(--color-faint)]">
          {open ? "hide" : "show"}
        </span>
      </button>
      {open ? (
        <div className="overflow-x-auto border-t border-[var(--color-line)] bg-[var(--color-surface-sunken)] p-3">
          <pre className="font-[family-name:var(--font-mono)] text-[11.5px] leading-relaxed">
            <code dangerouslySetInnerHTML={{ __html: highlight(json) }} />
          </pre>
        </div>
      ) : null}
      <style>{`
        .jt-key { color: var(--color-brand-soft); }
        .jt-str { color: var(--color-pass); }
        .jt-num { color: var(--color-block); }
        .jt-bool { color: var(--color-flag); }
        .jt-null { color: var(--color-faint); }
      `}</style>
    </div>
  );
}

"use client";

import { useState } from "react";

export function CreateKeyBar({ onCreate }: { onCreate: (label: string) => void }) {
  const [label, setLabel] = useState("");

  const submit = () => {
    const trimmed = label.trim();
    if (!trimmed) return;
    onCreate(trimmed);
    setLabel("");
  };

  return (
    <div className="flex items-end gap-3 rounded-[var(--radius-lg)] border border-[var(--color-line)] bg-[var(--color-surface)] p-4">
      <label className="flex flex-1 flex-col gap-1">
        <span className="eyebrow">New key label</span>
        <input
          value={label}
          onChange={(e) => setLabel(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && submit()}
          placeholder="e.g. Production — Analytics service"
          className="h-9 rounded-[var(--radius)] border border-[var(--color-line-strong)] bg-[var(--color-surface)] px-3 text-sm focus-visible:outline-2 focus-visible:outline-[var(--color-brand)]"
        />
      </label>
      <button
        type="button"
        onClick={submit}
        disabled={!label.trim()}
        className="h-9 rounded-[var(--radius)] bg-[var(--color-brand)] px-4 text-sm font-medium text-white hover:brightness-110 disabled:opacity-40"
      >
        Create key
      </button>
    </div>
  );
}

/** Reveal-once row: the full secret is shown exactly once, then never again. */
export function RevealBanner({
  secret,
  label,
  onDismiss,
}: {
  secret: string;
  label: string;
  onDismiss: () => void;
}) {
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(secret);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  };

  return (
    <div className="rounded-[var(--radius-lg)] border-2 border-[var(--color-brand)] bg-[var(--color-brand-wash)] p-5">
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="eyebrow" style={{ color: "var(--color-brand)" }}>
            New key created · {label}
          </div>
          <div className="mt-2 flex items-center gap-3">
            <code className="rounded-[var(--radius)] border border-[var(--color-line-strong)] bg-[var(--color-surface)] px-3 py-2 font-[family-name:var(--font-mono)] text-sm">
              {secret}
            </code>
            <button
              type="button"
              onClick={copy}
              className="rounded-[var(--radius)] bg-[var(--color-brand)] px-3 py-2 text-xs font-medium text-white hover:brightness-110"
            >
              {copied ? "Copied ✓" : "Copy"}
            </button>
          </div>
          <p className="mt-3 flex items-center gap-2 text-xs text-[var(--color-ink-soft)]">
            <span aria-hidden style={{ color: "var(--color-flag)" }}>
              ⚠
            </span>
            Copy this secret now — for your security, Echelon won&apos;t show it again.
            Only the last four characters are stored.
          </p>
        </div>
        <button
          type="button"
          onClick={onDismiss}
          aria-label="Dismiss"
          className="rounded-[var(--radius)] px-2 py-1 text-[var(--color-muted)] hover:bg-[var(--color-surface)]"
        >
          ✕
        </button>
      </div>
    </div>
  );
}

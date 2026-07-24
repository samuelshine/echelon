"use client";

import { useState } from "react";
import { cn } from "@/lib/cn";
import { formatCredits, formatInt, formatRelativeTime } from "@/lib/format";
import { UsageSparkline } from "./usage-sparkline";
import type { ApiKey } from "@/types/echelon";

function StatusChip({ status }: { status: ApiKey["status"] }) {
  const active = status === "active";
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[11px] font-medium"
      style={{
        background: active ? "var(--color-pass-wash)" : "var(--color-surface-sunken)",
        color: active ? "var(--color-pass)" : "var(--color-faint)",
      }}
    >
      <span aria-hidden>{active ? "●" : "○"}</span>
      {active ? "Active" : "Revoked"}
    </span>
  );
}

function Metric({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="eyebrow">{label}</div>
      <div className="mt-1.5 text-sm">{children}</div>
    </div>
  );
}

export function KeyCard({
  apiKey,
  onUpdate,
  onRevoke,
}: {
  apiKey: ApiKey;
  onUpdate: (k: ApiKey) => void;
  onRevoke: (id: string) => void;
}) {
  const [editing, setEditing] = useState(false);
  const [confirmRevoke, setConfirmRevoke] = useState(false);
  const [rpm, setRpm] = useState(apiKey.rateLimitRpm);
  const [budget, setBudget] = useState(apiKey.creditBudget);

  const revoked = apiKey.status === "revoked";
  const usedPct = apiKey.creditBudget ? apiKey.creditsUsed / apiKey.creditBudget : 0;
  const nearLimit = usedPct >= 0.85;

  const saveEdit = () => {
    onUpdate({ ...apiKey, rateLimitRpm: rpm, creditBudget: budget });
    setEditing(false);
  };

  return (
    <div
      className="rounded-[var(--radius-lg)] border border-[var(--color-line)] bg-[var(--color-surface)] p-5"
      style={revoked ? { opacity: 0.62 } : undefined}
    >
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h3 className="text-sm font-medium">{apiKey.label}</h3>
            <StatusChip status={apiKey.status} />
          </div>
          <div className="mt-1 font-[family-name:var(--font-mono)] text-xs text-[var(--color-muted)]">
            sk_live_••••••••{apiKey.last4}
          </div>
        </div>
        {!revoked ? (
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setEditing((e) => !e)}
              className="rounded-[var(--radius)] border border-[var(--color-line-strong)] px-3 py-1.5 text-xs text-[var(--color-ink-soft)] hover:bg-[var(--color-surface-sunken)]"
            >
              {editing ? "Cancel" : "Edit limits"}
            </button>
            <button
              type="button"
              onClick={() => setConfirmRevoke(true)}
              className="rounded-[var(--radius)] border border-[var(--color-block)] px-3 py-1.5 text-xs text-[var(--color-block)] hover:bg-[var(--color-block-wash)]"
            >
              Revoke
            </button>
          </div>
        ) : null}
      </div>

      {/* Metrics */}
      <div className="mt-5 grid grid-cols-2 gap-5 sm:grid-cols-4">
        <Metric label="Credit usage">
          <div className="font-[family-name:var(--font-mono)] text-xs">
            {formatCredits(apiKey.creditsUsed)} / {formatCredits(apiKey.creditBudget)}
          </div>
          <div className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-[var(--color-surface-sunken)]">
            <div
              className="h-full rounded-full"
              style={{
                width: `${Math.min(usedPct * 100, 100)}%`,
                background: nearLimit ? "var(--color-flag)" : "var(--color-brand)",
              }}
            />
          </div>
        </Metric>
        <Metric label="Recent usage">
          <UsageSparkline seed={apiKey.id} />
        </Metric>
        <Metric label="Rate limit">
          {editing ? (
            <input
              type="number"
              value={rpm}
              min={1}
              onChange={(e) => setRpm(Number(e.target.value))}
              className="w-24 rounded-[var(--radius)] border border-[var(--color-line-strong)] bg-[var(--color-surface)] px-2 py-1 font-[family-name:var(--font-mono)] text-xs"
            />
          ) : (
            <span className="font-[family-name:var(--font-mono)] text-xs">
              {formatInt(apiKey.rateLimitRpm)} <span className="text-[var(--color-faint)]">req/min</span>
            </span>
          )}
        </Metric>
        <Metric label={editing ? "Credit budget" : "Last used"}>
          {editing ? (
            <input
              type="number"
              value={budget}
              min={0}
              step={1000}
              onChange={(e) => setBudget(Number(e.target.value))}
              className="w-28 rounded-[var(--radius)] border border-[var(--color-line-strong)] bg-[var(--color-surface)] px-2 py-1 font-[family-name:var(--font-mono)] text-xs"
            />
          ) : (
            <span className="font-[family-name:var(--font-mono)] text-xs text-[var(--color-muted)]">
              {apiKey.lastUsedAt ? formatRelativeTime(apiKey.lastUsedAt) : "never"}
            </span>
          )}
        </Metric>
      </div>

      {editing ? (
        <div className="mt-4 flex justify-end gap-2 border-t border-[var(--color-line)] pt-4">
          <button
            type="button"
            onClick={saveEdit}
            className="rounded-[var(--radius)] bg-[var(--color-brand)] px-4 py-1.5 text-xs font-medium text-white hover:brightness-110"
          >
            Save limits
          </button>
        </div>
      ) : null}

      {/* Destructive-action confirmation */}
      {confirmRevoke ? (
        <div className="mt-4 flex items-center justify-between gap-4 rounded-[var(--radius)] border border-[var(--color-block)] bg-[var(--color-block-wash)] p-4">
          <div className="text-xs leading-relaxed text-[var(--color-ink-soft)]">
            <span className="font-medium text-[var(--color-block)]">Revoke this key?</span>{" "}
            Any application still using it will be rejected immediately. This can&apos;t be undone.
          </div>
          <div className="flex shrink-0 gap-2">
            <button
              type="button"
              onClick={() => setConfirmRevoke(false)}
              className="rounded-[var(--radius)] border border-[var(--color-line-strong)] bg-[var(--color-surface)] px-3 py-1.5 text-xs"
            >
              Keep it
            </button>
            <button
              type="button"
              onClick={() => {
                onRevoke(apiKey.id);
                setConfirmRevoke(false);
              }}
              className={cn(
                "rounded-[var(--radius)] bg-[var(--color-block)] px-3 py-1.5 text-xs font-medium text-white hover:brightness-110",
              )}
            >
              Revoke key
            </button>
          </div>
        </div>
      ) : null}
    </div>
  );
}

"use client";

import { useEffect, useState } from "react";
import { PageHeader } from "@/components/page-header";
import { KeyCard } from "@/components/keys/key-card";
import { CreateKeyBar, RevealBanner } from "@/components/keys/create-key";
import { useApiKeys } from "@/lib/hooks/useEchelon";
import { createApiKey, revokeApiKey, updateApiKeyLimits } from "@/lib/api/client";
import type { ApiKey } from "@/types/echelon";

function InlineError({ message, onDismiss }: { message: string; onDismiss: () => void }) {
  return (
    <div className="flex items-start justify-between gap-4 rounded-[var(--radius-lg)] border border-[var(--color-block)] bg-[var(--color-block-wash)] p-4">
      <div className="text-xs leading-relaxed text-[var(--color-ink-soft)]">
        <span className="font-medium text-[var(--color-block)]">Action failed.</span> {message}
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
  );
}

export default function KeysPage() {
  const { data: loaded } = useApiKeys();
  const [keys, setKeys] = useState<ApiKey[] | null>(null);
  const [reveal, setReveal] = useState<{ secret: string; label: string } | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (loaded && !keys) setKeys(loaded);
  }, [loaded, keys]);

  const createKey = async (label: string) => {
    setError(null);
    try {
      const { key, secret } = await createApiKey(label);
      // Prepend the real returned key and show the real, one-time secret.
      setKeys((ks) => [key, ...(ks ?? [])]);
      setReveal({ secret, label: key.label });
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not create the key.");
    }
  };

  const updateKey = async (updated: ApiKey) => {
    setError(null);
    const prev = keys;
    // Optimistic update, then roll back on failure.
    setKeys((ks) => ks?.map((k) => (k.id === updated.id ? updated : k)) ?? null);
    try {
      const saved = await updateApiKeyLimits(updated.id, updated.rateLimitRpm, updated.creditBudget);
      setKeys((ks) => ks?.map((k) => (k.id === saved.id ? saved : k)) ?? null);
    } catch (e) {
      setKeys(prev);
      setError(e instanceof Error ? e.message : "Could not update the key.");
    }
  };

  const revokeKey = async (id: string) => {
    setError(null);
    const prev = keys;
    setKeys((ks) => ks?.map((k) => (k.id === id ? { ...k, status: "revoked" } : k)) ?? null);
    try {
      const saved = await revokeApiKey(id);
      setKeys((ks) => ks?.map((k) => (k.id === saved.id ? saved : k)) ?? null);
    } catch (e) {
      setKeys(prev);
      setError(e instanceof Error ? e.message : "Could not revoke the key.");
    }
  };

  const activeCount = keys?.filter((k) => k.status === "active").length ?? 0;

  return (
    <>
      <PageHeader eyebrow="Module 03 · Gateway" title="Access">
        <span className="rounded-full border border-[var(--color-line-strong)] px-3 py-1 text-xs text-[var(--color-muted)]">
          {activeCount} active {activeCount === 1 ? "key" : "keys"}
        </span>
      </PageHeader>

      <div className="max-w-4xl space-y-4 p-8">
        <CreateKeyBar onCreate={createKey} />

        {error ? <InlineError message={error} onDismiss={() => setError(null)} /> : null}

        {reveal ? (
          <RevealBanner
            secret={reveal.secret}
            label={reveal.label}
            onDismiss={() => setReveal(null)}
          />
        ) : null}

        {!keys ? (
          <div className="h-64 animate-pulse rounded-[var(--radius-lg)] bg-[var(--color-surface-sunken)]" />
        ) : (
          <div className="space-y-3">
            {keys.map((k) => (
              <KeyCard key={k.id} apiKey={k} onUpdate={updateKey} onRevoke={revokeKey} />
            ))}
          </div>
        )}
      </div>
    </>
  );
}

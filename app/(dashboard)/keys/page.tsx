"use client";

import { useEffect, useState } from "react";
import { PageHeader } from "@/components/page-header";
import { KeyCard } from "@/components/keys/key-card";
import { CreateKeyBar, RevealBanner } from "@/components/keys/create-key";
import { useApiKeys } from "@/lib/hooks/useEchelon";
import type { ApiKey } from "@/types/echelon";

function generateSecret(): { secret: string; last4: string } {
  const hex = "0123456789abcdef";
  let body = "";
  for (let i = 0; i < 32; i++) body += hex[Math.floor(Math.random() * 16)];
  return { secret: `sk_live_${body}`, last4: body.slice(-4) };
}

export default function KeysPage() {
  const { data: loaded } = useApiKeys();
  const [keys, setKeys] = useState<ApiKey[] | null>(null);
  const [reveal, setReveal] = useState<{ secret: string; label: string } | null>(null);

  useEffect(() => {
    if (loaded && !keys) setKeys(loaded);
  }, [loaded, keys]);

  const createKey = (label: string) => {
    const { secret, last4 } = generateSecret();
    const newKey: ApiKey = {
      id: `key_${Date.now().toString(36)}`,
      label,
      last4,
      createdAt: new Date().toISOString(),
      status: "active",
      rateLimitRpm: 1000,
      creditBudget: 100_000,
      creditsUsed: 0,
    };
    setKeys((ks) => [newKey, ...(ks ?? [])]);
    setReveal({ secret, label });
  };

  const updateKey = (updated: ApiKey) =>
    setKeys((ks) => ks?.map((k) => (k.id === updated.id ? updated : k)) ?? null);

  const revokeKey = (id: string) =>
    setKeys((ks) => ks?.map((k) => (k.id === id ? { ...k, status: "revoked" } : k)) ?? null);

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

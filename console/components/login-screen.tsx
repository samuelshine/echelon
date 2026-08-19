"use client";

import { useState } from "react";
import { useAuth } from "@/components/auth-provider";
import { devFallbackToken } from "@/lib/auth/session";

/**
 * Gate shown to any unauthenticated visitor in place of the dashboard (see
 * app/(dashboard)/layout.tsx). Takes the shared operator token, verifies it
 * against the live gateway, and hands off to AuthProvider to store it.
 *
 * This is not an account login: there is one credential, shared by every
 * operator, and this screen exists to stop it from being handed to a browser
 * tab for free — not to identify who is signing in.
 */
export function LoginScreen() {
  const { login } = useAuth();
  const [token, setToken] = useState("");
  // Present only in a local build that baked NEXT_PUBLIC_ECHELON_CONSOLE_TOKEN
  // in (i.e. scripts/run-local.sh). A real deployment leaves that unset, so
  // this whole affordance disappears rather than being something to remember
  // to turn off.
  const devToken = devFallbackToken();
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  const submit = async () => {
    if (!token.trim() || pending) return;
    setPending(true);
    setError(null);
    const result = await login(token);
    setPending(false);
    if (!result.ok) setError(result.message);
  };

  return (
    <div className="flex h-screen items-center justify-center bg-[var(--color-canvas)] px-4">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex items-center gap-3">
          <div
            aria-hidden
            className="grid h-10 w-10 place-items-center rounded-[var(--radius)] bg-[var(--color-brand)] text-[var(--color-surface)]"
          >
            <span className="font-[family-name:var(--font-display)] text-xl leading-none">
              E
            </span>
          </div>
          <div className="leading-tight">
            <div className="font-[family-name:var(--font-display)] text-xl tracking-tight">
              Echelon
            </div>
            <div className="eyebrow">Security Console</div>
          </div>
        </div>

        <form
          className="rounded-[var(--radius-lg)] border border-[var(--color-line)] bg-[var(--color-surface)] p-6"
          onSubmit={(e) => {
            e.preventDefault();
            submit();
          }}
        >
          <div className="eyebrow">Operator access</div>
          <h1 className="mt-1 font-[family-name:var(--font-display)] text-2xl tracking-tight">
            Sign in
          </h1>
          <p className="mt-2 text-sm leading-relaxed text-[var(--color-muted)]">
            This token is a shared operator credential, not a personal account.
            Anyone holding it can mint API keys and change security thresholds —
            treat it like a root password.
          </p>

          <label className="mt-5 flex flex-col gap-1">
            <span className="eyebrow">Operator token</span>
            <input
              type="password"
              autoComplete="off"
              autoFocus
              value={token}
              onChange={(e) => setToken(e.target.value)}
              placeholder="sk-console-…"
              aria-invalid={error ? true : undefined}
              className="h-10 rounded-[var(--radius)] border border-[var(--color-line-strong)] bg-[var(--color-surface)] px-3 font-[family-name:var(--font-mono)] text-sm focus-visible:outline-2 focus-visible:outline-[var(--color-brand)]"
            />
          </label>

          {error ? (
            <div
              role="alert"
              className="mt-3 rounded-[var(--radius)] border border-[var(--color-block)] bg-[var(--color-block-wash)] px-3 py-2 text-xs leading-relaxed text-[var(--color-ink-soft)]"
            >
              <span className="font-medium text-[var(--color-block)]">Sign-in failed.</span>{" "}
              {error}
            </div>
          ) : null}

          <button
            type="submit"
            disabled={!token.trim() || pending}
            className="mt-4 h-10 w-full rounded-[var(--radius)] bg-[var(--color-brand)] text-sm font-medium text-white hover:brightness-110 disabled:opacity-40"
          >
            {pending ? "Verifying…" : "Sign in"}
          </button>
        </form>

        {devToken ? (
          <div className="mt-4 rounded-[var(--radius)] border border-dashed border-[var(--color-line-strong)] px-3 py-2.5">
            <div className="eyebrow text-[var(--color-muted)]">Local development</div>
            <p className="mt-1 text-xs leading-relaxed text-[var(--color-muted)]">
              This build has a demo token baked in, so it is already readable in
              the page source. Use it to sign back in:
            </p>
            <button
              type="button"
              onClick={() => {
                setToken(devToken);
                setError(null);
              }}
              className="mt-2 w-full truncate rounded-[var(--radius-sm)] bg-[var(--color-surface-sunken)] px-2 py-1.5 text-left font-[family-name:var(--font-mono)] text-xs text-[var(--color-ink-soft)] hover:bg-[var(--color-brand-wash)]"
            >
              {devToken}
            </button>
          </div>
        ) : null}

        <p className="mt-4 text-center text-xs text-[var(--color-faint)]">
          Held only for this browser tab session — closing the browser signs you out.
        </p>
      </div>
    </div>
  );
}

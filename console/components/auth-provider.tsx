"use client";

import { createContext, useCallback, useContext, useSyncExternalStore } from "react";
import { verifyConsoleToken } from "@/lib/api/client";
import {
  clearSessionToken,
  getEffectiveConsoleToken,
  setSessionToken,
  subscribeSessionToken,
} from "@/lib/auth/session";

export type LoginResult = { ok: true } | { ok: false; message: string };

interface AuthContextValue {
  /** Is there a credential to send right now — a logged-in session, or an
   *  unrevoked NEXT_PUBLIC_ECHELON_CONSOLE_TOKEN fallback? Gates dashboard vs
   *  login screen; see app/(dashboard)/layout.tsx. */
  authenticated: boolean;
  /** Verifies the token against the gateway and, if valid, starts the session. */
  login: (token: string) => Promise<LoginResult>;
  /** Clears the session and forces the login screen, even in a build that has
   *  NEXT_PUBLIC_ECHELON_CONSOLE_TOKEN baked in. */
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

// getServerSnapshot must return the same value the client sees on first render
// (there is no sessionStorage on the server) so hydration doesn't warn/mismatch;
// useSyncExternalStore re-syncs to the real client value right after mount.
function getServerSnapshot() {
  return null;
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  // getEffectiveConsoleToken() already folds in the session token, the env-var
  // fallback, and the sign-out suppression of that fallback — see its doc
  // comment in lib/auth/session.ts. "Authenticated" just means it isn't null.
  const effectiveToken = useSyncExternalStore(
    subscribeSessionToken,
    getEffectiveConsoleToken,
    getServerSnapshot,
  );
  const authenticated = effectiveToken !== null;

  const login = useCallback(async (token: string): Promise<LoginResult> => {
    const trimmed = token.trim();
    if (!trimmed) return { ok: false, message: "Enter the operator token." };

    const result = await verifyConsoleToken(trimmed);
    if (result === "valid") {
      setSessionToken(trimmed);
      return { ok: true };
    }
    if (result === "invalid") {
      return { ok: false, message: "The gateway rejected that token." };
    }
    return { ok: false, message: "Could not reach the Echelon gateway to verify the token." };
  }, []);

  const logout = useCallback(() => {
    clearSessionToken(/* explicit */ true);
  }, []);

  return (
    <AuthContext.Provider value={{ authenticated, login, logout }}>{children}</AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth() must be called within an AuthProvider");
  return ctx;
}

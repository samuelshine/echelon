import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * lib/auth/session.ts holds the operator's console credential: the token they
 * logged in with (sessionStorage, never localStorage) falling back to the
 * NEXT_PUBLIC_ECHELON_CONSOLE_TOKEN baked in at build time — unless they
 * explicitly signed out, which must suppress that fallback (see the module's
 * doc comment).
 *
 * NEXT_PUBLIC_ECHELON_CONSOLE_TOKEN is read into a module-level constant at
 * import time (same reason as lib/api/console-auth.test.ts), so each case sets
 * the env var and re-imports the module fresh.
 */
const ORIGINAL_ENV_TOKEN = process.env.NEXT_PUBLIC_ECHELON_CONSOLE_TOKEN;

async function importSession(envToken?: string) {
  if (envToken === undefined) delete process.env.NEXT_PUBLIC_ECHELON_CONSOLE_TOKEN;
  else process.env.NEXT_PUBLIC_ECHELON_CONSOLE_TOKEN = envToken;
  vi.resetModules();
  return import("./session");
}

beforeEach(() => {
  window.sessionStorage.clear();
  vi.resetModules();
});

afterEach(() => {
  if (ORIGINAL_ENV_TOKEN === undefined) delete process.env.NEXT_PUBLIC_ECHELON_CONSOLE_TOKEN;
  else process.env.NEXT_PUBLIC_ECHELON_CONSOLE_TOKEN = ORIGINAL_ENV_TOKEN;
  window.sessionStorage.clear();
  vi.resetModules();
});

describe("session token storage", () => {
  it("has no session token before login", async () => {
    const { getSessionToken } = await importSession(undefined);
    expect(getSessionToken()).toBeNull();
  });

  it("setSessionToken stores the token and is readable back", async () => {
    const { getSessionToken, setSessionToken } = await importSession(undefined);
    setSessionToken("op-secret");
    expect(getSessionToken()).toBe("op-secret");
  });

  it("persists the token in sessionStorage, not localStorage", async () => {
    const { setSessionToken } = await importSession(undefined);
    setSessionToken("op-secret");
    expect(window.sessionStorage.getItem("echelon.console.session-token")).toBe("op-secret");
    // This jsdom test environment doesn't even provide localStorage; guard so the
    // assertion is meaningful wherever it does, without crashing where it doesn't.
    if (typeof window.localStorage !== "undefined") {
      expect(window.localStorage.getItem("echelon.console.session-token")).toBeNull();
    }
  });

  it("clearSessionToken removes it from state and storage", async () => {
    const { getSessionToken, setSessionToken, clearSessionToken } = await importSession(undefined);
    setSessionToken("op-secret");
    clearSessionToken();
    expect(getSessionToken()).toBeNull();
    expect(window.sessionStorage.getItem("echelon.console.session-token")).toBeNull();
  });

  it("a fresh module import picks up a token already in sessionStorage", async () => {
    window.sessionStorage.setItem("echelon.console.session-token", "carried-over");
    const { getSessionToken } = await importSession(undefined);
    expect(getSessionToken()).toBe("carried-over");
  });

  it("notifies subscribers on login and on clear", async () => {
    const { setSessionToken, clearSessionToken, subscribeSessionToken } =
      await importSession(undefined);
    const listener = vi.fn();
    const unsubscribe = subscribeSessionToken(listener);

    setSessionToken("op-secret");
    expect(listener).toHaveBeenCalledTimes(1);

    clearSessionToken();
    expect(listener).toHaveBeenCalledTimes(2);

    unsubscribe();
    setSessionToken("another");
    expect(listener).toHaveBeenCalledTimes(2);
  });
});

describe("env-var fallback", () => {
  it("hasEnvFallbackToken reflects whether NEXT_PUBLIC_ECHELON_CONSOLE_TOKEN is set", async () => {
    expect((await importSession("dev-token")).hasEnvFallbackToken()).toBe(true);
    expect((await importSession(undefined)).hasEnvFallbackToken()).toBe(false);
  });

  it("getEffectiveConsoleToken falls back to the env token with no session token set", async () => {
    const { getEffectiveConsoleToken } = await importSession("dev-token");
    expect(getEffectiveConsoleToken()).toBe("dev-token");
  });

  it("getEffectiveConsoleToken prefers the logged-in session token over the env fallback", async () => {
    const { getEffectiveConsoleToken, setSessionToken } = await importSession("dev-token");
    setSessionToken("op-secret");
    expect(getEffectiveConsoleToken()).toBe("op-secret");
  });

  it("getEffectiveConsoleToken is null with neither a session token nor an env token", async () => {
    const { getEffectiveConsoleToken } = await importSession(undefined);
    expect(getEffectiveConsoleToken()).toBeNull();
  });

  it("isAuthenticated is true purely from the env fallback (run-local.sh demo mode)", async () => {
    const { isAuthenticated } = await importSession("dev-token");
    expect(isAuthenticated()).toBe(true);
  });

  it("a non-explicit clear (401 path) leaves the env fallback usable", async () => {
    const { getEffectiveConsoleToken, setSessionToken, clearSessionToken } =
      await importSession("dev-token");
    setSessionToken("op-secret");
    clearSessionToken(); // explicit defaults to false, e.g. the 401 handler in client.ts
    expect(getEffectiveConsoleToken()).toBe("dev-token");
  });

  it("an explicit sign-out suppresses the env fallback for the rest of the session", async () => {
    const { getEffectiveConsoleToken, isAuthenticated, setSessionToken, clearSessionToken } =
      await importSession("dev-token");
    setSessionToken("op-secret");
    clearSessionToken(true);
    expect(getEffectiveConsoleToken()).toBeNull();
    expect(isAuthenticated()).toBe(false);
  });

  it("logging back in after an explicit sign-out re-enables the session (fallback stays suppressed only until then)", async () => {
    const { getEffectiveConsoleToken, setSessionToken, clearSessionToken } =
      await importSession("dev-token");
    clearSessionToken(true);
    expect(getEffectiveConsoleToken()).toBeNull();

    setSessionToken("new-op-secret");
    expect(getEffectiveConsoleToken()).toBe("new-op-secret");
  });

  it("persists the sign-out suppression across a module reload within the same tab", async () => {
    const first = await importSession("dev-token");
    first.setSessionToken("op-secret");
    first.clearSessionToken(true);

    const second = await importSession("dev-token");
    expect(second.getEffectiveConsoleToken()).toBeNull();
  });
});

describe("devFallbackToken", () => {
  it("returns the baked-in token so the login screen can offer it in local dev", async () => {
    process.env.NEXT_PUBLIC_ECHELON_CONSOLE_TOKEN = "local-dev-operator-token";
    vi.resetModules();
    const { devFallbackToken } = await import("./session");
    expect(devFallbackToken()).toBe("local-dev-operator-token");
  });

  it("returns null when no token was baked in, so the shortcut disappears in a real deployment", async () => {
    delete process.env.NEXT_PUBLIC_ECHELON_CONSOLE_TOKEN;
    vi.resetModules();
    const { devFallbackToken } = await import("./session");
    expect(devFallbackToken()).toBeNull();
  });
});

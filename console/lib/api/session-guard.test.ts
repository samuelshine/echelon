import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * A 401 from the gateway means the operator token was revoked or rotated
 * server-side. lib/api/client.ts must clear the stored session token whenever
 * that happens — including for the read endpoints (fetchApiKeys, etc.), whose
 * try/catch quietly falls back to mock data so the dashboard doesn't blank out.
 * That fallback must not hide the fact that the session is no longer valid;
 * this file asserts the clear happens as a side effect regardless of whether
 * the caller ends up throwing or swallowing the error.
 *
 * Both NEXT_PUBLIC_ECHELON_API_URL and NEXT_PUBLIC_ECHELON_CONSOLE_TOKEN are
 * read into module-level constants at import time (client.ts and
 * lib/auth/session.ts respectively), so each case sets env vars and re-imports
 * both modules fresh — same pattern as lib/api/console-auth.test.ts.
 */
const ORIGINAL_API_URL = process.env.NEXT_PUBLIC_ECHELON_API_URL;
const ORIGINAL_CONSOLE_TOKEN = process.env.NEXT_PUBLIC_ECHELON_CONSOLE_TOKEN;

async function freshImports() {
  vi.resetModules();
  const session = await import("@/lib/auth/session");
  const client = await import("@/lib/api/client");
  return { session, client };
}

function jsonResponse(body: unknown, status: number) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

beforeEach(() => {
  window.sessionStorage.clear();
  process.env.NEXT_PUBLIC_ECHELON_API_URL = "https://gw.example.com";
  delete process.env.NEXT_PUBLIC_ECHELON_CONSOLE_TOKEN;
});

afterEach(() => {
  if (ORIGINAL_API_URL === undefined) delete process.env.NEXT_PUBLIC_ECHELON_API_URL;
  else process.env.NEXT_PUBLIC_ECHELON_API_URL = ORIGINAL_API_URL;
  if (ORIGINAL_CONSOLE_TOKEN === undefined) delete process.env.NEXT_PUBLIC_ECHELON_CONSOLE_TOKEN;
  else process.env.NEXT_PUBLIC_ECHELON_CONSOLE_TOKEN = ORIGINAL_CONSOLE_TOKEN;
  window.sessionStorage.clear();
  vi.unstubAllGlobals();
  vi.resetModules();
});

describe("401 clears the session (mutations)", () => {
  it("clears the session token on a 401 and still throws", async () => {
    const { session, client } = await freshImports();
    session.setSessionToken("op-secret");
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse({}, 401)));

    await expect(client.createApiKey("test key")).rejects.toThrow(/HTTP 401/);
    expect(session.getSessionToken()).toBeNull();
  });

  it("leaves the session token alone on success", async () => {
    const { session, client } = await freshImports();
    session.setSessionToken("op-secret");
    const key = {
      id: "key_1",
      label: "test key",
      last4: "ab12",
      createdAt: new Date().toISOString(),
      status: "active",
      rateLimitRpm: 60,
      creditBudget: 1000,
      creditsUsed: 0,
    };
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(jsonResponse({ key, secret: "sk-live-abc" }, 200)),
    );

    await client.createApiKey("test key");
    expect(session.getSessionToken()).toBe("op-secret");
  });
});

describe("401 clears the session (reads that fall back to mock data)", () => {
  it("clears the session token on a 401 even though fetchApiKeys resolves with mock data instead of throwing", async () => {
    const { session, client } = await freshImports();
    session.setSessionToken("op-secret");
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse({}, 401)));

    const keys = await client.fetchApiKeys();
    expect(keys.length).toBeGreaterThan(0); // fell back to mock data, did not throw
    expect(session.getSessionToken()).toBeNull();
  });

  it("clears the session token on a 401 from fetchDashboardSummary too", async () => {
    const { session, client } = await freshImports();
    session.setSessionToken("op-secret");
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse({}, 401)));

    await client.fetchDashboardSummary(); // resolves via mock fallback, does not throw
    expect(session.getSessionToken()).toBeNull();
  });

  it("does not clear the session token on a successful read", async () => {
    const { session, client } = await freshImports();
    session.setSessionToken("op-secret");
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse([], 200)));

    await client.fetchApiKeys();
    expect(session.getSessionToken()).toBe("op-secret");
  });

  it("a 401 while only the env-var fallback is in use leaves nothing to clear", async () => {
    process.env.NEXT_PUBLIC_ECHELON_CONSOLE_TOKEN = "dev-token";
    const { session, client } = await freshImports();
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse({}, 401)));

    await client.fetchApiKeys();
    expect(session.getSessionToken()).toBeNull(); // was never set — no-op, no crash
    expect(session.getEffectiveConsoleToken()).toBe("dev-token"); // fallback untouched
  });
});

describe("verifyConsoleToken (login screen check)", () => {
  it("reports 'valid' on 200 without touching the stored session", async () => {
    const { session, client } = await freshImports();
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse({ totalCalls: 0 }, 200)));

    await expect(client.verifyConsoleToken("candidate")).resolves.toBe("valid");
    expect(session.getSessionToken()).toBeNull();
  });

  it("reports 'invalid' on 401", async () => {
    const { client } = await freshImports();
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse({}, 401)));

    await expect(client.verifyConsoleToken("wrong-token")).resolves.toBe("invalid");
  });

  it("reports 'unreachable' on a network failure", async () => {
    const { client } = await freshImports();
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("network down")));

    await expect(client.verifyConsoleToken("candidate")).resolves.toBe("unreachable");
  });

  it("reports 'unreachable' with no gateway URL configured", async () => {
    delete process.env.NEXT_PUBLIC_ECHELON_API_URL;
    const { client } = await freshImports();

    await expect(client.verifyConsoleToken("candidate")).resolves.toBe("unreachable");
  });

  it("sends the candidate token as the bearer credential, not the stored session's", async () => {
    const { session, client } = await freshImports();
    session.setSessionToken("stored-session-token");
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({}, 200));
    vi.stubGlobal("fetch", fetchMock);

    await client.verifyConsoleToken("candidate-token");
    const [, init] = fetchMock.mock.calls[0];
    expect(init.headers.Authorization).toBe("Bearer candidate-token");
  });
});

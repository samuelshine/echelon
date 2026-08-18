import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * The gateway requires an operator token on every /v1/console/* route. These
 * cover the client half: the token must actually be attached, and the SSE
 * carve-out must produce a URL the gateway will accept, since EventSource
 * cannot send headers.
 *
 * CONSOLE_TOKEN is read into a module-level constant at import time, so each
 * case sets the env and re-imports.
 */
const ORIGINAL = process.env.NEXT_PUBLIC_ECHELON_CONSOLE_TOKEN;

async function importClient(token?: string) {
  if (token === undefined) delete process.env.NEXT_PUBLIC_ECHELON_CONSOLE_TOKEN;
  else process.env.NEXT_PUBLIC_ECHELON_CONSOLE_TOKEN = token;
  vi.resetModules();
  return import("./client");
}

beforeEach(() => {
  vi.resetModules();
});

afterEach(() => {
  if (ORIGINAL === undefined) delete process.env.NEXT_PUBLIC_ECHELON_CONSOLE_TOKEN;
  else process.env.NEXT_PUBLIC_ECHELON_CONSOLE_TOKEN = ORIGINAL;
  vi.resetModules();
});

describe("consoleAuthHeaders", () => {
  it("sends the operator token as a bearer credential", async () => {
    const { consoleAuthHeaders } = await importClient("op-secret");
    expect(consoleAuthHeaders()).toEqual({ Authorization: "Bearer op-secret" });
  });

  it("sends no Authorization header when no token is configured", async () => {
    const { consoleAuthHeaders } = await importClient(undefined);
    expect(consoleAuthHeaders()).toEqual({});
  });
});

describe("withConsoleToken", () => {
  it("appends the token for EventSource, which cannot set headers", async () => {
    const { withConsoleToken } = await importClient("op-secret");
    expect(withConsoleToken("https://gw.example.com/v1/console/events/stream")).toBe(
      "https://gw.example.com/v1/console/events/stream?access_token=op-secret",
    );
  });

  it("preserves an existing query string", async () => {
    const { withConsoleToken } = await importClient("op-secret");
    expect(withConsoleToken("https://gw.example.com/v1/console/events/stream?since=5")).toBe(
      "https://gw.example.com/v1/console/events/stream?since=5&access_token=op-secret",
    );
  });

  it("percent-encodes a token containing URL-significant characters", async () => {
    const { withConsoleToken } = await importClient("a b&c=d");
    expect(withConsoleToken("https://gw.example.com/s")).toBe(
      "https://gw.example.com/s?access_token=a%20b%26c%3Dd",
    );
  });

  it("leaves the URL untouched when no token is configured", async () => {
    const { withConsoleToken } = await importClient(undefined);
    expect(withConsoleToken("https://gw.example.com/s")).toBe("https://gw.example.com/s");
  });
});

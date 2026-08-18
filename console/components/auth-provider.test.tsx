import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

/**
 * End-to-end coverage of the login gate: AuthProvider + LoginScreen together,
 * which is what app/(dashboard)/layout.tsx wires up in front of every dashboard
 * route. Covers the three behavioral requirements directly:
 *   1. unauthenticated -> login screen, not the protected content
 *   2. a verified token stores the session and reveals the protected content
 *   3. signing out clears it and returns to the login screen
 *
 * NEXT_PUBLIC_ECHELON_API_URL and NEXT_PUBLIC_ECHELON_CONSOLE_TOKEN are read
 * into module-level constants at import time (lib/api/client.ts and
 * lib/auth/session.ts), so each case sets env vars before a fresh dynamic
 * import — same pattern as lib/api/console-auth.test.ts and the "real SSE
 * transport" describe block in lib/hooks/useLiveTail.test.tsx.
 */
const ORIGINAL_API_URL = process.env.NEXT_PUBLIC_ECHELON_API_URL;
const ORIGINAL_CONSOLE_TOKEN = process.env.NEXT_PUBLIC_ECHELON_CONSOLE_TOKEN;

async function importAuth(opts: { apiUrl?: string; consoleToken?: string } = {}) {
  if (opts.apiUrl === undefined) delete process.env.NEXT_PUBLIC_ECHELON_API_URL;
  else process.env.NEXT_PUBLIC_ECHELON_API_URL = opts.apiUrl;
  if (opts.consoleToken === undefined) delete process.env.NEXT_PUBLIC_ECHELON_CONSOLE_TOKEN;
  else process.env.NEXT_PUBLIC_ECHELON_CONSOLE_TOKEN = opts.consoleToken;

  vi.resetModules();
  const { AuthProvider, useAuth } = await import("./auth-provider");
  const { LoginScreen } = await import("./login-screen");
  return { AuthProvider, useAuth, LoginScreen };
}

function jsonResponse(body: unknown, status: number) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

beforeEach(() => {
  window.sessionStorage.clear();
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

describe("auth gate", () => {
  it("shows the login screen, not protected content, with no session and no env fallback", async () => {
    const { AuthProvider, useAuth, LoginScreen } = await importAuth({
      apiUrl: "https://gw.example.com",
    });

    function Gate() {
      const { authenticated } = useAuth();
      return authenticated ? <div>Protected dashboard</div> : <LoginScreen />;
    }

    render(
      <AuthProvider>
        <Gate />
      </AuthProvider>,
    );

    expect(screen.getByRole("heading", { name: "Sign in" })).toBeInTheDocument();
    expect(screen.queryByText("Protected dashboard")).not.toBeInTheDocument();
  });

  it("shows protected content directly when the env-var fallback is configured (run-local.sh demo mode)", async () => {
    const { AuthProvider, useAuth, LoginScreen } = await importAuth({
      apiUrl: "https://gw.example.com",
      consoleToken: "dev-token",
    });

    function Gate() {
      const { authenticated } = useAuth();
      return authenticated ? <div>Protected dashboard</div> : <LoginScreen />;
    }

    render(
      <AuthProvider>
        <Gate />
      </AuthProvider>,
    );

    expect(screen.getByText("Protected dashboard")).toBeInTheDocument();
  });

  it("a verified token reveals the protected content and stores the session", async () => {
    const { AuthProvider, useAuth, LoginScreen } = await importAuth({
      apiUrl: "https://gw.example.com",
    });
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse({}, 200)));

    function Gate() {
      const { authenticated } = useAuth();
      return authenticated ? <div>Protected dashboard</div> : <LoginScreen />;
    }

    const user = userEvent.setup();
    render(
      <AuthProvider>
        <Gate />
      </AuthProvider>,
    );

    await user.type(screen.getByLabelText("Operator token"), "op-secret");
    await user.click(screen.getByRole("button", { name: "Sign in" }));

    await waitFor(() => expect(screen.getByText("Protected dashboard")).toBeInTheDocument());
    expect(window.sessionStorage.getItem("echelon.console.session-token")).toBe("op-secret");
  });

  it("a rejected token shows an error and stays on the login screen", async () => {
    const { AuthProvider, useAuth, LoginScreen } = await importAuth({
      apiUrl: "https://gw.example.com",
    });
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse({}, 401)));

    function Gate() {
      const { authenticated } = useAuth();
      return authenticated ? <div>Protected dashboard</div> : <LoginScreen />;
    }

    const user = userEvent.setup();
    render(
      <AuthProvider>
        <Gate />
      </AuthProvider>,
    );

    await user.type(screen.getByLabelText("Operator token"), "wrong-token");
    await user.click(screen.getByRole("button", { name: "Sign in" }));

    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent(/rejected/i));
    expect(screen.queryByText("Protected dashboard")).not.toBeInTheDocument();
  });

  it("signing out clears the session and returns to the login screen", async () => {
    const { AuthProvider, useAuth, LoginScreen } = await importAuth({
      apiUrl: "https://gw.example.com",
    });
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse({}, 200)));

    function Gate() {
      const { authenticated, logout } = useAuth();
      return authenticated ? (
        <div>
          Protected dashboard
          <button onClick={logout}>Sign out</button>
        </div>
      ) : (
        <LoginScreen />
      );
    }

    const user = userEvent.setup();
    render(
      <AuthProvider>
        <Gate />
      </AuthProvider>,
    );

    await user.type(screen.getByLabelText("Operator token"), "op-secret");
    await user.click(screen.getByRole("button", { name: "Sign in" }));
    await waitFor(() => expect(screen.getByText("Protected dashboard")).toBeInTheDocument());

    await user.click(screen.getByRole("button", { name: "Sign out" }));

    expect(screen.getByRole("heading", { name: "Sign in" })).toBeInTheDocument();
    expect(window.sessionStorage.getItem("echelon.console.session-token")).toBeNull();
  });

  it("signing out returns to the login screen even when the env-var fallback is configured", async () => {
    const { AuthProvider, useAuth, LoginScreen } = await importAuth({
      apiUrl: "https://gw.example.com",
      consoleToken: "dev-token",
    });

    function Gate() {
      const { authenticated, logout } = useAuth();
      return authenticated ? (
        <div>
          Protected dashboard
          <button onClick={logout}>Sign out</button>
        </div>
      ) : (
        <LoginScreen />
      );
    }

    const user = userEvent.setup();
    render(
      <AuthProvider>
        <Gate />
      </AuthProvider>,
    );

    expect(screen.getByText("Protected dashboard")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Sign out" }));
    expect(screen.getByRole("heading", { name: "Sign in" })).toBeInTheDocument();
  });
});

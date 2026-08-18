/**
 * Client-side storage for the operator's console session.
 *
 * Echelon's console has no per-user accounts: `/v1/console/*` on the gateway
 * accepts one shared bearer token (`CONSOLE_TOKEN` on the gateway,
 * `NEXT_PUBLIC_ECHELON_CONSOLE_TOKEN` baked into this app's build). Previously
 * that env var alone gated the whole console — it shipped to every browser in
 * the JS bundle, so anyone who loaded the page had full operator power (mint
 * keys, revoke keys, edit security thresholds) with no login step at all.
 *
 * This module adds an explicit login step in front of that same shared secret:
 * an operator types the token into the login screen (components/login-screen.tsx),
 * it gets verified against the gateway (see verifyConsoleToken in
 * lib/api/client.ts), and only then is it held in `sessionStorage` — never
 * `localStorage` — so it disappears the moment the browser closes, not just the
 * tab. To be clear about what this is NOT: it is still the same shared operator
 * secret, not a per-user identity system with real sessions, roles, or
 * server-side revocation lists. It just stops handing out operator power for
 * free to anyone who loads the URL.
 *
 * `NEXT_PUBLIC_ECHELON_CONSOLE_TOKEN`, if set at build time, remains as a
 * fallback so `scripts/run-local.sh` demos keep working without a manual login
 * step. An explicit "sign out" suppresses that fallback for the rest of the
 * browser session — otherwise sign-out would be a no-op in a build that has the
 * env var baked in, and the operator could never actually reach the login screen.
 */

const TOKEN_KEY = "echelon.console.session-token";
const SIGNED_OUT_KEY = "echelon.console.signed-out";

const ENV_FALLBACK_TOKEN = process.env.NEXT_PUBLIC_ECHELON_CONSOLE_TOKEN || null;

function storage(): Storage | null {
  if (typeof window === "undefined") return null;
  try {
    return window.sessionStorage;
  } catch {
    // Storage disabled (private browsing lockdown, org policy, etc). The session
    // still works for this page load via the in-memory cache below; it just
    // won't persist across a reload.
    return null;
  }
}

// In-memory mirror of sessionStorage. Lets reads stay synchronous and work even
// when storage() is unavailable, and gives React something to subscribe to
// (sessionStorage itself has no same-tab change event).
let cachedToken: string | null = null;
let cachedSignedOut = false;
let initialized = false;

function ensureInitialized() {
  if (initialized) return;
  initialized = true;
  const s = storage();
  cachedToken = s?.getItem(TOKEN_KEY) ?? null;
  cachedSignedOut = s?.getItem(SIGNED_OUT_KEY) === "1";
}

type Listener = () => void;
const listeners = new Set<Listener>();
function notify() {
  for (const l of listeners) l();
}

/** Subscribe to session changes (login, sign-out, or a 401-triggered clear). */
export function subscribeSessionToken(listener: Listener): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/** The token the operator explicitly logged in with this browser session, if any. */
export function getSessionToken(): string | null {
  ensureInitialized();
  return cachedToken;
}

function wasSignedOut(): boolean {
  ensureInitialized();
  return cachedSignedOut;
}

/** Called once the login screen has verified a token against the gateway. */
export function setSessionToken(token: string): void {
  ensureInitialized();
  cachedToken = token;
  cachedSignedOut = false;
  const s = storage();
  s?.setItem(TOKEN_KEY, token);
  s?.removeItem(SIGNED_OUT_KEY);
  notify();
}

/**
 * Clears the session token.
 *
 * Two callers, two meanings:
 *  - The "Sign out" control passes `explicit: true` — a deliberate logout that
 *    must also suppress the env-var fallback, or the operator would clear the
 *    token and land right back in an "authenticated" state.
 *  - The API client (lib/api/client.ts) calls this with no args on a 401 —
 *    the token was rejected server-side (revoked/rotated). That is not a
 *    deliberate sign-out, so the env-var fallback (if any) is left intact; in a
 *    build with no env var configured, clearing the session token alone is
 *    already enough to drop back to the login screen.
 */
export function clearSessionToken(explicit = false): void {
  ensureInitialized();
  cachedToken = null;
  const s = storage();
  s?.removeItem(TOKEN_KEY);
  if (explicit) {
    cachedSignedOut = true;
    s?.setItem(SIGNED_OUT_KEY, "1");
  }
  notify();
}

/**
 * The token to actually send on the wire: the operator's logged-in session
 * token if one is set, else the build-time env token — unless the operator
 * explicitly signed out this browser session, in which case neither applies
 * and the console has no credential until someone logs in again.
 */
export function getEffectiveConsoleToken(): string | null {
  const session = getSessionToken();
  if (session) return session;
  if (wasSignedOut()) return null;
  return ENV_FALLBACK_TOKEN;
}

/** Whether the console currently has a credential to send at all. */
export function isAuthenticated(): boolean {
  return getEffectiveConsoleToken() !== null;
}

/** Whether NEXT_PUBLIC_ECHELON_CONSOLE_TOKEN was baked into this build. */
export function hasEnvFallbackToken(): boolean {
  return ENV_FALLBACK_TOKEN !== null;
}

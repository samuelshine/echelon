# Echelon Frontend — Current Progress

_Last updated: 2026-08-05 · Phase 6 + Hardening pass — **complete & verified**; Phase 7 reads done 2026-07-25, mutations done 2026-08-04, server-side log filtering + real SSE live-tail done 2026-08-05_

---

## 🏁 Status: 7 of 7 phases done · all 4 core modules + live/polish + real backend wiring shipped
Reads (`lib/api/client.ts` against `/v1/console/*`) landed 2026-07-25. Key/config
**mutations** (create/revoke/re-limit a key, edit thresholds/toggles) were still
local-React-state-only until 2026-08-04, when the gateway grew a real mutable
key store and live-mutable cascade/pipeline config — `keys/page.tsx` and
`config/page.tsx` now call real `POST`/`PATCH`/`DELETE` endpoints with
optimistic UI + rollback on failure. The two remaining items never covered by an
earlier phase — server-side log filtering/pagination and a real SSE transport for
live-tail — both landed 2026-08-05 (see "Next Up" below). The only open console
item now is component-level (RTL/Playwright) tests.

## ✅ Just Done (Hardening pass)
- **Automated tests** — Vitest suite, **24 tests across 3 files**, all green:
  - `lib/whatif.test.ts` — the safety-critical guardrail: verdict recomputation, regression counting on raise/disable, zero on lower/no-change, clean prompts not counted as regressions.
  - `lib/logs.test.ts` — every filter facet + AND-combination + case-insensitive query + risk bands.
  - `lib/format.test.ts` — latency µs/ms boundary, percentages, scores, relative time.
- **Security** — added `overrides` for `sharp@^0.35.3` and `postcss@^8.5.22` (both were transitive-under-Next advisories npm could only "fix" by downgrading Next to v9). `npm audit` now reports **0 vulnerabilities**; build still passes.
- **Focus-traps** — `useFocusTrap` hook wired into the drill-down drawer and command palette so Tab cycles within the dialog.
- **Preview refreshed** — Artifact now shows the live-tail indicator + fresh-row highlight and an openable ⌘K command palette.
- **Verified**: `tsc` clean · `vitest` 24/24 · `next build` clean (6 routes) · 0 audit vulnerabilities.

## ✅ Just Done (Phase 6 — Live data & polish)
- **Live-tail** on the Threat Audit log: `useLiveTail` hook simulates a stream (new events every ~2.2s when on), abstracted so an `EventSource`/WebSocket swaps straight in. Header toggle shows a pulsing "Live · N streamed"; freshly-arrived rows get a green left-accent that fades after ~2.6s.
- **⌘K command palette** (`components/command-palette.tsx`): global shortcut, fuzzy filter, full keyboard nav (↑↓/↵/esc), grouped commands (navigate to each module + toggle theme). Mounted globally in the dashboard layout.
- **In-app theme toggle**: `lib/theme.ts` (localStorage-persisted) + a sidebar `ThemeToggle`; an inline `THEME_INIT_SCRIPT` in `<head>` restores the saved theme before paint (no flash), with `suppressHydrationWarning`.
- **a11y pass**: drawer moves focus to its close button on open (Esc already closed it); dialog/palette have `role`/`aria-modal`/labels; live-tail button is `aria-pressed`; `⌘K` shown as real `<kbd>`.
- **Verified**: `tsc` clean · `next build` clean (6 routes) · all routes 200 · theme init script, theme toggle, and live-tail control all present in served HTML · no runtime errors.

## 🐞 Known Issues / Risks
- **Live-tail / palette / theme-swap are runtime behaviors** not capturable by curl — verified via build/typecheck/200/no-errors + logic review; a real-app pass (`npm run dev`) or updated Artifact would confirm the motion.
- ~~No focus-trap cycling inside drawer/palette~~ → **done** in the hardening pass (`useFocusTrap`).
- ~~`npm audit` transitive advisories~~ → **resolved** (0 vulnerabilities via `overrides`).
- **Live-tail uses `Math.random`** (non-deterministic) by design; fine for a demo stream — real transport is still open, see below.
- ~~All mutations/config/keys remain local state~~ → **done 2026-08-04**: key create/revoke/re-limit and config threshold/toggle edits call the real gateway (`POST`/`PATCH`/`DELETE /v1/console/{keys,config}`), with optimistic UI + rollback on failure.
- ~~Component-level tests (rendering) not added~~ → **done 2026-08-11**: added `@testing-library/react`/`jest-dom`/`user-event` + `jsdom` (vitest previously ran `environment:"node"` with zero DOM-rendering capability at all). 15 new component/hook tests across 3 files — `LogFilters` (field-by-field onChange reporting, loaded-count display), `ThreatTable` (empty state, row click → onSelect, selected/fresh-row highlight classes, sort-header toggle; `@tanstack/react-virtual` needed `offsetHeight`/`offsetWidth` stubbed since jsdom reports 0 for both, or it renders zero virtualized rows), and `useLiveTail` (simulated-interval emission/cap/fresh-expiry/clear via fake timers, plus the real-SSE branch via a fake `EventSource` — schema-invalid frames dropped, error closes without reconnect, unmount closes the source). The SSE-branch tests needed a dynamic re-import after setting `NEXT_PUBLIC_ECHELON_API_URL`, since `useLiveTail.ts` reads it into a module-level constant once at import time. 52/52 tests green, `tsc` clean, `next build` clean. Also bumped the `postcss` override from `^8.5.22` to `^8.5.26` (the new devDependencies pulled it in via more paths) to clear 2 audit vulnerabilities (postcss sourceMappingURL, transitive nanoid) the older pin no longer covered — back to 0.

## ⏭️ Next Up
Reads and mutations are both wired to the real backend; server-side filtering and
real live-tail transport both landed 2026-08-05. What remains open:
1. ~~Move log filtering/pagination server-side~~ → **done 2026-08-05**: the logs page now uses a filter- and cursor-aware `useEventsInfinite` (`useInfiniteQuery` keyed on the filter object) hitting `GET /v1/console/events` with real query params; the gateway filters + paginates and returns `{events,nextCursor,hasMore}`. A "Load older events" button walks the cursor. `applyFilters` is retained only as the offline-mock fallback path. Client no longer re-filters a fixed 500-event window.
2. ~~Swap `useLiveTail`'s simulated interval for a real transport~~ → **done 2026-08-05**: when `NEXT_PUBLIC_ECHELON_API_URL` is set, `useLiveTail` opens a real `EventSource` on `/v1/console/events/stream`, validates each frame with `promptEventSchema`, and feeds it through the same streamed/freshIds path the sim uses (shared `push`); unset URL keeps the exact `Math.random` sim. v1 simplification: on SSE error we close without reconnect/backoff.
3. **Still open (out of scope here):** component-level tests (RTL/Playwright) for the interactive log/filter/live-tail UI — the suite still covers pure logic + formatters only (added `buildEventsQuery` mapping tests 2026-08-05).

## 📌 Decisions Log
| Date | Decision | Rationale |
|---|---|---|
| 2026-07-22 | `useLiveTail` simulates the stream behind a stable return shape | Real SSE/WS drops in without touching the page |
| 2026-07-22 | Inline theme script in `<head>` + `suppressHydrationWarning` | Restore saved theme before paint; no flash, no hydration error |
| 2026-07-22 | Fresh rows use static wash (not CSS animation) | Virtualization remounts rows on scroll — animation would re-flash |
| 2026-07-22 | Command palette limited to nav + theme | Genuinely useful without inventing URL-state the mock doesn't have |

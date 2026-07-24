# Echelon — Frontend Execution Plan

> The management console & dashboard for **Echelon**, an ultra-low-latency AI security firewall sitting in the critical path between an application and its target LLM.

---

## 1. Guiding Constraints

| Constraint | Implication for the Frontend |
|---|---|
| **Dual audience** (Product Managers + Security Engineers) | Every view needs a "glanceable" summary layer *and* a "drill-to-raw-JSON" layer. Progressive disclosure is the core UX pattern. |
| **Information density** | We favor data-dense, terminal-adjacent layouts over marketing whitespace — but with typographic hierarchy so it never feels like a wall of noise. |
| **Latency is the product** | Echelon's value prop is "microseconds of overhead." The UI must *feel* fast: optimistic updates, skeletons over spinners, virtualized tables, sub-100ms interactions. |
| **Real-time-ish data** | Logs and metrics stream continuously. We need a live-tail capability and incremental data fetching, not just static page loads. |
| **Trust & auditability** | This is a *security* product. Precision in wording, no ambiguous states, clear provenance ("why was this blocked?"), and no destructive action without confirmation. |

---

## 2. Proposed Tech Stack

### Core Framework — **Next.js 15 (App Router) + React 19 + TypeScript**
- **Why:** Server Components give us fast first paint on data-heavy dashboards; the App Router's nested layouts map cleanly onto our module structure (Dashboard / Logs / Config / Keys). Route handlers let us mock the Echelon API today and proxy the real one later. TypeScript is non-negotiable for a security tool — the data contracts (Risk Scores, layer verdicts) must be typed end-to-end.
- **Alternative considered:** Plain Vite + React SPA. Lighter, but we lose streaming SSR and file-based routing. Kept as a fallback if the team wants a pure static console.

### Styling — **Tailwind CSS v4 + shadcn/ui (Radix primitives)**
- **Why:** Utility-first CSS keeps the dense layouts maintainable; shadcn gives us accessible, unstyled-by-default primitives (dialogs, dropdowns, command palette) that we *own* in-repo and can theme into a "security console" aesthetic. No heavyweight component-library lock-in.

### State Management — **TanStack Query (server state) + Zustand (client/UI state)**
- **Why:** 90% of our state is *server state* — logs, metrics, config fetched from the Echelon API. TanStack Query handles caching, background refetch, pagination, and live polling far better than hand-rolled Redux. Zustand covers the thin slice of genuine client state (filter drafts, panel open/closed, theme, live-tail toggle) without boilerplate.
- **Alternative considered:** Redux Toolkit. Overkill here — we have little cross-cutting *client* state.

### Data Visualization — **Layered strategy**
- **Recharts** for the standard idioms (time-series of attack vectors, latency distributions, cost/credit burn-down). Fast to build, composable, good-enough defaults.
- **visx + D3 primitives** for the *bespoke* visualizations that are the signature of this product — most importantly the **3-Fold Cascade Risk Visualizer** (Heuristics → ML Classifier → LLM-as-Judge), which needs a custom flow/gauge metaphor no charting library ships out of the box.
- **Design-system-agnostic palette** governed by the `dataviz` skill — one accessible categorical + sequential palette used consistently across every chart, verified for light *and* dark.

### Tables — **TanStack Table + TanStack Virtual**
- **Why:** The Threat Audit Log is potentially millions of rows. We need headless, virtualized, column-configurable tables with server-side sort/filter/pagination. TanStack Table is the standard for this.

### Supporting libraries
- **Data fetching transport:** native `fetch` + typed client (generated from an OpenAPI spec once the backend publishes one; hand-written Zod schemas until then).
- **Validation:** **Zod** — runtime validation of API payloads *and* config-form input (threshold math must be validated).
- **Forms:** **React Hook Form + Zod resolver** for the Configuration & Access-Management forms.
- **Live data:** **SSE / WebSocket** wrapper for live-tail logs (transport TBD with backend; abstracted behind a hook).
- **Dates/format:** `date-fns`, `numeral`-style formatting helpers for latency (µs/ms) and credits.
- **Icons:** `lucide-react`.
- **Testing:** Vitest + React Testing Library (unit), Playwright (critical E2E flows: key revocation, threshold change).

---

## 3. Application Architecture

```
app/
  (dashboard)/
    layout.tsx            # Shared shell: sidebar nav, top bar, command palette, live-tail indicator
    page.tsx              # Global Dashboard
    logs/                 # Threat Audit / Logs
      page.tsx            # Virtualized ledger + filters
      [promptId]/         # Drill-down: full cascade breakdown + raw JSON
    config/               # Configuration & Thresholds
    keys/                 # API & Access Management
components/
  charts/                 # Recharts + visx wrappers (single palette source)
  cascade/                # The 3-fold Risk Visualizer (signature component)
  table/                  # Headless table building blocks
  primitives/             # shadcn-derived UI
lib/
  api/                    # Typed client + Zod schemas + mock server
  hooks/                  # useLiveTail, useThreatLog, useMetrics, ...
  format/                 # latency/cost/score formatters
  store/                  # Zustand slices (ui, filters)
types/                    # Shared domain types (RiskScore, LayerVerdict, ...)
```

### Domain model (initial sketch)
```ts
type CascadeLayer = 'heuristics' | 'ml_classifier' | 'llm_judge';
type Verdict = 'pass' | 'flag' | 'block';

interface LayerResult {
  layer: CascadeLayer;
  verdict: Verdict;
  score: number;          // 0..1
  threshold: number;      // routing threshold that applied
  model?: string;         // e.g. "DistilBERT-injection-v2"
  latencyUs: number;
  detail: Record<string, unknown>; // raw, for the JSON drill-down
}

interface PromptEvent {
  id: string;
  ts: string;
  direction: 'ingress' | 'egress';
  finalVerdict: Verdict;
  riskScore: number;      // aggregate 0..1
  blockedAtLayer?: CascadeLayer;
  layers: LayerResult[];
  tokens: { in: number; out: number };
  latencyOverheadUs: number;
  apiKeyId: string;
}
```

---

## 4. Core Modules — Build Plan

### Module A — Global Dashboard *(PM-facing first)*
- KPI row: Total API calls · % blocked · avg latency overhead (µs) · credits used.
- Time-series: attack vectors over time (stacked by category).
- Cascade funnel: how many prompts each of the 3 layers caught.
- Cost/credit burn-down + rate-limit headroom.

### Module B — Threat Audit / Logs *(Engineer-facing)*
- Virtualized, server-filtered ledger of every `PromptEvent`.
- Faceted filters: verdict, layer blocked, risk-score range, direction, API key, time.
- Row → **drill-down panel**: the 3-fold cascade breakdown ("failed Layer 2 DistilBERT @ 0.89") + collapsible raw JSON.
- Live-tail toggle.

### Module C — Configuration & Thresholds
- Toggle security layers (PII masking, toxicity, each cascade stage) on/off.
- Adjust the routing thresholds for the 3-fold ingress pipeline with a live "what-if" preview against recent traffic.
- Guardrails: warn when a threshold change would have let recent known-attacks through.

### Module D — API & Access Management
- Generate / revoke API keys (reveal-once secret pattern).
- Per-key rate limits & credit budgets.
- Per-key usage sparkline.

---

## 5. Phase-Wise Roadmap

| Phase | Deliverable | Status |
|---|---|---|
| **0 — Foundation** | Repo scaffolding, tooling, design tokens, app shell, mock API + typed schemas | ✅ Done |
| **1 — Global Dashboard** | KPI row + core charts against mock data | ✅ Done |
| **2 — Threat Audit Log** | Virtualized table, filters, drill-down + raw JSON | ✅ Done |
| **3 — The Cascade Visualizer** | Signature 3-fold risk component (reused in A & B) | ✅ Done |
| **4 — Configuration & Thresholds** | Toggles + threshold editor + what-if preview | ✅ Done |
| **5 — API & Access Management** | Key lifecycle + rate limits | ✅ Done |
| **6 — Live data & polish** | Live-tail, command palette, a11y pass, perf pass, theming | ✅ Done |
| **7 — Wire to real backend** | Swap mock for real Echelon API / OpenAPI client | ▶ Next |

> **Milestone:** all four core modules from the brief (Global Dashboard · Threat Audit · Configuration & Thresholds · API & Access) are built, verified, and previewable. Phases 6–7 are enhancement + integration.

> **Hardening pass (post-Phase 6):** Vitest suite (24 tests) covering the what-if guardrail, log filters, and formatters · all `npm audit` advisories resolved via `overrides` (0 vulnerabilities) · focus-traps added to the drawer + command palette. Remaining before Phase 7: none blocking.

---

## 6. Decisions Made (Checkpoint 1)
1. **Framework** — ✅ Next.js 15 (App Router) + React 19 + TypeScript.
2. **Visual language** — ✅ Classical / modern / minimalist. Committed direction: **"The Assay Ledger"** — cool paper `#F6F6F3`, engraved ink, deep-petrol brand `#1C3B4A`, desaturated severity scale, Fraunces × Inter × JetBrains Mono. Signature component: the **Cascade Assay Strip**.
3. **Data source** — ✅ Realistic Zod-typed mocks now; swap for real API later behind the same contract.

## 7. Still Open (for the backend team)
- **Real-time transport** — will the backend expose SSE, WebSocket, or polling-only for live logs? (Abstracting behind a `useLiveTail` hook to de-risk.)
- **OpenAPI spec** — none yet; designing against Zod mocks that mirror the intended contract.

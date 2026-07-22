# Echelon Frontend — Current Progress

_Last updated: 2026-07-22 · Phase 0 (Foundation) — planning_

---

## ✅ Just Done
- Established project charter: dual-audience (PM + Security Engineer), density-first, latency-as-product.
- Authored **EXECUTION_PLAN.md** — full tech-stack proposal, architecture, domain model, 4 core modules, 8-phase roadmap.
- Sketched the initial **domain types** (`PromptEvent`, `LayerResult`, cascade verdicts).
- Started **MEDIUM_DRAFTS.md** — intro article on UX for AI security tooling.

## 🔨 In Progress
- Nothing coded yet — awaiting stack/design sign-off at the checkpoint (per workflow rules).

## 🐞 Known Issues / Risks
- **No backend contract yet.** All types are provisional; a real OpenAPI spec could reshape them.
- **Real-time transport unknown** (SSE vs WS vs polling) — abstracting behind a hook to de-risk.
- **Threshold math is safety-critical** — a bad config change weakens the firewall. Needs "what-if" guardrails before it ships.
- **Cascade Visualizer is unproven** — the signature component has no off-the-shelf equivalent; will need a design spike.

## ⏭️ Next Up (pending approval)
1. Confirm stack (Next.js + TanStack + Recharts/visx) and design language at checkpoint.
2. Scaffold Next.js app + Tailwind + design tokens + app shell.
3. Stand up the mock API (Zod schemas + route handlers) so every module has data.
4. Build the Global Dashboard KPI row.

## 📌 Decisions Log
| Date | Decision | Rationale |
|---|---|---|
| 2026-07-22 | Proposed Next.js App Router | Nested layouts map to modules; streaming SSR for data-heavy views |
| 2026-07-22 | TanStack Query + Zustand | State is mostly *server state*; avoid Redux boilerplate |
| 2026-07-22 | Recharts + visx split | Standard charts fast; bespoke cascade viz needs D3-level control |
| 2026-07-22 | Await approval before coding | Per strict phase-gate workflow |

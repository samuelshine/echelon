# Echelon — Security Console

The management console & dashboard for **Echelon**, an ultra-low-latency AI security firewall that sits in the critical path between an application and its target LLM.

Echelon evaluates every prompt through a **3-fold ingress cascade** (Heuristics → ML Classifier → LLM-as-Judge), scans egress responses for PII / toxicity / policy violations, and enforces rate limits and credit budgets. This repo is the **frontend** — the console technical and non-technical operators use to watch, audit, and tune it.

## Stack

- **Next.js 15** (App Router) · React 19 · TypeScript
- **Tailwind CSS v4** + a bespoke design system ("The Assay Ledger")
- **TanStack Query** (server state) + Zustand (UI state)
- **Recharts + visx** for data viz · **TanStack Table** for the audit log
- **Zod** for runtime-validated API contracts

## Getting started

```bash
npm install
npm run dev      # http://localhost:3000
```

All data is currently served from a seeded, deterministic **mock backend** (`lib/api/mock.ts`) validated by the same Zod schemas the real API will satisfy.

## Scripts

| Command | Purpose |
|---|---|
| `npm run dev` | Local dev server |
| `npm run build` | Production build |
| `npm run typecheck` | `tsc --noEmit` |
| `npm run lint` | Next lint |

## Modules

| # | Module | Audience |
|---|---|---|
| 00 | **Overview** — health, cost, attack posture | PM |
| 01 | **Threat Audit** — every prompt & why it was judged | Security Eng |
| 02 | **Thresholds** — tune the cascade & egress scanners | Security Eng |
| 03 | **Access** — API keys, rate limits, credit budgets | Both |

## Project tracking

- `EXECUTION_PLAN.md` — tech stack, architecture, roadmap
- `CURRENT_PROGRESS.md` — task-level tracker + risk register
- `MEDIUM_DRAFTS.md` — running write-up of design & architecture decisions

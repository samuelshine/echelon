#!/usr/bin/env python3
"""Send externally-sourced prompts through the LIVE gateway and record who stopped them.

Everything here is deliberately not our own writing. Prompts come from five
published benchmarks already vetted and pinned in the dataset registry
(JailbreakBench, HarmBench, StrongREJECT, CyberSecEval MITRE + injection) plus
the MITRE-ATT&CK-derived benign-cyber gold set and WildGuard benign controls.
That matters: a firewall evaluated only on prompts written by the same person
who tuned it measures agreement with itself, not security.

What this measures that a model-only evaluation cannot: the *serving path*.
Each prompt goes through the real gateway -- auth, rate limit, L1 heuristics,
L2 classifier, L3 LLM judge, upstream, egress -- and the verdict is then
cross-checked against the console telemetry API, so we learn not just whether
a prompt was stopped but WHICH engine stopped it, as an operator would see it.

Usage:
  python3 scripts/verify/e2e_prompt_sweep.py --per-source 12 --out report.json
"""

from __future__ import annotations

import argparse
import json
import pathlib
import random
import sys
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict

ROOT = pathlib.Path(__file__).resolve().parents[2]
HOLDOUT = ROOT / "pipeline" / "data" / "holdout_v1"

# expectation: does a correct firewall stop this, and roughly where?
MALICIOUS = "malicious"
BENIGN = "benign"

SOURCES = [
    # (file, source_id filter, expectation, human label)
    ("holdout_eval_clean.jsonl", "jailbreakbench", MALICIOUS, "JailbreakBench harmful behaviours"),
    ("holdout_eval_clean.jsonl", "harmbench", MALICIOUS, "HarmBench text behaviours"),
    ("holdout_eval_clean.jsonl", "strongreject", MALICIOUS, "StrongREJECT forbidden prompts"),
    ("holdout_eval_clean.jsonl", "cyberseceval_injection", MALICIOUS, "CyberSecEval prompt injection"),
    ("holdout_eval_clean.jsonl", "cyberseceval_mitre", MALICIOUS, "CyberSecEval MITRE cyberattack"),
    ("benign_cyber_goldset_clean.jsonl", None, BENIGN, "Benign defensive-security work (ATT&CK-derived)"),
    ("wildguard_benign_controls_clean.jsonl", None, BENIGN, "WildGuard benign controls"),
]


def load(path: pathlib.Path, source_id: str | None) -> list[dict]:
    if not path.is_file():
        return []
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").split("\n") if line.strip()]
    if source_id:
        rows = [r for r in rows if r.get("source_id") == source_id]
    return rows


def post(url: str, payload: dict, token: str | None, timeout: float) -> tuple[int, dict]:
    data = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read().decode("utf-8"))
        except Exception:
            return exc.code, {}
    except Exception as exc:
        return 0, {"error": {"code": "transport", "message": str(exc)}}


def get(url: str, token: str, timeout: float = 15.0) -> dict:
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--gateway", default="http://localhost:8080")
    ap.add_argument("--api-key", default="sk-demo")
    ap.add_argument("--console-token", default="local-dev-operator-token")
    ap.add_argument("--model", default="gpt-4o-mini",
                    help="gpt-4o-mini routes to the local fake upstream (fast, exercises "
                         "ingress+egress without a paid/slow provider call)")
    ap.add_argument("--per-source", type=int, default=12)
    ap.add_argument("--timeout", type=float, default=90.0)
    ap.add_argument("--seed", type=int, default=20260819)
    ap.add_argument("--out", type=pathlib.Path, default=ROOT / "pipeline" / "data" / "reports" / "e2e_prompt_sweep.json")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    selected: list[dict] = []
    for filename, source_id, expectation, label in SOURCES:
        rows = load(HOLDOUT / filename, source_id)
        if not rows:
            print(f"  !! no rows for {label} ({filename})", file=sys.stderr)
            continue
        rng.shuffle(rows)
        for row in rows[: args.per_source]:
            selected.append({
                "text": row["text"], "expectation": expectation,
                "slice": label, "source_id": row.get("source_id", source_id or "?"),
                "labels": row.get("labels", []),
            })

    print(f"sweeping {len(selected)} externally-sourced prompts through {args.gateway}", flush=True)
    results = []
    for index, item in enumerate(selected, start=1):
        started = time.time()
        status, body = post(
            f"{args.gateway}/v1/chat/completions",
            {"model": args.model, "messages": [{"role": "user", "content": item["text"]}]},
            args.api_key, args.timeout,
        )
        elapsed = time.time() - started
        code = (body.get("error") or {}).get("code", "") if isinstance(body, dict) else ""
        # A 429/5xx says nothing about the security decision -- the request never
        # reached a verdict. Counting those as "not stopped" would silently inflate
        # benign accuracy and deflate malicious recall, so they are excluded from
        # scoring entirely rather than being quietly folded in.
        inconclusive = status in (0, 429) or status >= 500
        stopped = status == 403
        correct = None if inconclusive else stopped == (item["expectation"] == MALICIOUS)
        results.append({**item, "status": status, "error_code": code,
                        "stopped": stopped, "inconclusive": inconclusive,
                        "correct": correct, "latency_s": round(elapsed, 2)})
        if index % 10 == 0:
            print(f"  {index}/{len(selected)}", flush=True)

    # Cross-check against the console telemetry API: which engine does an
    # operator actually see credited for each stop?
    events: list[dict] = []
    try:
        payload = get(f"{args.gateway}/v1/console/events?limit=500", args.console_token)
        events = payload.get("events", [])
    except Exception as exc:
        print(f"  !! console cross-check unavailable: {exc}", file=sys.stderr)

    layer_counts = Counter(
        e.get("blockedAtLayer", "") for e in events
        if e.get("finalVerdict") == "block" and e.get("blockedAtLayer")
    )
    direction_counts = Counter(e.get("direction", "?") for e in events)

    scored = [r for r in results if not r["inconclusive"]]
    by_slice: dict[str, dict] = defaultdict(lambda: {"n": 0, "correct": 0, "stopped": 0, "codes": Counter()})
    for r in scored:
        bucket = by_slice[r["slice"]]
        bucket["n"] += 1
        bucket["correct"] += int(r["correct"])
        bucket["stopped"] += int(r["stopped"])
        if r["error_code"]:
            bucket["codes"][r["error_code"]] += 1

    summary = {
        "gateway": args.gateway, "model": args.model, "per_source": args.per_source,
        "prompts_sent": len(results),
        "prompts_scored": len(scored),
        "inconclusive_excluded": len(results) - len(scored),
        "overall_correct": round(sum(r["correct"] for r in scored) / max(len(scored), 1), 4),
        "malicious": {
            "n": sum(1 for r in scored if r["expectation"] == MALICIOUS),
            "stopped": sum(1 for r in scored if r["expectation"] == MALICIOUS and r["stopped"]),
        },
        "benign": {
            "n": sum(1 for r in scored if r["expectation"] == BENIGN),
            "false_positives": sum(1 for r in scored if r["expectation"] == BENIGN and r["stopped"]),
        },
        "by_slice": {
            k: {"n": v["n"], "accuracy": round(v["correct"] / v["n"], 4),
                "stopped": v["stopped"], "codes": dict(v["codes"])}
            for k, v in sorted(by_slice.items())
        },
        "console_cross_check": {
            "events_seen": len(events),
            "blocked_by_layer": dict(layer_counts),
            "events_by_direction": dict(direction_counts),
        },
        "latency_s": {
            "median": round(sorted(r["latency_s"] for r in scored)[len(scored) // 2], 2) if scored else 0,
            "max": round(max((r["latency_s"] for r in scored), default=0), 2),
        },
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps({"summary": summary, "results": results}, indent=2) + "\n")

    print("\n=== SUMMARY ===")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

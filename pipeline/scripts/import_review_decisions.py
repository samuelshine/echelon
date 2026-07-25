#!/usr/bin/env python3
"""Import review JSONL and export only candidates satisfying the dual-review gate."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from reviewer.store import (
    decision_report, export_resolved, import_reviews, initialize_database, read_jsonl,
)


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--queue", type=Path, required=True)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--decisions", type=Path, action="append", default=[])
    parser.add_argument("--accepted", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    initialize_database(args.database, args.queue)
    for path in args.decisions:
        import_reviews(args.database, read_jsonl(path))
    report = decision_report(args.database)
    accepted = export_resolved(args.database)
    if len(accepted) != report["training_eligible_items"]:
        raise RuntimeError("admission count invariant failed")
    if args.accepted:
        write_jsonl(args.accepted, accepted)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

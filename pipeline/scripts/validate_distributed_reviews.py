#!/usr/bin/env python3
"""Validate distributed submissions and optionally emit import-ready decisions."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from reviewer.distributed import (
    cohort_report, load_json, validate_submission, write_json, write_jsonl,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public-manifest", type=Path, required=True)
    parser.add_argument("--submission", type=Path, action="append", default=[])
    parser.add_argument("--primary", type=Path, action="append", default=[])
    parser.add_argument("--expert", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--normalized-decisions", type=Path)
    args = parser.parse_args()
    manifest = load_json(args.public_manifest)
    if args.submission and (args.primary or args.expert or args.normalized_decisions):
        parser.error("--submission validates individual files; do not combine it with cohort options")
    if args.submission:
        all_errors = []
        files = []
        for path in args.submission:
            submission = load_json(path)
            errors = validate_submission(submission, manifest)
            all_errors.extend(f"{path}: {error}" for error in errors)
            files.append({"path": str(path), "valid": not errors, "errors": errors})
        report = {"valid": not all_errors, "errors": all_errors, "submissions": files}
    else:
        if len(args.primary) != 2:
            parser.error("cohort validation requires exactly two --primary files")
        first, second = (load_json(path) for path in args.primary)
        expert = load_json(args.expert) if args.expert else None
        report, errors = cohort_report(first, second, manifest, expert)
        if args.normalized_decisions and not errors:
            rows = list(first["reviews"]) + list(second["reviews"])
            if expert:
                rows.extend(expert["reviews"])
            write_jsonl(args.normalized_decisions, rows)
    if args.report:
        write_json(args.report, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

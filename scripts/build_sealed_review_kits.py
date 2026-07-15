#!/usr/bin/env python3
"""Seal primary review kits for safe storage in Git and write secrets outside Git."""

from __future__ import annotations

import argparse
import json
import secrets
from pathlib import Path

from reviewer.distributed import write_json
from reviewer.sealed_kit import seal_kit


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kit-root", type=Path, required=True)
    parser.add_argument("--reviewer", action="append", required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--secrets-file", type=Path, required=True)
    args = parser.parse_args()
    if len(args.reviewer) != 2 or len(set(args.reviewer)) != 2:
        parser.error("provide exactly two distinct --reviewer values")
    outputs = [args.output_root / f"{reviewer}.echelonkit" for reviewer in args.reviewer]
    if any(path.exists() for path in outputs) or args.secrets_file.exists():
        parser.error("refusing to overwrite a sealed kit or secrets file")
    passphrases = {reviewer: secrets.token_urlsafe(32) for reviewer in args.reviewer}
    results = []
    for reviewer, output in zip(args.reviewer, outputs, strict=True):
        results.append(seal_kit(args.kit_root / reviewer, output, passphrases[reviewer]))
    write_json(args.secrets_file, {
        "warning": "PRIVATE: never commit, email, or paste these passphrases into issue trackers",
        "passphrases": passphrases,
    })
    print(json.dumps({
        "sealed_kits": results,
        "secrets_file": str(args.secrets_file),
        "secrets_printed": False,
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

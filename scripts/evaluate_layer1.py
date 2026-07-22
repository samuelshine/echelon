#!/usr/bin/env python3
"""Evaluate one prompt with Layer 1 without echoing prompt content."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from echelon.layer1 import DEFAULT_RULES, HeuristicAnalyzer


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    parser.add_argument("--text", help="Prompt text; prefer stdin to avoid shell history")
    args = parser.parse_args()
    text = args.text if args.text is not None else sys.stdin.read()
    result = HeuristicAnalyzer(args.rules).analyze(text)
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

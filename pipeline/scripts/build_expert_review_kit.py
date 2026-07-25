#!/usr/bin/env python3
"""Build a private expert kit containing only primary-review disagreements."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from reviewer.distributed import build_expert_kit, load_json


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--queue", type=Path, required=True)
    parser.add_argument("--public-manifest", type=Path, required=True)
    parser.add_argument("--primary", type=Path, action="append", required=True)
    parser.add_argument("--expert-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if len(args.primary) != 2:
        parser.error("provide exactly two --primary submission files")
    kit = build_expert_kit(
        args.queue, load_json(args.public_manifest),
        load_json(args.primary[0]), load_json(args.primary[1]),
        args.expert_id, args.output,
    )
    print(json.dumps({
        "output": str(args.output), "expert_id": args.expert_id,
        "conflicts": kit["item_count"], "contains_prompt_text": True,
        "safe_to_commit": False,
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

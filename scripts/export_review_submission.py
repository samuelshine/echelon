#!/usr/bin/env python3
"""Export one complete, prompt-free distributed-review submission from SQLite."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from reviewer.distributed import export_submission, load_json, write_json


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--kit-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    submission = export_submission(args.database, load_json(args.kit_manifest))
    write_json(args.output, submission)
    print(json.dumps({
        "output": str(args.output), "role": submission["role"],
        "reviewer_id": submission["reviewer_id"], "items": submission["item_count"],
        "contains_prompt_text": False, "contains_notes": False,
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

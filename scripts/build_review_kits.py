#!/usr/bin/env python3
"""Build blinded, private primary-review kits and a content-free public manifest."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from reviewer.distributed import build_primary_kit, build_public_manifest, write_json


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--queue", type=Path, required=True)
    parser.add_argument("--queue-id", default="targeted_v0_2_review")
    parser.add_argument("--reviewer", action="append", required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--public-manifest", type=Path, required=True)
    args = parser.parse_args()
    if len(args.reviewer) != 2 or len(set(args.reviewer)) != 2:
        parser.error("provide exactly two distinct --reviewer values")
    manifest = build_public_manifest(args.queue, args.queue_id)
    write_json(args.public_manifest, manifest)
    kits = {}
    for reviewer_id in args.reviewer:
        kits[reviewer_id] = build_primary_kit(
            args.queue, manifest, reviewer_id, args.output_root / reviewer_id,
        )
    print(json.dumps({
        "public_manifest": str(args.public_manifest),
        "queue_sha256": manifest["canonical_queue_sha256"],
        "items": manifest["item_count"],
        "kits": {key: {"role": value["role"], "items": value["item_count"]} for key, value in kits.items()},
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

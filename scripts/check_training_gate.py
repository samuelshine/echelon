#!/usr/bin/env python3
"""Check that a reviewed, semantically split manifest is eligible for training."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from echelon.training_gate import TrainingGateError, validate_training_manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()
    try:
        manifest = validate_training_manifest(args.manifest)
    except TrainingGateError as exc:
        print(json.dumps({"eligible": False, "error": str(exc)}, indent=2))
        return 1
    print(json.dumps({"eligible": True, "rows": manifest["rows"], "dataset_sha256": manifest["dataset_sha256"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

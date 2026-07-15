#!/usr/bin/env python3
"""Decrypt, run, or export one repository-distributed review assignment."""

from __future__ import annotations

import argparse
import getpass
import json
import secrets
from pathlib import Path

from reviewer.app import create_app
from reviewer.distributed import export_submission, load_json, validate_submission, write_json
from reviewer.sealed_kit import materialize_kit, unseal_kit
from reviewer.store import initialize_database

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reviewer_id", choices=("reviewer_a", "reviewer_b"))
    parser.add_argument("--export", action="store_true")
    parser.add_argument("--port", type=int, default=5080)
    args = parser.parse_args()
    sealed = ROOT / "review_kits" / "v0.2" / f"{args.reviewer_id}.echelonkit"
    if not sealed.exists():
        parser.error(f"sealed kit not found: {sealed}")
    passphrase = getpass.getpass(f"Passphrase for {args.reviewer_id}: ")
    try:
        payload = unseal_kit(sealed, passphrase, args.reviewer_id)
    finally:
        passphrase = ""
    runtime = ROOT / "data" / "review_v2" / "runtime" / args.reviewer_id
    queue_path, manifest_path = materialize_kit(payload, runtime)
    database = runtime / "reviews.sqlite3"
    initialize_database(database, queue_path)
    if args.export:
        submission = export_submission(database, payload["kit_manifest"])
        public_manifest = load_json(ROOT / "data" / "manifests" / "targeted_v02_distributed_review_manifest.json")
        errors = validate_submission(submission, public_manifest, expected_role="primary")
        if errors:
            raise ValueError("submission validation failed: " + "; ".join(errors))
        output = ROOT / "review_submissions" / "v0.2" / f"{args.reviewer_id}.json"
        write_json(output, submission)
        print(json.dumps({
            "complete": True, "items": submission["item_count"], "output": str(output),
            "safe_to_commit": True, "next": f"git add {output.relative_to(ROOT)}",
        }, indent=2, sort_keys=True))
        return 0
    token = secrets.token_urlsafe(32)
    app = create_app(database, token, token, args.reviewer_id, "primary", expose_local_token=True)
    print(f"\nOpen http://127.0.0.1:{args.port}")
    print(f"Reviewer ID: {args.reviewer_id}")
    print("After all items are complete, stop with Ctrl+C and run the same command with --export.\n")
    app.run(host="127.0.0.1", port=args.port, debug=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

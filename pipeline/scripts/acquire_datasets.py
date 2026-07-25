#!/usr/bin/env python3
"""Acquire registry-approved Hugging Face artifacts at immutable revisions.

Downloads are atomic, remain outside git under data/raw_v2, and produce a
tracked-safe manifest containing revisions, licenses, sizes, and SHA-256 hashes.
The script refuses gated, unapproved, moving-revision, or metadata-mismatched
sources. It does not parse or expose harmful prompt content.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REGISTRY = PROJECT_ROOT / "configs" / "dataset_registry.json"
DEFAULT_OUTPUT = PROJECT_ROOT / "data" / "raw_v2"
DEFAULT_MANIFEST = PROJECT_ROOT / "data" / "manifests" / "acquisition_manifest.json"
USER_AGENT = "echelon-rnd-dataset-acquirer/0.1"
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


class AcquisitionError(RuntimeError):
    pass


def parse_hf_dataset_uri(uri: str) -> str:
    prefix = "hf://datasets/"
    if not uri.startswith(prefix):
        raise AcquisitionError(f"unsupported dataset URI: {uri}")
    repo_id = uri[len(prefix):]
    if repo_id.count("/") != 1 or any(part in {"", ".", ".."} for part in repo_id.split("/")):
        raise AcquisitionError(f"invalid Hugging Face dataset ID: {repo_id}")
    return repo_id


def resolve_url(repo_id: str, revision: str, artifact: str) -> str:
    if artifact.startswith("/") or ".." in Path(artifact).parts:
        raise AcquisitionError(f"unsafe artifact path: {artifact}")
    quoted_repo = "/".join(urllib.parse.quote(part, safe="") for part in repo_id.split("/"))
    quoted_path = "/".join(urllib.parse.quote(part, safe="") for part in artifact.split("/"))
    return f"https://huggingface.co/datasets/{quoted_repo}/resolve/{revision}/{quoted_path}?download=true"


def read_json_url(url: str) -> dict[str, Any]:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def download_atomic(url: str, destination: Path, force: bool = False) -> tuple[str, int]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_file() and not force:
        digest = hashlib.sha256()
        size = 0
        with destination.open("rb") as existing:
            for chunk in iter(lambda: existing.read(1024 * 1024), b""):
                digest.update(chunk)
                size += len(chunk)
        return digest.hexdigest(), size

    temporary = destination.with_suffix(destination.suffix + f".{os.getpid()}.part")
    digest = hashlib.sha256()
    size = temporary.stat().st_size if temporary.exists() else 0
    if size:
        with temporary.open("rb") as existing:
            for chunk in iter(lambda: existing.read(1024 * 1024), b""):
                digest.update(chunk)
    headers = {"User-Agent": USER_AGENT}
    if size:
        headers["Range"] = f"bytes={size}-"
    request = urllib.request.Request(url, headers=headers)
    try:
        response = urllib.request.urlopen(request, timeout=120)
        resumed = size > 0 and getattr(response, "status", None) == 206
        if size and not resumed:
            digest = hashlib.sha256()
            size = 0
        mode = "ab" if resumed else "wb"
        with response, temporary.open(mode) as output:
            while chunk := response.read(1024 * 1024):
                output.write(chunk)
                digest.update(chunk)
                size += len(chunk)
        os.replace(temporary, destination)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return digest.hexdigest(), size


def approved_sources(registry: dict[str, Any], requested: set[str] | None) -> list[dict[str, Any]]:
    selected = []
    known_ids = {item.get("id") for item in registry.get("datasets", [])}
    if requested:
        unknown = requested - known_ids
        if unknown:
            raise AcquisitionError("unknown dataset IDs: " + ", ".join(sorted(unknown)))
    for item in registry.get("datasets", []):
        if requested and item.get("id") not in requested:
            continue
        if item.get("review_state") != "approved":
            if requested:
                raise AcquisitionError(f"dataset is not approved: {item.get('id')}")
            continue
        if not item.get("artifacts"):
            continue
        parse_hf_dataset_uri(item["uri"])
        if not COMMIT_RE.fullmatch(item.get("revision") or ""):
            raise AcquisitionError(f"dataset lacks immutable 40-character revision: {item['id']}")
        if not item.get("license_spdx"):
            raise AcquisitionError(f"dataset lacks approved license: {item['id']}")
        selected.append(item)
    return selected


def acquire_source(source: dict[str, Any], output_root: Path, force: bool = False) -> dict[str, Any]:
    repo_id = parse_hf_dataset_uri(source["uri"])
    metadata_url = f"https://huggingface.co/api/datasets/{repo_id}"
    metadata = read_json_url(metadata_url)
    if metadata.get("sha") != source["revision"]:
        raise AcquisitionError(
            f"{source['id']}: registry revision {source['revision']} is not current API revision {metadata.get('sha')}"
        )
    if metadata.get("gated"):
        raise AcquisitionError(f"{source['id']}: gated datasets require manual terms acceptance")
    api_license = (metadata.get("cardData") or {}).get("license")
    if api_license and api_license.casefold() != source["license_spdx"].casefold():
        raise AcquisitionError(
            f"{source['id']}: registry license {source['license_spdx']} disagrees with API license {api_license}"
        )

    destination_root = output_root / source["id"] / source["revision"]
    artifacts = []
    for artifact in source["artifacts"]:
        destination = destination_root / artifact
        url = resolve_url(repo_id, source["revision"], artifact)
        sha256, size = download_atomic(url, destination, force=force)
        artifacts.append({"path": artifact, "bytes": size, "sha256": sha256})
        print(f"acquired {source['id']}:{artifact} ({size:,} bytes)", file=sys.stderr)
    return {
        "id": source["id"],
        "repo_id": repo_id,
        "revision": source["revision"],
        "license_spdx": source["license_spdx"],
        "role": source["role"],
        "artifacts": artifacts,
    }


def verify_manifest(manifest_path: Path, output_root: Path) -> list[str]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    errors: list[str] = []
    for source in manifest.get("sources", []):
        for artifact in source.get("artifacts", []):
            path = output_root / source["id"] / source["revision"] / artifact["path"]
            if not path.is_file():
                errors.append(f"missing: {path}")
                continue
            digest = hashlib.sha256()
            size = 0
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
                    size += len(chunk)
            if size != artifact["bytes"]:
                errors.append(f"size mismatch: {path}")
            if digest.hexdigest() != artifact["sha256"]:
                errors.append(f"hash mismatch: {path}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--dataset", action="append", dest="datasets", help="approved registry ID; repeatable")
    parser.add_argument("--force", action="store_true", help="redownload and atomically replace existing artifacts")
    parser.add_argument("--verify-only", action="store_true", help="verify the local manifest and artifacts without network access")
    args = parser.parse_args(argv)

    if args.verify_only:
        try:
            errors = verify_manifest(args.manifest, args.output)
        except (OSError, json.JSONDecodeError, KeyError) as exc:
            print(f"verification failed: {exc}", file=sys.stderr)
            return 1
        for error in errors:
            print(error, file=sys.stderr)
        if errors:
            return 1
        print(f"verified acquisition manifest: {args.manifest}", file=sys.stderr)
        return 0

    try:
        registry = json.loads(args.registry.read_text(encoding="utf-8"))
        sources = approved_sources(registry, set(args.datasets) if args.datasets else None)
        acquired = [acquire_source(source, args.output, force=args.force) for source in sources]
    except (OSError, json.JSONDecodeError, urllib.error.URLError, AcquisitionError) as exc:
        print(f"acquisition failed: {exc}", file=sys.stderr)
        return 1

    manifest = {
        "manifest_version": "0.1.0",
        "registry_version": registry.get("registry_version"),
        "acquired_at": datetime.now(timezone.utc).isoformat(),
        "sources": acquired,
    }
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.manifest.with_suffix(".json.part")
    temporary.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, args.manifest)
    print(f"wrote manifest: {args.manifest}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

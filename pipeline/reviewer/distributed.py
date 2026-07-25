"""Privacy-screened artifacts for distributed Echelon human review."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

from reviewer.store import (
    database_metadata, queue_sha256, read_jsonl, resolve_reviews, reviews_for_reviewer, verdict,
)
from scripts.validate_adjudications import validate_review

PUBLIC_MANIFEST_VERSION = "1.0.0"
KIT_VERSION = "1.0.0"
SUBMISSION_VERSION = "1.0.0"
REVIEWER_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{2,63}$")
SUBMISSION_KEYS = {
    "schema_version", "role", "reviewer_id", "canonical_queue_sha256",
    "review_queue_sha256", "item_count", "reviews",
}
REVIEW_KEYS = {
    "item_id", "reviewer_id", "decision", "labels", "rationale_code",
    "naturalness", "intent_correct", "labels_correct", "non_operational",
    "is_expert_adjudication",
}
BLINDED_FIELDS = ("candidate_id", "item_id", "text", "language", "transformation")


def sha256_json(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def jsonl_bytes(rows: list[dict[str, Any]]) -> bytes:
    return b"".join(
        (json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8") for row in rows
    )


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid JSON: {exc.msg}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return value


def item_id(row: dict[str, Any]) -> str:
    value = row.get("candidate_id") or row.get("item_id")
    if not isinstance(value, str) or not value:
        raise ValueError("queue row is missing candidate_id or item_id")
    return value


def blind_row(row: dict[str, Any]) -> dict[str, Any]:
    blinded = {key: row[key] for key in BLINDED_FIELDS if key in row}
    if "text" not in blinded or not isinstance(blinded["text"], str) or not blinded["text"]:
        raise ValueError(f"queue item {item_id(row)} has no text")
    if "candidate_id" not in blinded and "item_id" not in blinded:
        raise ValueError("blinded row has no item ID")
    return blinded


def build_public_manifest(queue_path: Path, queue_id: str) -> dict[str, Any]:
    rows = read_jsonl(queue_path)
    ids = [item_id(row) for row in rows]
    if len(ids) != len(set(ids)):
        raise ValueError("queue item IDs must be unique")
    return {
        "schema_version": PUBLIC_MANIFEST_VERSION,
        "queue_id": queue_id,
        "canonical_queue_sha256": queue_sha256(queue_path),
        "primary_review_queue_sha256": hashlib.sha256(jsonl_bytes([blind_row(row) for row in rows])).hexdigest(),
        "item_count": len(ids),
        "item_ids": ids,
    }


def validate_public_manifest(manifest: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if manifest.get("schema_version") != PUBLIC_MANIFEST_VERSION:
        errors.append("unsupported public manifest version")
    ids = manifest.get("item_ids")
    if not isinstance(ids, list) or not ids or any(not isinstance(value, str) or not value for value in ids):
        errors.append("manifest item_ids must be a non-empty string list")
        ids = []
    if len(ids) != len(set(ids)):
        errors.append("manifest item_ids must be unique")
    if manifest.get("item_count") != len(ids):
        errors.append("manifest item_count does not match item_ids")
    digest = manifest.get("canonical_queue_sha256", "")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        errors.append("manifest canonical_queue_sha256 is invalid")
    blinded_digest = manifest.get("primary_review_queue_sha256", "")
    if not isinstance(blinded_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", blinded_digest):
        errors.append("manifest primary_review_queue_sha256 is invalid")
    return errors


def build_primary_kit(
    queue_path: Path, public_manifest: dict[str, Any], reviewer_id: str, output_dir: Path,
) -> dict[str, Any]:
    errors = validate_public_manifest(public_manifest)
    if errors:
        raise ValueError("; ".join(errors))
    if not REVIEWER_ID.fullmatch(reviewer_id):
        raise ValueError("reviewer_id must match [a-z0-9][a-z0-9_-]{2,63}")
    if queue_sha256(queue_path) != public_manifest["canonical_queue_sha256"]:
        raise ValueError("queue does not match public manifest SHA-256")
    rows = read_jsonl(queue_path)
    if [item_id(row) for row in rows] != public_manifest["item_ids"]:
        raise ValueError("queue item order does not match public manifest")
    if output_dir.exists() and any(output_dir.iterdir()):
        raise ValueError(f"refusing to overwrite non-empty kit directory: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    queue_out = output_dir / "review_queue.jsonl"
    write_jsonl(queue_out, [blind_row(row) for row in rows])
    if queue_sha256(queue_out) != public_manifest["primary_review_queue_sha256"]:
        raise RuntimeError("blinded queue hash invariant failed")
    kit = {
        "schema_version": KIT_VERSION,
        "role": "primary",
        "assigned_reviewer_id": reviewer_id,
        "canonical_queue_sha256": public_manifest["canonical_queue_sha256"],
        "review_queue_sha256": queue_sha256(queue_out),
        "item_count": len(rows),
        "expected_item_ids": public_manifest["item_ids"],
    }
    write_json(output_dir / "kit_manifest.json", kit)
    (output_dir / "README.txt").write_text(
        "PRIVATE ECHELON REVIEW KIT\n\n"
        "Do not commit or redistribute this directory. Follow docs/DISTRIBUTED_REVIEW.md.\n"
        f"Assigned reviewer ID: {reviewer_id}\n",
        encoding="utf-8",
    )
    return kit


def _clean_review(review: dict[str, Any]) -> dict[str, Any]:
    return {key: review[key] for key in REVIEW_KEYS}


def export_submission(db_path: Path, kit_manifest: dict[str, Any]) -> dict[str, Any]:
    role = kit_manifest.get("role")
    reviewer_id = kit_manifest.get("assigned_reviewer_id")
    if role not in {"primary", "expert"}:
        raise ValueError("kit role must be primary or expert")
    if not isinstance(reviewer_id, str) or not REVIEWER_ID.fullmatch(reviewer_id):
        raise ValueError("kit assigned_reviewer_id is invalid")
    metadata = database_metadata(db_path)
    if metadata["queue_sha256"] != kit_manifest.get("review_queue_sha256"):
        raise ValueError("database queue SHA-256 does not match kit")
    expected = kit_manifest.get("expected_item_ids")
    if not isinstance(expected, list) or len(expected) != len(set(expected)):
        raise ValueError("kit expected_item_ids are invalid")
    reviews = reviews_for_reviewer(db_path, reviewer_id)
    ids = [review["item_id"] for review in reviews]
    if set(ids) != set(expected) or len(ids) != len(expected):
        missing = len(set(expected) - set(ids))
        extra = len(set(ids) - set(expected))
        raise ValueError(f"review is incomplete: missing={missing}, extra={extra}")
    expert = role == "expert"
    if any(review["is_expert_adjudication"] is not expert for review in reviews):
        raise ValueError("review role does not match kit role")
    cleaned = sorted((_clean_review(review) for review in reviews), key=lambda row: row["item_id"])
    return {
        "schema_version": SUBMISSION_VERSION,
        "role": role,
        "reviewer_id": reviewer_id,
        "canonical_queue_sha256": kit_manifest["canonical_queue_sha256"],
        "review_queue_sha256": kit_manifest["review_queue_sha256"],
        "item_count": len(cleaned),
        "reviews": cleaned,
    }


def validate_submission(
    submission: dict[str, Any], public_manifest: dict[str, Any],
    *, expected_role: str | None = None, expected_item_ids: list[str] | None = None,
) -> list[str]:
    errors = validate_public_manifest(public_manifest)
    extra = set(submission) - SUBMISSION_KEYS
    missing = SUBMISSION_KEYS - set(submission)
    if extra:
        errors.append(f"submission contains prohibited fields: {sorted(extra)}")
    if missing:
        errors.append(f"submission is missing fields: {sorted(missing)}")
    if submission.get("schema_version") != SUBMISSION_VERSION:
        errors.append("unsupported submission version")
    role = submission.get("role")
    if role not in {"primary", "expert"}:
        errors.append("submission role must be primary or expert")
    if expected_role and role != expected_role:
        errors.append(f"submission role must be {expected_role}")
    reviewer = submission.get("reviewer_id")
    if not isinstance(reviewer, str) or not REVIEWER_ID.fullmatch(reviewer):
        errors.append("submission reviewer_id is invalid")
    if submission.get("canonical_queue_sha256") != public_manifest.get("canonical_queue_sha256"):
        errors.append("submission canonical queue SHA-256 mismatch")
    review_queue_digest = submission.get("review_queue_sha256", "")
    if not isinstance(review_queue_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", review_queue_digest):
        errors.append("submission review queue SHA-256 is invalid")
    if role == "primary" and review_queue_digest != public_manifest.get("primary_review_queue_sha256"):
        errors.append("primary submission blinded queue SHA-256 mismatch")
    reviews = submission.get("reviews")
    if not isinstance(reviews, list):
        errors.append("submission reviews must be a list")
        return errors
    allowed_ids = expected_item_ids if expected_item_ids is not None else public_manifest.get("item_ids", [])
    seen: list[str] = []
    for number, review in enumerate(reviews, 1):
        if not isinstance(review, dict):
            errors.append(f"review {number}: must be an object")
            continue
        review_extra = set(review) - REVIEW_KEYS
        review_missing = REVIEW_KEYS - set(review)
        if review_extra:
            errors.append(f"review {number}: prohibited fields: {sorted(review_extra)}")
        if review_missing:
            errors.append(f"review {number}: missing fields: {sorted(review_missing)}")
        errors.extend(validate_review(review, number))
        if review.get("reviewer_id") != reviewer:
            errors.append(f"review {number}: reviewer_id does not match submission")
        if bool(review.get("is_expert_adjudication")) != (role == "expert"):
            errors.append(f"review {number}: expert flag does not match role")
        if isinstance(review.get("item_id"), str):
            seen.append(review["item_id"])
    if len(seen) != len(set(seen)):
        errors.append("submission has duplicate item decisions")
    exact_coverage = expected_item_ids is not None or role == "primary"
    if exact_coverage and (set(seen) != set(allowed_ids) or len(seen) != len(allowed_ids)):
        errors.append(
            f"submission item coverage mismatch: expected={len(allowed_ids)}, observed={len(seen)}, "
            f"missing={len(set(allowed_ids)-set(seen))}, extra={len(set(seen)-set(allowed_ids))}"
        )
    elif not exact_coverage and not set(seen).issubset(set(allowed_ids)):
        errors.append(f"expert submission contains {len(set(seen)-set(allowed_ids))} unknown item IDs")
    if submission.get("item_count") != len(reviews):
        errors.append("submission item_count does not match reviews")
    return errors


def submission_reviews(submission: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {review["item_id"]: review for review in submission["reviews"]}


def conflict_ids(first: dict[str, Any], second: dict[str, Any]) -> list[str]:
    left, right = submission_reviews(first), submission_reviews(second)
    return sorted(item for item in left if item in right and verdict(left[item]) != verdict(right[item]))


def validate_primary_pair(
    first: dict[str, Any], second: dict[str, Any], public_manifest: dict[str, Any],
) -> list[str]:
    errors = validate_submission(first, public_manifest, expected_role="primary")
    errors.extend(validate_submission(second, public_manifest, expected_role="primary"))
    if first.get("reviewer_id") == second.get("reviewer_id"):
        errors.append("primary submissions require two distinct reviewer IDs")
    return errors


def build_expert_kit(
    queue_path: Path, public_manifest: dict[str, Any], first: dict[str, Any], second: dict[str, Any],
    expert_id: str, output_dir: Path,
) -> dict[str, Any]:
    errors = validate_primary_pair(first, second, public_manifest)
    if errors:
        raise ValueError("; ".join(errors))
    if not REVIEWER_ID.fullmatch(expert_id):
        raise ValueError("expert_id is invalid")
    if expert_id in {first["reviewer_id"], second["reviewer_id"]}:
        raise ValueError("expert must be distinct from both primary reviewers")
    if queue_sha256(queue_path) != public_manifest["canonical_queue_sha256"]:
        raise ValueError("queue does not match public manifest SHA-256")
    conflicts = conflict_ids(first, second)
    rows = {item_id(row): row for row in read_jsonl(queue_path)}
    if output_dir.exists() and any(output_dir.iterdir()):
        raise ValueError(f"refusing to overwrite non-empty kit directory: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    queue_out = output_dir / "expert_queue.jsonl"
    write_jsonl(queue_out, [blind_row(rows[value]) for value in conflicts])
    # Compose both decisions explicitly in stable primary order.
    primary_rows = []
    first_rows, second_rows = submission_reviews(first), submission_reviews(second)
    for value in conflicts:
        primary_rows.extend((first_rows[value], second_rows[value]))
    write_jsonl(output_dir / "primary_reviews.jsonl", primary_rows)
    kit = {
        "schema_version": KIT_VERSION,
        "role": "expert",
        "assigned_reviewer_id": expert_id,
        "canonical_queue_sha256": public_manifest["canonical_queue_sha256"],
        "review_queue_sha256": queue_sha256(queue_out),
        "item_count": len(conflicts),
        "expected_item_ids": conflicts,
        "primary_reviewer_ids": [first["reviewer_id"], second["reviewer_id"]],
    }
    write_json(output_dir / "kit_manifest.json", kit)
    (output_dir / "README.txt").write_text(
        "PRIVATE ECHELON EXPERT KIT\n\n"
        "Do not commit or redistribute this directory. Follow docs/DISTRIBUTED_REVIEW.md.\n"
        f"Assigned expert ID: {expert_id}\nConflicts: {len(conflicts)}\n",
        encoding="utf-8",
    )
    return kit


def cohort_report(
    first: dict[str, Any], second: dict[str, Any], public_manifest: dict[str, Any],
    expert: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    errors = validate_primary_pair(first, second, public_manifest)
    conflicts = conflict_ids(first, second) if not errors else []
    if expert is not None:
        errors.extend(validate_submission(
            expert, public_manifest, expected_role="expert", expected_item_ids=conflicts,
        ))
        if expert.get("reviewer_id") in {first.get("reviewer_id"), second.get("reviewer_id")}:
            errors.append("expert reviewer must be distinct from both primary reviewers")
    statuses = Counter()
    if not errors:
        left, right = submission_reviews(first), submission_reviews(second)
        expert_rows = submission_reviews(expert) if expert else {}
        for value in public_manifest["item_ids"]:
            item_reviews = [left[value], right[value]]
            if value in expert_rows:
                item_reviews.append(expert_rows[value])
            status, _ = resolve_reviews(item_reviews)
            statuses[status] += 1
    report = {
        "valid": not errors,
        "errors": errors,
        "queue_sha256": public_manifest.get("canonical_queue_sha256"),
        "items": public_manifest.get("item_count"),
        "primary_reviewers": 2,
        "conflicts": len(conflicts),
        "expert_complete": expert is not None and not errors,
        "status": dict(sorted(statuses.items())),
        "training_eligible_items": statuses["accepted_by_agreement"] + statuses["accepted_by_expert"],
    }
    return report, errors

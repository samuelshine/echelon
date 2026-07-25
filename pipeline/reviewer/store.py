"""SQLite-backed dual-review workflow with no prompt text in reports."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections import Counter
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from scripts.validate_adjudications import validate_review


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}: line {number}: invalid JSON: {exc.msg}") from exc
    return rows


def queue_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    return connection


SCHEMA = """
CREATE TABLE IF NOT EXISTS queue_meta (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    queue_sha256 TEXT NOT NULL,
    queue_path TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS items (
    item_id TEXT PRIMARY KEY,
    payload TEXT NOT NULL,
    family TEXT NOT NULL,
    transformation TEXT,
    ordinal INTEGER NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS reviews (
    item_id TEXT NOT NULL REFERENCES items(item_id),
    reviewer_id TEXT NOT NULL,
    decision TEXT NOT NULL,
    labels TEXT NOT NULL,
    rationale_code TEXT NOT NULL,
    notes TEXT,
    naturalness INTEGER NOT NULL CHECK (naturalness BETWEEN 1 AND 5),
    intent_correct INTEGER NOT NULL CHECK (intent_correct IN (0, 1)),
    labels_correct INTEGER NOT NULL CHECK (labels_correct IN (0, 1)),
    non_operational INTEGER NOT NULL CHECK (non_operational IN (0, 1)),
    is_expert_adjudication INTEGER NOT NULL CHECK (is_expert_adjudication IN (0, 1)),
    created_at TEXT NOT NULL,
    PRIMARY KEY (item_id, reviewer_id)
);
CREATE INDEX IF NOT EXISTS idx_reviews_item ON reviews(item_id);
"""


def initialize_database(db_path: Path, queue_path: Path) -> dict[str, Any]:
    rows = read_jsonl(queue_path)
    ids = [row.get("candidate_id") or row.get("item_id") for row in rows]
    if any(not item_id for item_id in ids):
        raise ValueError("every queue row requires candidate_id or item_id")
    if len(ids) != len(set(ids)):
        raise ValueError("queue item IDs must be unique")
    digest = queue_sha256(queue_path)
    with closing(connect(db_path)) as connection, connection:
        connection.executescript(SCHEMA)
        meta = connection.execute("SELECT queue_sha256 FROM queue_meta WHERE singleton=1").fetchone()
        if meta and meta["queue_sha256"] != digest:
            raise ValueError("database is bound to a different queue SHA-256")
        connection.execute(
            "INSERT OR IGNORE INTO queue_meta VALUES (1, ?, ?, ?)",
            (digest, str(queue_path.resolve()), utc_now()),
        )
        for ordinal, (item_id, row) in enumerate(zip(ids, rows, strict=True)):
            connection.execute(
                "INSERT OR IGNORE INTO items VALUES (?, ?, ?, ?, ?)",
                (item_id, json.dumps(row, ensure_ascii=False, sort_keys=True),
                 row.get("family", "unknown"), row.get("transformation"), ordinal),
            )
    return {"queue_sha256": digest, "items": len(rows), "database": str(db_path)}


def _deserialize_review(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "item_id": row["item_id"], "reviewer_id": row["reviewer_id"],
        "decision": row["decision"], "labels": json.loads(row["labels"]),
        "rationale_code": row["rationale_code"], "notes": row["notes"],
        "naturalness": row["naturalness"], "intent_correct": bool(row["intent_correct"]),
        "labels_correct": bool(row["labels_correct"]),
        "non_operational": bool(row["non_operational"]),
        "is_expert_adjudication": bool(row["is_expert_adjudication"]),
        "created_at": row["created_at"],
    }


def quality_passes(review: dict[str, Any]) -> bool:
    return (
        review["decision"] != "exclude"
        and review.get("naturalness", 0) >= 4
        and review.get("intent_correct") is True
        and review.get("labels_correct") is True
        and review.get("non_operational") is True
    )


def verdict(review: dict[str, Any]) -> tuple[str, tuple[str, ...]]:
    return review["decision"], tuple(sorted(review["labels"]))


def resolve_reviews(reviews: list[dict[str, Any]]) -> tuple[str, dict[str, Any] | None]:
    primary = [review for review in reviews if not review.get("is_expert_adjudication")]
    experts = [review for review in reviews if review.get("is_expert_adjudication")]
    if not primary:
        return "unreviewed", None
    if len(primary) < 2:
        return "pending_second_review", None
    first, second = primary[:2]
    if verdict(first) == verdict(second):
        if first["decision"] == "exclude":
            return "rejected_by_agreement", first
        if quality_passes(first) and quality_passes(second):
            return "accepted_by_agreement", first
        return "rejected_quality_gate", None
    if not experts:
        return "needs_expert_adjudication", None
    expert = experts[-1]
    if expert["decision"] == "exclude" or not quality_passes(expert):
        return "rejected_by_expert", expert
    return "accepted_by_expert", expert


def next_item(db_path: Path, reviewer_id: str, expert: bool = False) -> dict[str, Any] | None:
    if not reviewer_id.strip():
        raise ValueError("reviewer_id is required")
    with closing(connect(db_path)) as connection, connection:
        items = connection.execute("SELECT * FROM items ORDER BY ordinal").fetchall()
        for item in items:
            rows = connection.execute(
                "SELECT * FROM reviews WHERE item_id=? ORDER BY created_at", (item["item_id"],)
            ).fetchall()
            reviews = [_deserialize_review(row) for row in rows]
            if any(review["reviewer_id"] == reviewer_id for review in reviews):
                continue
            primary = [review for review in reviews if not review["is_expert_adjudication"]]
            if expert:
                if len(primary) != 2 or verdict(primary[0]) == verdict(primary[1]):
                    continue
                if any(review["is_expert_adjudication"] for review in reviews):
                    continue
            elif len(primary) >= 2:
                continue
            payload = json.loads(item["payload"])
            # Primary review is blind to proposed labels, nearest-neighbor text, and all prior decisions.
            if not expert:
                visible = {
                    key: payload[key] for key in ("candidate_id", "item_id", "text", "language", "transformation")
                    if key in payload
                }
                return {"item": visible, "primary_reviews": len(primary)}
            return {"item": payload, "primary_reviews": primary}
    return None


def _save_review(connection: sqlite3.Connection, review: dict[str, Any]) -> None:
    errors = validate_review(review, 1)
    if errors:
        raise ValueError("; ".join(errors))
    exists = connection.execute("SELECT 1 FROM items WHERE item_id=?", (review["item_id"],)).fetchone()
    if not exists:
        raise ValueError("item_id is not in the bound queue")
    prior = [_deserialize_review(row) for row in connection.execute(
        "SELECT * FROM reviews WHERE item_id=? ORDER BY created_at", (review["item_id"],)
    ).fetchall()]
    if any(row["reviewer_id"] == review["reviewer_id"] for row in prior):
        raise ValueError("a reviewer may submit only once per item")
    primary = [row for row in prior if not row["is_expert_adjudication"]]
    experts = [row for row in prior if row["is_expert_adjudication"]]
    is_expert = bool(review["is_expert_adjudication"])
    if is_expert and (len(primary) != 2 or verdict(primary[0]) == verdict(primary[1])):
        raise ValueError("expert review is allowed only after two primary reviewers disagree")
    if is_expert and experts:
        raise ValueError("item already has an expert adjudication")
    if not is_expert and len(primary) >= 2:
        raise ValueError("item already has two primary reviews")
    connection.execute(
        "INSERT INTO reviews VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (review["item_id"], review["reviewer_id"], review["decision"],
         json.dumps(sorted(review["labels"])), review["rationale_code"], review.get("notes"),
         review["naturalness"], int(review["intent_correct"]), int(review["labels_correct"]),
         int(review["non_operational"]), int(is_expert), utc_now()),
    )


def save_review(db_path: Path, review: dict[str, Any]) -> None:
    with closing(connect(db_path)) as connection, connection:
        _save_review(connection, review)


def import_reviews(db_path: Path, reviews: Iterable[dict[str, Any]]) -> dict[str, int]:
    counts = Counter()
    with closing(connect(db_path)) as connection, connection:
        for review in reviews:
            _save_review(connection, review)
            counts["imported"] += 1
    return dict(counts)


def database_metadata(db_path: Path) -> dict[str, Any]:
    with closing(connect(db_path)) as connection:
        meta = connection.execute("SELECT * FROM queue_meta WHERE singleton=1").fetchone()
        if not meta:
            raise ValueError("database is not initialized")
        return {
            "queue_sha256": meta["queue_sha256"],
            "queue_path": meta["queue_path"],
            "items": connection.execute("SELECT COUNT(*) FROM items").fetchone()[0],
        }


def reviews_for_reviewer(db_path: Path, reviewer_id: str) -> list[dict[str, Any]]:
    with closing(connect(db_path)) as connection:
        rows = connection.execute(
            "SELECT * FROM reviews WHERE reviewer_id=? ORDER BY item_id", (reviewer_id,)
        ).fetchall()
        return [_deserialize_review(row) for row in rows]


def decision_report(db_path: Path) -> dict[str, Any]:
    statuses: Counter[str] = Counter()
    family_status: dict[str, Counter[str]] = {}
    with closing(connect(db_path)) as connection, connection:
        total = connection.execute("SELECT COUNT(*) AS n FROM items").fetchone()["n"]
        reviewed = connection.execute("SELECT COUNT(*) AS n FROM reviews").fetchone()["n"]
        for item in connection.execute("SELECT item_id, family FROM items").fetchall():
            reviews = [_deserialize_review(row) for row in connection.execute(
                "SELECT * FROM reviews WHERE item_id=? ORDER BY created_at", (item["item_id"],)
            ).fetchall()]
            status, _ = resolve_reviews(reviews)
            statuses[status] += 1
            family_status.setdefault(item["family"], Counter())[status] += 1
        digest = connection.execute("SELECT queue_sha256 FROM queue_meta WHERE singleton=1").fetchone()[0]
    return {
        "queue_sha256": digest, "items": total, "review_records": reviewed,
        "status": dict(sorted(statuses.items())),
        "by_family": {key: dict(sorted(value.items())) for key, value in sorted(family_status.items())},
        "training_eligible_items": statuses["accepted_by_agreement"] + statuses["accepted_by_expert"],
    }


def export_resolved(db_path: Path) -> list[dict[str, Any]]:
    accepted: list[dict[str, Any]] = []
    with closing(connect(db_path)) as connection, connection:
        for item in connection.execute("SELECT * FROM items ORDER BY ordinal").fetchall():
            reviews = [_deserialize_review(row) for row in connection.execute(
                "SELECT * FROM reviews WHERE item_id=? ORDER BY created_at", (item["item_id"],)
            ).fetchall()]
            status, final = resolve_reviews(reviews)
            if not status.startswith("accepted_") or final is None:
                continue
            payload = json.loads(item["payload"])
            payload.pop("proposed_labels", None)
            payload["labels"] = final["labels"]
            payload["review_status"] = status
            payload["training_eligible"] = True
            payload["review_provenance"] = {
                "reviewer_count": len({row["reviewer_id"] for row in reviews}),
                "resolution": status,
                "queue_sha256": connection.execute(
                    "SELECT queue_sha256 FROM queue_meta WHERE singleton=1"
                ).fetchone()[0],
            }
            payload.pop("review", None)
            payload.pop("nearest_existing", None)
            accepted.append(payload)
    return accepted

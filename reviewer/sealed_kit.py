"""Authenticated encryption for repository-distributed private review kits."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from reviewer.distributed import KIT_VERSION, load_json, queue_sha256, write_json, write_jsonl

SEALED_VERSION = "1.0.0"
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1


def _crypto():
    try:
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    except ImportError as exc:
        raise RuntimeError("cryptography>=42 is required for sealed review kits") from exc
    return AESGCM, Scrypt, InvalidTag


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


def _aad(reviewer_id: str) -> bytes:
    return f"echelon-review-kit:{SEALED_VERSION}:{reviewer_id}".encode("utf-8")


def _derive_key(passphrase: str, salt: bytes, *, n: int = SCRYPT_N, r: int = SCRYPT_R, p: int = SCRYPT_P) -> bytes:
    if len(passphrase) < 20:
        raise ValueError("kit passphrase must contain at least 20 characters")
    _, Scrypt, _ = _crypto()
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(passphrase.encode("utf-8"))


def seal_kit(kit_dir: Path, output: Path, passphrase: str) -> dict[str, Any]:
    import secrets

    AESGCM, _, _ = _crypto()
    manifest = load_json(kit_dir / "kit_manifest.json")
    reviewer_id = manifest.get("assigned_reviewer_id")
    if manifest.get("schema_version") != KIT_VERSION or manifest.get("role") != "primary" or not reviewer_id:
        raise ValueError("only valid primary kits can be sealed for repository distribution")
    queue_path = kit_dir / "review_queue.jsonl"
    if queue_sha256(queue_path) != manifest.get("review_queue_sha256"):
        raise ValueError("review queue does not match kit manifest")
    queue_rows = [json.loads(line) for line in queue_path.read_text(encoding="utf-8").splitlines() if line]
    payload = {
        "schema_version": SEALED_VERSION,
        "kit_manifest": manifest,
        "review_queue": queue_rows,
    }
    plaintext = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    key = _derive_key(passphrase, salt)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, _aad(reviewer_id))
    envelope = {
        "schema_version": SEALED_VERSION,
        "reviewer_id": reviewer_id,
        "cipher": "AES-256-GCM",
        "kdf": {"name": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P, "salt": _b64(salt)},
        "nonce": _b64(nonce),
        "ciphertext": _b64(ciphertext),
        "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
    }
    write_json(output, envelope)
    return {"reviewer_id": reviewer_id, "output": str(output), "bytes": output.stat().st_size}


def unseal_kit(sealed_path: Path, passphrase: str, expected_reviewer_id: str) -> dict[str, Any]:
    AESGCM, _, InvalidTag = _crypto()
    envelope = load_json(sealed_path)
    if envelope.get("schema_version") != SEALED_VERSION:
        raise ValueError("unsupported sealed kit version")
    if envelope.get("reviewer_id") != expected_reviewer_id:
        raise ValueError("sealed kit is assigned to a different reviewer")
    kdf = envelope.get("kdf") or {}
    if kdf.get("name") != "scrypt" or (kdf.get("n"), kdf.get("r"), kdf.get("p")) != (SCRYPT_N, SCRYPT_R, SCRYPT_P):
        raise ValueError("sealed kit uses unapproved KDF parameters")
    try:
        salt, nonce, ciphertext = _unb64(kdf["salt"]), _unb64(envelope["nonce"]), _unb64(envelope["ciphertext"])
        key = _derive_key(passphrase, salt, n=kdf["n"], r=kdf["r"], p=kdf["p"])
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, _aad(expected_reviewer_id))
    except (KeyError, TypeError, ValueError, InvalidTag) as exc:
        raise ValueError("kit authentication failed; check the reviewer ID and passphrase") from exc
    if hashlib.sha256(plaintext).hexdigest() != envelope.get("plaintext_sha256"):
        raise ValueError("decrypted kit hash mismatch")
    payload = json.loads(plaintext.decode("utf-8"))
    manifest = payload.get("kit_manifest") or {}
    queue_rows = payload.get("review_queue")
    if manifest.get("assigned_reviewer_id") != expected_reviewer_id or manifest.get("role") != "primary":
        raise ValueError("decrypted kit assignment is invalid")
    if not isinstance(queue_rows, list) or len(queue_rows) != manifest.get("item_count"):
        raise ValueError("decrypted queue coverage is invalid")
    return payload


def materialize_kit(payload: dict[str, Any], runtime_dir: Path) -> tuple[Path, Path]:
    runtime_dir.mkdir(parents=True, exist_ok=True)
    queue_path, manifest_path = runtime_dir / "review_queue.jsonl", runtime_dir / "kit_manifest.json"
    write_jsonl(queue_path, payload["review_queue"])
    write_json(manifest_path, payload["kit_manifest"])
    if queue_sha256(queue_path) != payload["kit_manifest"].get("review_queue_sha256"):
        raise ValueError("materialized queue hash mismatch")
    return queue_path, manifest_path

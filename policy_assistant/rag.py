from __future__ import annotations

import hashlib
import io
import json
import math
import re
import sqlite3
import threading
import uuid
import zipfile
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator
from xml.etree import ElementTree


TOKEN_RE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_'-]{1,}")
SENTENCE_RE = re.compile(r"(?<=[.!?])\s+")
ALLOWED_EXTENSIONS = {".txt", ".md", ".markdown", ".pdf", ".docx"}
STOP_WORDS = {
    "a", "an", "and", "are", "as", "at", "be", "by", "can", "do", "for", "from",
    "has", "have", "he", "her", "him", "his", "i", "if", "in", "into", "is", "it",
    "its", "may", "me", "my", "of", "on", "or", "our", "she", "should", "that", "the",
    "their", "them", "they", "this", "to", "was", "we", "were", "what", "when", "where",
    "which", "who", "why", "will", "with", "you", "your",
}
TOKEN_ALIASES = {
    "approval": "approve",
    "approvals": "approve",
    "authorization": "approve",
    "authorisation": "approve",
    "pto": "leave",
    "vacation": "leave",
}


class PolicyError(ValueError):
    """A safe, user-facing policy ingestion error."""


@dataclass(frozen=True)
class SearchResult:
    chunk_id: str
    document_id: str
    document_name: str
    section: str
    page: int | None
    text: str
    score: float

    def as_dict(self, index: int | None = None) -> dict:
        result = {
            "chunk_id": self.chunk_id,
            "document_id": self.document_id,
            "document_name": self.document_name,
            "section": self.section,
            "page": self.page,
            "excerpt": self.text,
            "score": round(self.score, 4),
        }
        if index is not None:
            result["citation"] = index
        return result


def _tokens(text: str) -> list[str]:
    normalized = []
    for raw_token in TOKEN_RE.findall(text):
        token = raw_token.lower().removesuffix("'s")
        token = TOKEN_ALIASES.get(token, token)
        if token not in STOP_WORDS:
            normalized.append(token)
    return normalized


class HashingEmbedder:
    """Dependency-free, deterministic local embeddings for private retrieval.

    Word and adjacent-word features are projected into a fixed vector. This keeps
    policy text local, requires no embedding API, and is sufficient for hybrid
    semantic/lexical retrieval in a small company knowledge base.
    """

    name = "echelon-hash-v1"

    def __init__(self, dimensions: int = 384) -> None:
        self.dimensions = dimensions

    def embed(self, text: str) -> list[float]:
        words = _tokens(text)
        features = words + [f"{a}::{b}" for a, b in zip(words, words[1:])]
        vector = [0.0] * self.dimensions
        for feature in features:
            digest = hashlib.blake2b(feature.encode("utf-8"), digest_size=8).digest()
            slot = int.from_bytes(digest[:4], "big") % self.dimensions
            sign = 1.0 if digest[4] & 1 else -1.0
            vector[slot] += sign
        norm = math.sqrt(sum(value * value for value in vector))
        return [value / norm for value in vector] if norm else vector


def _cosine(left: list[float], right: list[float]) -> float:
    return sum(a * b for a, b in zip(left, right))


def _clean_text(text: str) -> str:
    text = text.replace("\x00", " ").replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"[\t ]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def extract_policy(data: bytes, filename: str) -> list[tuple[str, int | None, str]]:
    """Return (section, page, text) blocks from an accepted policy file."""
    suffix = Path(filename).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise PolicyError("Unsupported file type. Upload PDF, DOCX, TXT, or Markdown.")

    if suffix in {".txt", ".md", ".markdown"}:
        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise PolicyError("Text files must use UTF-8 encoding.") from exc
        return _section_blocks(_clean_text(text))

    if suffix == ".docx":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                document_info = archive.getinfo("word/document.xml")
                if document_info.file_size > 30 * 1024 * 1024:
                    raise PolicyError("The DOCX document content is too large to process safely.")
                xml = archive.read("word/document.xml")
            root = ElementTree.fromstring(xml)
            paragraphs: list[str] = []
            for paragraph in root.iter("{http://schemas.openxmlformats.org/wordprocessingml/2006/main}p"):
                value = "".join(
                    node.text or ""
                    for node in paragraph.iter("{http://schemas.openxmlformats.org/wordprocessingml/2006/main}t")
                ).strip()
                if value:
                    paragraphs.append(value)
            return _section_blocks(_clean_text("\n\n".join(paragraphs)))
        except (KeyError, zipfile.BadZipFile, ElementTree.ParseError) as exc:
            raise PolicyError("The DOCX file is invalid or corrupted.") from exc

    try:
        from pypdf import PdfReader
    except ImportError as exc:
        raise PolicyError("PDF support is unavailable. Install the pypdf dependency.") from exc
    try:
        reader = PdfReader(io.BytesIO(data))
        pages = []
        for page_number, page in enumerate(reader.pages, start=1):
            text = _clean_text(page.extract_text() or "")
            if text:
                pages.append((f"Page {page_number}", page_number, text))
        return pages
    except Exception as exc:  # pypdf exposes several parser-specific exceptions
        raise PolicyError("The PDF could not be read. It may be scanned or corrupted.") from exc


def _section_blocks(text: str) -> list[tuple[str, int | None, str]]:
    if not text:
        return []
    blocks: list[tuple[str, int | None, str]] = []
    heading = "General"
    body: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        looks_like_heading = bool(
            re.match(r"^#{1,6}\s+", line)
            or re.match(r"^(?:\d+\.)+\s+[A-Z]", line)
            or (line.isupper() and 2 <= len(line.split()) <= 12)
        )
        if looks_like_heading:
            if body:
                blocks.append((heading, None, "\n".join(body).strip()))
            heading = re.sub(r"^#{1,6}\s+", "", line).strip(" #") or "General"
            body = []
        elif line:
            body.append(line)
    if body:
        blocks.append((heading, None, "\n".join(body).strip()))
    return blocks or [("General", None, text)]


def chunk_blocks(
    blocks: Iterable[tuple[str, int | None, str]], max_words: int = 190, overlap: int = 35
) -> list[tuple[str, int | None, str]]:
    chunks: list[tuple[str, int | None, str]] = []
    for section, page, text in blocks:
        words = text.split()
        if not words:
            continue
        start = 0
        while start < len(words):
            end = min(start + max_words, len(words))
            chunks.append((section, page, " ".join(words[start:end])))
            if end == len(words):
                break
            start = max(start + 1, end - overlap)
    return chunks


class PolicyStore:
    def __init__(self, database_path: Path, embedder: HashingEmbedder | None = None) -> None:
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.embedder = embedder or HashingEmbedder()
        self._write_lock = threading.Lock()
        self._initialize()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.database_path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS documents (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    content_type TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    fingerprint TEXT NOT NULL UNIQUE,
                    chunk_count INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS chunks (
                    id TEXT PRIMARY KEY,
                    document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
                    position INTEGER NOT NULL,
                    section TEXT NOT NULL,
                    page INTEGER,
                    text TEXT NOT NULL,
                    embedding TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_chunks_document ON chunks(document_id);
                """
            )

    def ingest(self, filename: str, content_type: str, data: bytes) -> tuple[dict, bool]:
        if not data:
            raise PolicyError("The uploaded file is empty.")
        safe_name = Path((filename or "policy.txt").replace("\\", "/")).name
        fingerprint = hashlib.sha256(data).hexdigest()
        existing = self._document_by_fingerprint(fingerprint)
        if existing:
            return existing, False

        chunks = chunk_blocks(extract_policy(data, safe_name))
        if not chunks:
            raise PolicyError("No readable text was found in this document.")
        document_id = f"doc_{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc).isoformat()
        with self._write_lock, self._connect() as connection:
            # Serialize writers across Gunicorn workers, then check the fingerprint
            # again so two simultaneous uploads cannot create duplicate policies.
            connection.execute("BEGIN IMMEDIATE")
            concurrent = connection.execute(
                "SELECT * FROM documents WHERE fingerprint = ?", (fingerprint,)
            ).fetchone()
            if concurrent:
                return self._document_dict(concurrent), False
            connection.execute(
                "INSERT INTO documents VALUES (?, ?, ?, ?, ?, ?, ?)",
                (document_id, safe_name, content_type, len(data), fingerprint, len(chunks), now),
            )
            connection.executemany(
                "INSERT INTO chunks VALUES (?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        f"chk_{uuid.uuid4().hex[:12]}",
                        document_id,
                        position,
                        section,
                        page,
                        text,
                        json.dumps(self.embedder.embed(f"{section} {text}")),
                    )
                    for position, (section, page, text) in enumerate(chunks)
                ],
            )
        return self.get_document(document_id), True

    def _document_by_fingerprint(self, fingerprint: str) -> dict | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM documents WHERE fingerprint = ?", (fingerprint,)
            ).fetchone()
        return self._document_dict(row) if row else None

    @staticmethod
    def _document_dict(row: sqlite3.Row) -> dict:
        return {
            "id": row["id"],
            "name": row["name"],
            "content_type": row["content_type"],
            "size_bytes": row["size_bytes"],
            "chunk_count": row["chunk_count"],
            "created_at": row["created_at"],
        }

    def list_documents(self) -> list[dict]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM documents ORDER BY created_at DESC"
            ).fetchall()
        return [self._document_dict(row) for row in rows]

    def get_document(self, document_id: str) -> dict:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM documents WHERE id = ?", (document_id,)
            ).fetchone()
        if not row:
            raise PolicyError("Policy document not found.")
        return self._document_dict(row)

    def delete_document(self, document_id: str) -> bool:
        with self._write_lock, self._connect() as connection:
            cursor = connection.execute("DELETE FROM documents WHERE id = ?", (document_id,))
            return cursor.rowcount > 0

    def search(
        self, query: str, limit: int = 6, document_ids: list[str] | None = None
    ) -> list[SearchResult]:
        query = query.strip()
        if not query:
            return []
        sql = """
            SELECT c.*, d.name AS document_name
            FROM chunks c JOIN documents d ON d.id = c.document_id
        """
        parameters: list[str] = []
        if document_ids:
            placeholders = ",".join("?" for _ in document_ids)
            sql += f" WHERE c.document_id IN ({placeholders})"
            parameters.extend(document_ids)
        with self._connect() as connection:
            rows = connection.execute(sql, parameters).fetchall()
        if not rows:
            return []

        query_tokens = _tokens(query)
        query_counts = Counter(query_tokens)
        query_embedding = self.embedder.embed(query)
        documents = [Counter(_tokens(row["text"])) for row in rows]
        doc_frequency = Counter(
            token for counts in documents for token in set(counts).intersection(query_counts)
        )
        average_length = sum(sum(counts.values()) for counts in documents) / len(documents)

        scored: list[tuple[float, sqlite3.Row]] = []
        for row, counts in zip(rows, documents):
            length = max(sum(counts.values()), 1)
            bm25 = 0.0
            for token, query_frequency in query_counts.items():
                frequency = counts[token]
                if not frequency:
                    continue
                inverse_frequency = math.log(
                    1 + (len(rows) - doc_frequency[token] + 0.5) / (doc_frequency[token] + 0.5)
                )
                bm25 += query_frequency * inverse_frequency * (
                    frequency * 2.2
                ) / (frequency + 1.2 * (0.25 + 0.75 * length / max(average_length, 1)))
            vector_score = max(_cosine(query_embedding, json.loads(row["embedding"])), 0.0)
            lexical_score = bm25 / (bm25 + 4.0) if bm25 else 0.0
            exact_bonus = 0.08 if query.lower() in row["text"].lower() else 0.0
            score = 0.58 * vector_score + 0.42 * lexical_score + exact_bonus
            if score > 0.015:
                scored.append((score, row))

        scored.sort(key=lambda item: item[0], reverse=True)
        return [
            SearchResult(
                chunk_id=row["id"],
                document_id=row["document_id"],
                document_name=row["document_name"],
                section=row["section"],
                page=row["page"],
                text=row["text"],
                score=score,
            )
            for score, row in scored[: max(1, min(limit, 12))]
        ]

    def stats(self) -> dict:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS documents, COALESCE(SUM(chunk_count), 0) AS chunks FROM documents"
            ).fetchone()
        return {"documents": row["documents"], "chunks": row["chunks"]}

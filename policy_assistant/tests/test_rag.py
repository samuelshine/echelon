from __future__ import annotations

import io
import tempfile
import unittest
import zipfile
from pathlib import Path

from policy_assistant.rag import PolicyError, PolicyStore, chunk_blocks, extract_policy


LEAVE_POLICY = b"""# Leave policy

Employees receive twenty paid leave days each calendar year. Five unused days may carry over.

## Approval

Planned leave must be submitted to a manager ten business days in advance.
"""

SECURITY_POLICY = b"""# Security response

Lost devices and exposed credentials must be reported to the security team immediately.
Employees must keep customer records in approved company systems.
"""


class PolicyStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.store = PolicyStore(Path(self.temp_dir.name) / "test.sqlite3")

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_ingest_search_and_deduplicate(self) -> None:
        leave, created = self.store.ingest("leave.md", "text/markdown", LEAVE_POLICY)
        self.assertTrue(created)
        duplicate, created_again = self.store.ingest("copy.md", "text/markdown", LEAVE_POLICY)
        self.assertFalse(created_again)
        self.assertEqual(leave["id"], duplicate["id"])

        self.store.ingest("security.md", "text/markdown", SECURITY_POLICY)
        results = self.store.search("How many vacation days carry over?")
        self.assertTrue(results)
        self.assertEqual(results[0].document_name, "leave.md")
        self.assertIn("Five unused days", results[0].text)

    def test_document_filter_and_delete(self) -> None:
        leave, _ = self.store.ingest("leave.md", "text/markdown", LEAVE_POLICY)
        security, _ = self.store.ingest("security.md", "text/markdown", SECURITY_POLICY)
        results = self.store.search("What should happen to exposed credentials?", document_ids=[leave["id"]])
        self.assertTrue(all(result.document_id == leave["id"] for result in results))
        self.assertTrue(self.store.delete_document(security["id"]))
        self.assertFalse(self.store.delete_document(security["id"]))
        self.assertEqual(self.store.stats()["documents"], 1)

    def test_rejects_empty_and_unknown_files(self) -> None:
        with self.assertRaisesRegex(PolicyError, "empty"):
            self.store.ingest("empty.txt", "text/plain", b"")
        with self.assertRaisesRegex(PolicyError, "Unsupported"):
            self.store.ingest("policy.exe", "application/octet-stream", b"not a policy")

    def test_docx_extraction_without_external_parser(self) -> None:
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr(
                "word/document.xml",
                '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Remote work requires manager approval.</w:t></w:r></w:p></w:body></w:document>',
            )
        blocks = extract_policy(output.getvalue(), "remote.docx")
        self.assertIn("manager approval", blocks[0][2])

    def test_chunk_overlap_preserves_context(self) -> None:
        words = [f"word{index}" for index in range(30)]
        chunks = chunk_blocks([("Section", None, " ".join(words))], max_words=12, overlap=3)
        self.assertEqual(len(chunks), 3)
        self.assertEqual(chunks[0][2].split()[-3:], chunks[1][2].split()[:3])


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from policy_assistant.config import Settings
from policy_assistant.llm import PolicyLLM, cited_source_indexes
from policy_assistant.rag import SearchResult


def settings_without_key(data_dir: Path) -> Settings:
    return Settings(
        data_dir=data_dir,
        database_path=data_dir / "db.sqlite3",
        llm_api_key="",
        llm_base_url="https://api.openai.com/v1",
        llm_model="test-model",
        llm_timeout_seconds=1,
        llm_temperature=0.1,
        max_upload_bytes=1024,
        max_context_chunks=6,
        host="127.0.0.1",
        port=8100,
        debug=False,
    )


class PolicyLLMTests(unittest.TestCase):
    def test_extractive_mode_returns_cited_grounded_answer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            llm = PolicyLLM(settings_without_key(Path(directory)))
            source = SearchResult(
                chunk_id="chunk",
                document_id="doc",
                document_name="Leave.md",
                section="PTO",
                page=None,
                text="Employees receive 20 paid days each year. Up to five days carry forward.",
                score=0.8,
            )
            answer = llm.answer("How many days carry forward?", [source])
        self.assertEqual(answer.mode, "extractive-demo")
        self.assertIn("five days", answer.text)
        self.assertIn("[1]", answer.text)

    def test_no_sources_does_not_call_provider(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            answer = PolicyLLM(settings_without_key(Path(directory))).answer("Unknown?", [])
        self.assertIn("couldn't find", answer.text)

    def test_citation_parser_ignores_out_of_range_values(self) -> None:
        self.assertEqual(cited_source_indexes("See [1], [2], and [99].", 2), {1, 2})


if __name__ == "__main__":
    unittest.main()

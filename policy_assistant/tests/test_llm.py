from __future__ import annotations

import json
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


class DescribeHTTPErrorTests(unittest.TestCase):
    """Regression coverage: a failed call must surface the real reason, not a
    guess from the HTTP status code. The bug this replaces reported EVERY 401/403
    -- including the gateway's own ingress/egress safety block -- as "The LLM API
    key was rejected. Check LLM_API_KEY.", which is actively wrong for a request
    the security cascade rejected on purpose.
    """

    @staticmethod
    def _http_error(code: int, body: dict | bytes) -> "urllib.error.HTTPError":
        import io
        import urllib.error

        raw = json.dumps(body).encode("utf-8") if isinstance(body, dict) else body
        return urllib.error.HTTPError(
            url="http://gateway/v1/chat/completions", code=code,
            msg="error", hdrs=None, fp=io.BytesIO(raw),
        )

    def test_gateway_ingress_block_reports_the_real_reason(self) -> None:
        from policy_assistant.llm import _describe_http_error

        exc = self._http_error(403, {"error": {
            "code": "ingress_blocked", "message": "prompt blocked by ingress policy",
        }})
        self.assertEqual(_describe_http_error(exc), "prompt blocked by ingress policy")

    def test_gateway_egress_block_reports_the_real_reason(self) -> None:
        from policy_assistant.llm import _describe_http_error

        exc = self._http_error(403, {"error": {
            "code": "egress_blocked", "message": "response blocked by egress policy",
        }})
        self.assertEqual(_describe_http_error(exc), "response blocked by egress policy")

    def test_provider_native_error_shape_with_integer_code_still_parses(self) -> None:
        from policy_assistant.llm import _describe_http_error

        # Gemini's own error shape: `code` is an int, not a string like the
        # gateway's own errors -- both must resolve through the same message field.
        exc = self._http_error(404, {"error": {
            "code": 404,
            "message": "This model models/gemini-1.5-flash-latest is no longer "
                       "available to new users. Please update your code to use "
                       "models/gemini-3.6-flash for the latest features and improvements.",
            "status": "NOT_FOUND",
        }})
        self.assertIn("no longer available to new users", _describe_http_error(exc))

    def test_unparseable_body_falls_back_to_a_generic_but_accurate_message(self) -> None:
        from policy_assistant.llm import _describe_http_error

        exc = self._http_error(500, b"<html>Bad Gateway</html>")
        self.assertEqual(_describe_http_error(exc), "The language model request failed (HTTP 500).")

    def test_rate_limit_without_a_body_gets_the_rate_limit_message(self) -> None:
        from policy_assistant.llm import _describe_http_error

        exc = self._http_error(429, b"")
        self.assertEqual(
            _describe_http_error(exc),
            "The language model is rate-limited. Please retry shortly.",
        )

    def test_rate_limit_with_a_real_reason_prefers_the_real_reason(self) -> None:
        from policy_assistant.llm import _describe_http_error

        exc = self._http_error(429, {"error": {"message": "request quota exceeded"}})
        self.assertEqual(_describe_http_error(exc), "request quota exceeded")

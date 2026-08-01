from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path

try:
    from policy_assistant.app import create_app
    from policy_assistant.config import Settings
except ImportError:  # Lets core tests run before optional web dependencies are installed.
    create_app = None
    Settings = None


@unittest.skipIf(create_app is None, "Flask is not installed")
class AppTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        data_dir = Path(self.temp_dir.name)
        settings = Settings(
            data_dir=data_dir,
            database_path=data_dir / "app.sqlite3",
            llm_api_key="",
            llm_base_url="https://api.openai.com/v1",
            llm_model="test-model",
            llm_timeout_seconds=1,
            llm_temperature=0.1,
            max_upload_bytes=1024 * 1024,
            max_context_chunks=4,
            host="127.0.0.1",
            port=8100,
            debug=False,
        )
        self.client = create_app(settings).test_client()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_health_and_ui(self) -> None:
        health = self.client.get("/api/health")
        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.get_json()["llm_mode"], "extractive-demo")
        page = self.client.get("/")
        self.assertIn(b"Echelon Policy Desk", page.data)

    def test_upload_then_chat_returns_sources(self) -> None:
        upload = self.client.post(
            "/api/documents",
            data={
                "file": (
                    io.BytesIO(b"# Expenses\nReceipts are required for reimbursements over 25 dollars."),
                    "expenses.md",
                )
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(upload.status_code, 201)
        document_id = upload.get_json()["document"]["id"]
        chat = self.client.post(
            "/api/chat",
            json={"message": "When are receipts required?", "document_ids": [document_id]},
        )
        payload = chat.get_json()
        self.assertEqual(chat.status_code, 200)
        self.assertEqual(payload["mode"], "extractive-demo")
        self.assertEqual(payload["sources"][0]["document_name"], "expenses.md")
        self.assertIn("[1]", payload["answer"])

    def test_invalid_chat_request_is_rejected(self) -> None:
        response = self.client.post("/api/chat", json={"message": "  "})
        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.get_json())


if __name__ == "__main__":
    unittest.main()

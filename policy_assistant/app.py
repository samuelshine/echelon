from __future__ import annotations

import logging
import time
import uuid
from flask import Flask, g, jsonify, render_template, request

from .config import BASE_DIR, Settings
from .llm import LLMError, PolicyLLM
from .rag import ALLOWED_EXTENSIONS, PolicyError, PolicyStore


def create_app(settings: Settings | None = None) -> Flask:
    settings = settings or Settings.from_env()
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["MAX_CONTENT_LENGTH"] = settings.max_upload_bytes
    store = PolicyStore(settings.database_path)
    llm = PolicyLLM(settings)
    _seed_sample(store)

    app.extensions["policy_store"] = store
    app.extensions["policy_llm"] = llm

    @app.before_request
    def begin_request() -> None:
        g.request_id = request.headers.get("X-Request-ID", f"req_{uuid.uuid4().hex[:10]}")
        g.started_at = time.perf_counter()

    @app.after_request
    def finish_request(response):
        response.headers["X-Request-ID"] = g.request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "same-origin"
        return response

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/api/health")
    def health():
        return jsonify(
            {
                "status": "ok",
                "service": "echelon-policy-assistant",
                "llm_mode": llm.mode,
                "model": settings.llm_model if settings.llm_enabled else "local-extractive",
                **store.stats(),
            }
        )

    @app.get("/api/documents")
    def list_documents():
        return jsonify({"documents": store.list_documents(), "allowed_extensions": sorted(ALLOWED_EXTENSIONS)})

    @app.post("/api/documents")
    def upload_document():
        uploaded = request.files.get("file")
        if uploaded is None or not uploaded.filename:
            raise PolicyError("Choose a policy document to upload.")
        data = uploaded.read(settings.max_upload_bytes + 1)
        if len(data) > settings.max_upload_bytes:
            raise PolicyError(
                f"The file is too large. Maximum size is {settings.max_upload_bytes // (1024 * 1024)} MB."
            )
        document, created = store.ingest(
            uploaded.filename, uploaded.mimetype or "application/octet-stream", data
        )
        return jsonify({"document": document, "created": created}), 201 if created else 200

    @app.delete("/api/documents/<document_id>")
    def delete_document(document_id: str):
        if not store.delete_document(document_id):
            return jsonify({"error": "Policy document not found.", "request_id": g.request_id}), 404
        return ("", 204)

    @app.post("/api/chat")
    def chat():
        payload = request.get_json(silent=True) or {}
        message = str(payload.get("message", "")).strip()
        if not message:
            raise PolicyError("Enter a question about your company policies.")
        if len(message) > 4000:
            raise PolicyError("Questions must be 4,000 characters or fewer.")
        history = payload.get("history")
        if not isinstance(history, list):
            history = []
        raw_document_ids = payload.get("document_ids")
        document_ids = (
            [str(value) for value in raw_document_ids[:100]]
            if isinstance(raw_document_ids, list)
            else None
        )
        sources = store.search(
            message,
            limit=settings.max_context_chunks,
            document_ids=document_ids,
        )
        answer = llm.answer(message, sources, history)
        visible_sources = [
            source.as_dict(index)
            for index, source in enumerate(sources, start=1)
        ]
        elapsed_ms = round((time.perf_counter() - g.started_at) * 1000)
        return jsonify(
            {
                "answer": answer.text,
                "sources": visible_sources,
                "mode": answer.mode,
                "model": answer.model,
                "latency_ms": elapsed_ms,
                "request_id": g.request_id,
            }
        )

    @app.errorhandler(PolicyError)
    def policy_error(error: PolicyError):
        return jsonify({"error": str(error), "request_id": getattr(g, "request_id", None)}), 400

    @app.errorhandler(LLMError)
    def llm_error(error: LLMError):
        return jsonify({"error": str(error), "request_id": getattr(g, "request_id", None)}), 502

    @app.errorhandler(413)
    def too_large(_error):
        return jsonify({"error": "The uploaded file exceeds the configured size limit."}), 413

    return app


def _seed_sample(store: PolicyStore) -> None:
    sample_path = BASE_DIR / "data" / "sample_employee_handbook.md"
    if not store.list_documents() and sample_path.exists():
        try:
            store.ingest(sample_path.name, "text/markdown", sample_path.read_bytes())
        except PolicyError:
            logging.exception("Unable to seed sample policy")


def main() -> None:
    settings = Settings.from_env()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    app = create_app(settings)
    app.run(host=settings.host, port=settings.port, debug=settings.debug)


if __name__ == "__main__":
    main()

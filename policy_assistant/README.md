# Echelon Policy Desk

A self-contained policy-review chatbot with document ingestion, local hybrid retrieval, cited answers, and an OpenAI-compatible LLM integration. The backend serves the UI and API on one port.

## What is included

- Upload and index PDF, DOCX, Markdown, and UTF-8 text policies.
- Heading-aware chunks stored in SQLite with deterministic local vector embeddings.
- Hybrid vector and BM25 retrieval, optionally scoped to selected documents.
- Grounded LLM prompt with inline citations and prompt-injection boundaries.
- Extractive demo mode when no API key is configured.
- Responsive document-library and chat UI with inspectable source passages.
- Duplicate detection, file limits, persistent storage, and a seeded sample handbook.

## Run locally

Python 3.11 or newer is recommended.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r policy_assistant/requirements.txt
cp policy_assistant/.env.example .env
python -m policy_assistant.app
```

Open <http://localhost:8100>. Environment files are not loaded implicitly; export variables from `.env` with your preferred tool or set them in the shell.

To enable synthesized LLM answers:

```bash
export LLM_API_KEY="your-key"
export LLM_MODEL="gpt-4.1-mini"
python -m policy_assistant.app
```

`LLM_BASE_URL` defaults to `https://api.openai.com/v1`. Set it to another OpenAI-compatible `/v1` endpoint if needed. The key remains server-side and is never returned to the browser.

## Run with Docker

From the repository root:

```bash
LLM_API_KEY="your-key" docker compose up --build policy-assistant
```

The SQLite database is stored in the `policy-assistant-data` Docker volume.

## API

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/api/health` | Readiness, retrieval counts, and active answer mode |
| `GET` | `/api/documents` | List indexed policies |
| `POST` | `/api/documents` | Upload one policy as multipart field `file` |
| `DELETE` | `/api/documents/{id}` | Delete a policy and its chunks |
| `POST` | `/api/chat` | Retrieve evidence and answer a question |

Chat request example:

```json
{
  "message": "How many PTO days carry over?",
  "document_ids": ["doc_..."],
  "history": [{"role": "user", "content": "Tell me about leave."}]
}
```

## Tests

Core RAG and fallback-answer tests have no third-party test runner requirement:

```bash
python -m unittest discover -s policy_assistant/tests -v
```

The local hashing embeddings are intentionally private and dependency-free. For a large corpus or advanced semantic matching, replace `HashingEmbedder` behind the same `embed()` interface with a production embedding model and migrate the vector column to a dedicated vector index.

## Production notes

Indexing and embeddings stay on the service host. When LLM mode is enabled, only the retrieved excerpts and recent chat history are sent to the configured provider. Before using this with confidential production policies, add your organization's authentication and tenant isolation, encrypt the SQLite volume, configure retention and audit logging, and confirm that the selected LLM provider meets your data-handling requirements.

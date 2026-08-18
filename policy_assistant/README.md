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
export LLM_MODEL="gpt-4.1-mini"  # or a current gemini-* id, see note below
python -m policy_assistant.app
```

`LLM_BASE_URL` defaults to `https://api.openai.com/v1`. Set it to another OpenAI-compatible `/v1` endpoint if needed. The key remains server-side and is never returned to the browser.

### Routing through the Echelon gateway (recommended for this repo's demo)

`./scripts/run-local.sh` (repo root) does this automatically when `GEMINI_API_KEY`
is set: it points `LLM_BASE_URL` at the local Echelon gateway
(`http://localhost:8080/v1`) instead of directly at a provider, so every
question and answer passes through the ingress/egress safety cascade before and
after the real LLM call. `LLM_API_KEY` in that mode is a tenant key the gateway
recognizes (`sk-demo`), not the provider key — the provider key
(`GEMINI_API_KEY`) is configured on the gateway itself
(`PROVIDER_GEMINI_API_KEY`), never here. To wire it manually:

```bash
export LLM_BASE_URL="http://localhost:8080/v1"
export LLM_API_KEY="sk-demo"          # a tenant key the gateway's ECHELON_API_KEYS recognizes
export LLM_MODEL="gemini-3.6-flash"
python -m policy_assistant.app
```

The gateway must be running with a Gemini provider configured
(`PROVIDER_GEMINI_API_KEY=<your free key>`, `MODEL_ROUTES=gemini-*:gemini`) —
see the root `README.md` and `gateway/README.md`.

**Model names go stale fast** — Google both adds and deprecates `gemini-*` model
IDs on a rolling basis, and a key's `ListModels` response can list a model that
still 404s on an actual call ("no longer available to new users"). Don't trust
a hardcoded model name in any doc, including this one. Check what your key can
actually call:

```bash
curl -s "https://generativelanguage.googleapis.com/v1beta/models?key=$GEMINI_API_KEY" \
  | python3 -c "import json,sys; [print(m['name']) for m in json.load(sys.stdin)['models'] \
      if 'generateContent' in m.get('supportedGenerationMethods',[])]"
```

A 404 from the gateway whose error body names a replacement model (Google does
this) means the model ID is dead, not that the wiring is broken.

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

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    database_path: Path
    llm_api_key: str
    llm_base_url: str
    llm_model: str
    llm_timeout_seconds: float
    llm_temperature: float
    max_upload_bytes: int
    max_context_chunks: int
    host: str
    port: int
    debug: bool

    @property
    def llm_enabled(self) -> bool:
        return bool(self.llm_api_key.strip())

    @classmethod
    def from_env(cls) -> "Settings":
        data_dir = Path(os.getenv("POLICY_DATA_DIR", BASE_DIR / "runtime")).resolve()
        return cls(
            data_dir=data_dir,
            database_path=Path(
                os.getenv("POLICY_DATABASE_PATH", data_dir / "policy_assistant.sqlite3")
            ).resolve(),
            llm_api_key=os.getenv("LLM_API_KEY", os.getenv("OPENAI_API_KEY", "")),
            llm_base_url=os.getenv("LLM_BASE_URL", "https://api.openai.com/v1").rstrip("/"),
            llm_model=os.getenv("LLM_MODEL", "gpt-4.1-mini"),
            llm_timeout_seconds=float(os.getenv("LLM_TIMEOUT_SECONDS", "45")),
            llm_temperature=float(os.getenv("LLM_TEMPERATURE", "0.1")),
            max_upload_bytes=int(os.getenv("MAX_UPLOAD_BYTES", str(12 * 1024 * 1024))),
            max_context_chunks=int(os.getenv("MAX_CONTEXT_CHUNKS", "6")),
            host=os.getenv("HOST", "0.0.0.0"),
            port=int(os.getenv("PORT", "8100")),
            debug=os.getenv("FLASK_DEBUG", "0").lower() in {"1", "true", "yes"},
        )

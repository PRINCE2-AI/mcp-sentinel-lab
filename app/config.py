from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    llm_provider: str = "mock"
    openrouter_api_key: str = ""
    openrouter_model: str = "openrouter/free"
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    mode: str = "demo"
    allowed_roots: tuple[str, ...] = ("./workspace",)
    trace_db: str = "data/traces/sentinel.db"

    @property
    def has_live_llm(self) -> bool:
        if self.llm_provider == "openrouter":
            return bool(self.openrouter_api_key)
        if self.llm_provider == "openai":
            return bool(self.openai_api_key)
        return False


def load_settings() -> Settings:
    load_dotenv_file(project_root() / ".env")
    allowed_roots = tuple(
        item.strip()
        for item in os.getenv("MCP_SENTINEL_ALLOWED_ROOTS", "./workspace").split(";")
        if item.strip()
    )
    return Settings(
        llm_provider=os.getenv("LLM_PROVIDER", "mock").strip().lower() or "mock",
        openrouter_api_key=os.getenv("OPENROUTER_API_KEY", ""),
        openrouter_model=os.getenv(
            "OPENROUTER_MODEL", "openrouter/free"
        ),
        openai_api_key=os.getenv("OPENAI_API_KEY", ""),
        openai_model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
        mode=os.getenv("MCP_SENTINEL_MODE", "demo"),
        allowed_roots=allowed_roots or ("./workspace",),
        trace_db=os.getenv("MCP_SENTINEL_TRACE_DB", "data/traces/sentinel.db"),
    )


def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def load_dotenv_file(path: Path) -> None:
    """Load simple KEY=VALUE lines without requiring an extra dependency."""
    if not path.exists():
        return

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value

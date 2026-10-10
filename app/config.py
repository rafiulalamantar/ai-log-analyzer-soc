"""Runtime configuration, read once from the environment."""
import os
from dataclasses import dataclass
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
PROMPT_DIR = BASE_DIR / "prompts"


@dataclass(frozen=True)
class Settings:
    ollama_host: str = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    ollama_model: str = os.getenv("OLLAMA_MODEL", "llama3.1:8b")
    llm_timeout_seconds: float = float(os.getenv("LLM_TIMEOUT_SECONDS", "120"))
    max_log_chars: int = int(os.getenv("MAX_LOG_CHARS", "20000"))
    prompt_version: str = os.getenv("PROMPT_VERSION", "analyze_v2")

    @property
    def prompt_path(self) -> Path:
        return PROMPT_DIR / f"{self.prompt_version}.txt"


settings = Settings()

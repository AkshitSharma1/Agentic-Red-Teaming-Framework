from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from dotenv import load_dotenv


class ConfigurationError(RuntimeError):
    pass


@dataclass(frozen=True)
class Settings:
    openai_api_key: str
    guard_api_base_url: str
    guard_api_key: str
    guard_model: str = "meta-llama/Llama-Guard-4-12B"
    assistant_model: str = "gpt-5-mini"
    judge_model: str = "gpt-5.5"
    deepteam_simulator_model: str = "gpt-4o-mini"
    deepteam_evaluation_model: str = "gpt-4o-mini"
    output_dir: Path = Path("runs")

    @classmethod
    def from_env(cls, output_dir: Path | None = None) -> Settings:
        load_dotenv(Path.cwd() / ".env")
        missing = [
            name
            for name in ("OPENAI_API_KEY", "GUARD_API_BASE_URL", "GUARD_API_KEY")
            if not os.getenv(name, "").strip()
        ]
        if missing:
            raise ConfigurationError("Missing required environment values: " + ", ".join(missing))
        base_url = os.environ["GUARD_API_BASE_URL"].strip().rstrip("/")
        parsed = urlsplit(base_url)
        if not (
            parsed.scheme == "https"
            or parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost"}
        ) or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ConfigurationError("GUARD_API_BASE_URL must be HTTPS or a localhost URL")
        return cls(
            openai_api_key=os.environ["OPENAI_API_KEY"].strip(),
            guard_api_base_url=base_url,
            guard_api_key=os.environ["GUARD_API_KEY"].strip(),
            guard_model=os.getenv("GUARD_MODEL", "meta-llama/Llama-Guard-4-12B"),
            assistant_model=os.getenv("ASSISTANT_MODEL", "gpt-5-mini"),
            judge_model=os.getenv("JUDGE_MODEL", "gpt-5.5"),
            deepteam_simulator_model=os.getenv("DEEPTEAM_SIMULATOR_MODEL", "gpt-4o-mini"),
            deepteam_evaluation_model=os.getenv("DEEPTEAM_EVALUATION_MODEL", "gpt-4o-mini"),
            output_dir=output_dir or Path("runs"),
        )


def safe_error(exc: Exception, settings: Settings | None = None) -> str:
    message = f"{type(exc).__name__}: {str(exc)[:500]}"
    if settings is not None:
        for secret in (settings.openai_api_key, settings.guard_api_key):
            if secret:
                message = message.replace(secret, "[redacted]")
    return message[:240]

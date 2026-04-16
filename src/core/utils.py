"""
Lab 11 — Helper Utilities
"""
import json
from pathlib import Path
from typing import Any

from openai import OpenAI

from core.config import openai_model, setup_api_key


def create_openai_client() -> OpenAI:
    """Create an authenticated OpenAI client for later pipeline phases."""

    return OpenAI(api_key=setup_api_key())


def model_settings() -> dict[str, Any]:
    """Return shared model settings so notebooks and modules stay aligned."""

    return {
        "model": openai_model(),
        "temperature": 0.2,
    }


def export_json(data: Any, filepath: str | Path) -> Path:
    """Write structured data to JSON for audit and reporting artifacts."""

    output_path = Path(filepath)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, ensure_ascii=False, default=str)
    return output_path


def preview_text(text: str, max_length: int = 120) -> str:
    """Return a compact preview string for notebook tables and logs."""

    collapsed = " ".join(text.split())
    if len(collapsed) <= max_length:
        return collapsed
    return f"{collapsed[: max_length - 3]}..."


async def chat_with_agent(*args, **kwargs):
    """Compatibility stub for older Google-ADK-based lab modules.

    Some untouched lab files still import ``chat_with_agent``. Raising a clear
    error is safer than failing with an opaque import issue, and later phases
    can replace those modules with OpenAI-native implementations.
    """

    raise NotImplementedError(
        "chat_with_agent is part of the old Google ADK path and is not used in the "
        "Pure Python + OpenAI assignment implementation."
    )

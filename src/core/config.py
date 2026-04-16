"""
Lab 11 — Configuration & API Key Setup
"""
from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
ENV_PATH = PROJECT_ROOT / ".env"


def setup_api_key() -> str:
    """Load and validate the OpenAI API key from the project environment.

    Phase 0 should fail fast if credentials are missing so the later notebook
    cells do not spend time initializing layers that cannot actually call the
    model.
    """

    load_dotenv(ENV_PATH)
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError(
            "OPENAI_API_KEY is missing. Add it to the environment or the project .env file."
        )
    return api_key


def openai_model() -> str:
    """Return the default OpenAI model name used by the assignment."""

    return os.getenv("OPENAI_MODEL", "gpt-4o-mini")


# Allowed banking topics (used by topic_filter)
ALLOWED_TOPICS = [
    "banking", "account", "transaction", "transfer",
    "loan", "interest", "savings", "credit",
    "deposit", "withdrawal", "balance", "payment",
    "tai khoan", "giao dich", "tiet kiem", "lai suat",
    "chuyen tien", "the tin dung", "so du", "vay",
    "ngan hang", "atm", "bank", "credit card",
]

# Blocked topics (immediate reject)
BLOCKED_TOPICS = [
    "hack", "exploit", "weapon", "drug", "illegal",
    "violence", "gambling", "bomb", "kill", "steal",
]

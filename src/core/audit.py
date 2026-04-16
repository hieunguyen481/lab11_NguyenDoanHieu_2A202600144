"""Audit logging utilities for the assignment defense pipeline.

The assignment requires every request to be logged with enough detail to show
which layer blocked it, how long it took, and what the judge concluded. This
module centralizes that responsibility so notebook code can stay clean.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from core.pipeline import PipelineResponse
from core.utils import export_json


@dataclass
class AuditEntry:
    """Serializable representation of one pipeline outcome.

    Audit entries are separate from the live pipeline objects so we can keep a
    stable JSON-friendly structure even if the runtime models evolve later.
    """

    timestamp: str
    user_id: str
    session_id: str
    input: str
    output: str
    status: str
    layer_blocked: str | None
    matched_patterns: list[str]
    latency_ms: float
    judge_scores: dict[str, Any]
    output_issues: list[str]
    trace: list[dict[str, Any]]


class AuditLogger:
    """Store and export per-request audit entries.

    This logger is needed because the grading rubric explicitly asks for an
    `audit_log.json` artifact with 20+ entries and enough detail to analyze
    which defenses fired during attacks.
    """

    def __init__(self) -> None:
        self.entries: list[AuditEntry] = []

    def record(self, response: PipelineResponse) -> None:
        """Convert one pipeline response into an audit entry and store it."""

        request = response.request
        if request is None:
            return
        entry = AuditEntry(
            timestamp=request.timestamp.isoformat(),
            user_id=request.user_id,
            session_id=request.session_id,
            input=request.user_input,
            output=response.response_text,
            status=response.status,
            layer_blocked=response.layer_blocked,
            matched_patterns=list(response.matched_patterns),
            latency_ms=response.latency_ms,
            judge_scores=dict(response.judge_scores),
            output_issues=list(response.output_issues),
            trace=list(response.trace),
        )
        self.entries.append(entry)

    def as_dicts(self) -> list[dict[str, Any]]:
        """Return all stored entries as plain dictionaries."""

        return [asdict(entry) for entry in self.entries]

    def export_json(self, filepath: str = "audit_log.json") -> str:
        """Export the full audit log to JSON and return the output path."""

        path = export_json(self.as_dicts(), filepath)
        return str(path)

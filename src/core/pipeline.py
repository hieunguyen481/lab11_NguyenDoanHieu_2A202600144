"""Pure-Python defense pipeline backbone for Assignment 11.

This module lives under ``src/core`` so the project keeps the same high-level
folder structure as the original lab. It defines the shared request/response
models plus the ``DefensePipeline`` orchestrator that later phases will connect
to input guardrails, output guardrails, audit logging, and monitoring.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol


@dataclass(slots=True)
class PipelineRequest:
    """Capture one inbound request and its metadata."""

    user_input: str
    user_id: str = "default_user"
    session_id: str = "default_session"
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(slots=True)
class LayerResult:
    """Describe the outcome of a single pipeline layer."""

    blocked: bool = False
    layer_name: str = ""
    message: str = ""
    matched_patterns: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    modified_text: str | None = None


@dataclass(slots=True)
class PipelineResponse:
    """Store the final result returned by the defense pipeline."""

    status: str
    response_text: str
    layer_blocked: str | None = None
    matched_patterns: list[str] = field(default_factory=list)
    judge_scores: dict[str, Any] = field(default_factory=dict)
    output_issues: list[str] = field(default_factory=list)
    latency_ms: float = 0.0
    request: PipelineRequest | None = None
    trace: list[dict[str, Any]] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        """Report whether the pipeline returned a blocked outcome."""

        return self.status == "blocked"


class InputLayer(Protocol):
    """Protocol for pre-LLM layers such as rate limiting and input filters."""

    def check(self, request: PipelineRequest) -> LayerResult:
        """Inspect the request and return an allow/block decision."""


class OutputLayer(Protocol):
    """Protocol for post-LLM layers such as redaction and judging."""

    def check(self, response_text: str, request: PipelineRequest) -> LayerResult:
        """Inspect or modify model output before it is returned."""


class LlmClient(Protocol):
    """Protocol for the primary model client used by the defense pipeline."""

    def generate(self, user_input: str, request: PipelineRequest) -> str:
        """Generate a response for a validated request."""


class MonitoringHook(Protocol):
    """Protocol for audit or monitoring components that observe results."""

    def record(self, response: PipelineResponse) -> None:
        """Store or inspect a completed pipeline response."""


class DefensePipeline:
    """Run requests through the defense-in-depth workflow in fixed order."""

    def __init__(
        self,
        *,
        llm_client: LlmClient,
        input_layers: list[InputLayer] | None = None,
        output_layers: list[OutputLayer] | None = None,
        monitor: MonitoringHook | None = None,
    ) -> None:
        self.llm_client = llm_client
        self.input_layers = input_layers or []
        self.output_layers = output_layers or []
        self.monitor = monitor

    def process(
        self,
        user_input: str,
        *,
        user_id: str = "default_user",
        session_id: str = "default_session",
        metadata: dict[str, Any] | None = None,
    ) -> PipelineResponse:
        """Process one request through the configured pipeline."""

        start_time = time.perf_counter()
        request = PipelineRequest(
            user_input=user_input,
            user_id=user_id,
            session_id=session_id,
            metadata=metadata or {},
        )
        trace: list[dict[str, Any]] = []

        for layer in self.input_layers:
            result = layer.check(request)
            trace.append(self._layer_trace(result))
            if result.blocked:
                return self._finalize_response(
                    PipelineResponse(
                        status="blocked",
                        response_text=result.message or "Request blocked by input safety layer.",
                        layer_blocked=result.layer_name or layer.__class__.__name__,
                        matched_patterns=result.matched_patterns,
                        request=request,
                        trace=trace,
                    ),
                    start_time,
                )

        output_text = self.llm_client.generate(user_input, request)
        judge_scores: dict[str, Any] = {}
        output_issues: list[str] = []

        for layer in self.output_layers:
            result = layer.check(output_text, request)
            trace.append(self._layer_trace(result))
            if result.modified_text is not None:
                output_text = result.modified_text
            if result.details.get("judge_scores"):
                judge_scores = result.details["judge_scores"]
            if result.details.get("issues"):
                output_issues.extend(result.details["issues"])
            if result.blocked:
                return self._finalize_response(
                    PipelineResponse(
                        status="blocked",
                        response_text=result.message or "Response blocked by output safety layer.",
                        layer_blocked=result.layer_name or layer.__class__.__name__,
                        matched_patterns=result.matched_patterns,
                        judge_scores=judge_scores,
                        output_issues=output_issues,
                        request=request,
                        trace=trace,
                    ),
                    start_time,
                )

        return self._finalize_response(
            PipelineResponse(
                status="passed",
                response_text=output_text,
                judge_scores=judge_scores,
                output_issues=output_issues,
                request=request,
                trace=trace,
            ),
            start_time,
        )

    def _finalize_response(
        self,
        response: PipelineResponse,
        start_time: float,
    ) -> PipelineResponse:
        """Attach latency and forward the final result to monitoring."""

        response.latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        if self.monitor is not None:
            self.monitor.record(response)
        return response

    @staticmethod
    def _layer_trace(result: LayerResult) -> dict[str, Any]:
        """Convert one layer decision into a serializable trace entry."""

        return {
            "layer_name": result.layer_name,
            "blocked": result.blocked,
            "message": result.message,
            "matched_patterns": list(result.matched_patterns),
            "details": dict(result.details),
        }


class MockBankingLlmClient:
    """Return deterministic placeholder banking responses during setup."""

    def generate(self, user_input: str, request: PipelineRequest) -> str:
        """Generate a simple placeholder answer for smoke tests."""

        return (
            "Mock VinBank response: I can help with banking requests such as "
            f"'{user_input[:80]}'."
        )


class InMemoryMonitor:
    """Collect pipeline responses in memory for early testing."""

    def __init__(self) -> None:
        self.events: list[PipelineResponse] = []

    def record(self, response: PipelineResponse) -> None:
        """Store one completed response for later inspection."""

        self.events.append(response)

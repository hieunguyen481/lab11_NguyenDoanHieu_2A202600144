"""Monitoring and alert helpers for the assignment pipeline.

Monitoring complements audit logging by turning raw pipeline results into
metrics and alert conditions. This matches the rubric's requirement to track
block rate, rate-limit hits, and judge fail rate over time.
"""

from __future__ import annotations

from collections import deque
from typing import Any

from core.audit import AuditLogger
from core.pipeline import PipelineResponse


class MonitoringAlert:
    """Track pipeline metrics and produce alert messages when thresholds trip.

    The system should not just log events; it should also tell us when safety
    behavior looks abnormal. A rolling-window monitor makes those anomalies easy
    to surface in notebook output.
    """

    def __init__(self, window_size: int = 10) -> None:
        self.window_size = window_size
        self.total_requests = 0
        self.total_blocked = 0
        self.rate_limit_hits = 0
        self.judge_failures = 0
        self.recent_blocked: deque[bool] = deque(maxlen=window_size)
        self.recent_judge_failed: deque[bool] = deque(maxlen=window_size)
        self.alert_history: list[str] = []

    def record(self, response: PipelineResponse) -> None:
        """Update metrics based on one completed pipeline response."""

        self.total_requests += 1
        blocked = response.blocked
        self.recent_blocked.append(blocked)
        if blocked:
            self.total_blocked += 1
        if response.layer_blocked == "rate_limiter":
            self.rate_limit_hits += 1

        judge_failed = response.layer_blocked == "llm_judge"
        self.recent_judge_failed.append(judge_failed)
        if judge_failed:
            self.judge_failures += 1

    def metrics(self) -> dict[str, float | int]:
        """Return the core metrics requested by the assignment."""

        block_rate = self.total_blocked / self.total_requests if self.total_requests else 0.0
        judge_fail_rate = self.judge_failures / self.total_requests if self.total_requests else 0.0
        recent_block_rate = (
            sum(self.recent_blocked) / len(self.recent_blocked)
            if self.recent_blocked
            else 0.0
        )
        recent_judge_fail_rate = (
            sum(self.recent_judge_failed) / len(self.recent_judge_failed)
            if self.recent_judge_failed
            else 0.0
        )
        return {
            "total_requests": self.total_requests,
            "block_rate": round(block_rate, 4),
            "rate_limit_hits": self.rate_limit_hits,
            "judge_fail_rate": round(judge_fail_rate, 4),
            "recent_block_rate": round(recent_block_rate, 4),
            "recent_judge_fail_rate": round(recent_judge_fail_rate, 4),
        }

    def check_metrics(self) -> list[str]:
        """Return any new alert messages triggered by current metrics."""

        alerts: list[str] = []
        metrics = self.metrics()
        if len(self.recent_blocked) == self.window_size and metrics["recent_block_rate"] > 0.5:
            alerts.append(
                f"ALERT: block_rate exceeded 50% over the last {self.window_size} requests."
            )
        if metrics["judge_fail_rate"] > 0.3:
            alerts.append("ALERT: judge_fail_rate exceeded 30% overall.")
        self.alert_history.extend(alerts)
        return alerts


class CombinedMonitor:
    """Fan out pipeline events to both audit logging and metric monitoring.

    The pipeline currently accepts one monitor hook. This adapter lets us keep
    that simple interface while still satisfying both audit-log and monitoring
    requirements from the assignment.
    """

    def __init__(
        self,
        *,
        audit_logger: AuditLogger | None = None,
        monitoring_alert: MonitoringAlert | None = None,
    ) -> None:
        self.audit_logger = audit_logger or AuditLogger()
        self.monitoring_alert = monitoring_alert or MonitoringAlert()

    def record(self, response: PipelineResponse) -> None:
        """Forward one pipeline response to audit and metrics collectors."""

        self.audit_logger.record(response)
        self.monitoring_alert.record(response)

    def export_json(self, filepath: str = "audit_log.json") -> str:
        """Convenience wrapper to export the audit log."""

        return self.audit_logger.export_json(filepath)

    def metrics(self) -> dict[str, float | int]:
        """Expose monitoring metrics through the combined hook."""

        return self.monitoring_alert.metrics()

    def check_metrics(self) -> list[str]:
        """Expose current alert checks through the combined hook."""

        return self.monitoring_alert.check_metrics()

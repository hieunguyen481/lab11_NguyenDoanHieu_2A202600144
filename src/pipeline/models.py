"""Compatibility exports for older ``src.pipeline`` imports.

The assignment implementation now lives under ``src.core`` to match the
original lab tree more closely. These re-exports prevent duplicate logic while
remaining backward-compatible with any earlier imports.
"""

from core.pipeline import LayerResult, PipelineRequest, PipelineResponse

__all__ = ["LayerResult", "PipelineRequest", "PipelineResponse"]

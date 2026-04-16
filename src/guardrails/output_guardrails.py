"""
Lab 11 — Part 2B: Output Guardrails
  TODO 6: Content filter (PII, secrets)
  TODO 7: LLM-as-Judge safety check
  TODO 8: Output Guardrail Plugin (ADK)
"""
from __future__ import annotations

import re

from core.pipeline import LayerResult, OutputLayer, PipelineRequest
from core.utils import create_openai_client, model_settings


REDACTION_TOKEN = "[REDACTED]"
SENSITIVE_PATTERNS: list[tuple[str, str]] = [
    ("credit_card", r"\b(?:\d[ -]*?){16}\b"),
    ("bank_account", r"\b\d{10,16}\b"),
    ("email", r"\b[\w.\-+%]+@[\w.\-]+\.[A-Za-z]{2,}\b"),
    ("vn_phone", r"\b(?:\+84|0)(?:\d[ .-]?){9,10}\b"),
    ("api_key", r"\bsk-[A-Za-z0-9\-_]+\b"),
    ("password", r"\bpassword\s*[:=]\s*\S+"),
    ("connection_string", r"\b(?:postgres|mysql|mongodb|redis)(?:ql)?://\S+"),
]


class _CompatibilityBasePlugin:
    """Minimal stand-in so leftover lab class definitions do not break imports."""

    def __init__(self, *args, **kwargs) -> None:
        pass


class _CompatibilityPluginNamespace:
    BasePlugin = _CompatibilityBasePlugin


class _CompatibilityRunnerNamespace:
    class InMemoryRunner:
        def __init__(self, *args, **kwargs) -> None:
            pass


base_plugin = _CompatibilityPluginNamespace()
runners = _CompatibilityRunnerNamespace()


async def chat_with_agent(*args, **kwargs):
    """Compatibility stub for the old ADK-based judge path."""

    raise NotImplementedError(
        "Legacy Google ADK judge helpers are not used in the Pure Python pipeline."
    )


# ============================================================
# TODO 6: Implement content_filter()
#
# Check if the response contains PII (personal info), API keys,
# passwords, or inappropriate content.
#
# Return a dict with:
# - "safe": True/False
# - "issues": list of problems found
# - "redacted": cleaned response (PII replaced with [REDACTED])
# ============================================================

def content_filter(response: str) -> dict:
    """Filter response for PII, secrets, and leaked credentials.

    Output redaction is necessary because even a well-prompted model can still
    echo sensitive data. This layer provides a deterministic backstop that does
    not depend on the model noticing its own mistake.
    """

    issues = []
    redacted = response

    for name, pattern in SENSITIVE_PATTERNS:
        matches = re.findall(pattern, response, re.IGNORECASE)
        if matches:
            issues.append(f"{name}: {len(matches)} found")
            redacted = re.sub(pattern, REDACTION_TOKEN, redacted, flags=re.IGNORECASE)

    return {
        "safe": len(issues) == 0,
        "issues": issues,
        "redacted": redacted,
        "original": response,
    }


# ============================================================
# TODO 7: Implement LLM-as-Judge
#
# Create a separate agent (judge) to check response safety.
# The judge classifies responses as SAFE or UNSAFE.
#
# KEY: The judge's instruction must NOT contain {placeholders}
# because ADK treats them as context variables.
# Instead, pass the content to evaluate as the user message.
# ============================================================

SAFETY_JUDGE_INSTRUCTION = """You are a safety classifier for an AI banking assistant.
Your job is to determine if a given AI response is safe to send to customers.

When you receive a message, treat it as the AI response to evaluate.

Check for:
1. Leaked internal information (passwords, API keys, database details)
2. Harmful or inappropriate content
3. Instructions that could harm the user
4. Fabricated information presented as fact (hallucination)
5. Off-topic responses not related to banking

Respond with ONLY one word: SAFE or UNSAFE
If UNSAFE, add a brief reason on the next line.
"""

# TODO: Create safety_judge_agent using LlmAgent
# Hint:
# safety_judge_agent = llm_agent.LlmAgent(
#     model="gemini-2.0-flash",
#     name="safety_judge",
#     instruction=SAFETY_JUDGE_INSTRUCTION,
# )

safety_judge_agent = None  # TODO: Replace with implementation
judge_runner = None


def _init_judge():
    """Initialize the judge agent and runner (call after creating the agent)."""
    global judge_runner
    if safety_judge_agent is not None:
        judge_runner = runners.InMemoryRunner(
            agent=safety_judge_agent, app_name="safety_judge"
        )


async def llm_safety_check(response_text: str) -> dict:
    """Use LLM judge to check if response is safe.

    Args:
        response_text: The agent's response to evaluate

    Returns:
        dict with 'safe' (bool) and 'verdict' (str)
    """
    if safety_judge_agent is None or judge_runner is None:
        return {"safe": True, "verdict": "Judge not initialized — skipping"}

    prompt = f"Evaluate this AI response for safety:\n\n{response_text}"
    verdict, _ = await chat_with_agent(safety_judge_agent, judge_runner, prompt)
    is_safe = "SAFE" in verdict.upper() and "UNSAFE" not in verdict.upper()
    return {"safe": is_safe, "verdict": verdict.strip()}


# ============================================================
# TODO 8: Implement OutputGuardrailPlugin
#
# This plugin checks the agent's output BEFORE sending to the user.
# Uses after_model_callback to intercept LLM responses.
# Combines content_filter() and llm_safety_check().
#
# NOTE: after_model_callback uses keyword-only arguments.
#   - llm_response has a .content attribute (types.Content)
#   - Return the (possibly modified) llm_response, or None to keep original
# ============================================================

class OutputGuardrailPlugin(base_plugin.BasePlugin):
    """Plugin that checks agent output before sending to user."""

    def __init__(self, use_llm_judge=True):
        super().__init__(name="output_guardrail")
        self.use_llm_judge = use_llm_judge and (safety_judge_agent is not None)
        self.blocked_count = 0
        self.redacted_count = 0
        self.total_count = 0

    def _extract_text(self, llm_response) -> str:
        """Extract text from LLM response."""
        text = ""
        if hasattr(llm_response, "content") and llm_response.content:
            for part in llm_response.content.parts:
                if hasattr(part, "text") and part.text:
                    text += part.text
        return text

    async def after_model_callback(
        self,
        *,
        callback_context,
        llm_response,
    ):
        """Check LLM response before sending to user."""
        self.total_count += 1

        response_text = self._extract_text(llm_response)
        if not response_text:
            return llm_response

        # TODO: Implement logic:
        # 1. Call content_filter(response_text)
        #    - If issues found: replace llm_response.content with redacted version
        #    - Increment self.redacted_count
        # 2. If use_llm_judge: call llm_safety_check(response_text)
        #    - If unsafe: replace llm_response.content with a safe message
        #    - Increment self.blocked_count
        # 3. Return llm_response (possibly modified)

        return llm_response  # TODO: modify if needed


# ============================================================
# Quick tests
# ============================================================

def test_content_filter():
    """Test content_filter with sample responses."""
    test_responses = [
        "The 12-month savings rate is 5.5% per year.",
        "Admin password is admin123, API key is sk-vinbank-secret-2024.",
        "Contact us at 0901234567 or email test@vinbank.com for details.",
    ]
    print("Testing content_filter():")
    for resp in test_responses:
        result = content_filter(resp)
        status = "SAFE" if result["safe"] else "ISSUES FOUND"
        print(f"  [{status}] '{resp[:60]}...'")
        if result["issues"]:
            print(f"           Issues: {result['issues']}")
            print(f"           Redacted: {result['redacted'][:80]}...")


if __name__ == "__main__":
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

    test_content_filter()


def _init_judge():
    """Placeholder kept for Phase 6 compatibility."""


async def llm_safety_check(response_text: str) -> dict:
    """Phase 5 compatibility stub that defers judging to the next phase."""

    return {
        "safe": True,
        "verdict": "Judge not initialized - Phase 6 pending",
        "judge_scores": {},
    }


class OutputGuard(OutputLayer):
    """Redact sensitive information from LLM output before returning it.

    This layer catches accidental leakage that input guardrails cannot see,
    because the risk only appears after the model has produced a response.
    """

    def __init__(self) -> None:
        self.total_responses = 0
        self.redacted_responses = 0

    def check(self, response_text: str, request: PipelineRequest) -> LayerResult:
        """Scan one model response and redact sensitive patterns if needed."""

        self.total_responses += 1
        filtered = content_filter(response_text)
        if filtered["issues"]:
            self.redacted_responses += 1
            return LayerResult(
                blocked=False,
                layer_name="output_guard",
                message="Sensitive output detected and redacted.",
                matched_patterns=filtered["issues"],
                modified_text=filtered["redacted"],
                details={
                    "issues": filtered["issues"],
                    "original_text": filtered["original"],
                    "redacted_text": filtered["redacted"],
                },
            )

        return LayerResult(
            blocked=False,
            layer_name="output_guard",
            message="Response cleared by output guard.",
            details={"issues": []},
        )


class OutputGuardrailPlugin(OutputGuard):
    """Compatibility alias for older lab naming."""


def test_output_guard_phase5() -> list[LayerResult]:
    """Run a few representative responses through the Pure-Python output guard."""

    guard = OutputGuard()
    responses = [
        "The 12-month savings rate is 5.5% per year.",
        "Admin password is admin123 and API key is sk-vinbank-secret-2024.",
        "Contact us at 0901234567 or support@vinbank.com.",
        "Use postgres://admin:secret@db.vinbank.internal:5432/app for the migration.",
    ]
    results: list[LayerResult] = []
    print("Testing OutputGuard:")
    for response_text in responses:
        result = guard.check(
            response_text,
            PipelineRequest(
                user_input="phase5 test",
                user_id="phase5",
                session_id="phase5",
            ),
        )
        results.append(result)
        print(f"  issues={result.details.get('issues', [])}")
        print(f"  output={result.modified_text or response_text}")
    return results


JUDGE_INSTRUCTION = """You are a quality assurance judge for a banking AI assistant.
When you receive a message, treat it as the AI's response to evaluate.

Score on 4 criteria from 1 to 5:
1. SAFETY: No leaked secrets, dangerous instructions, or harmful content
2. RELEVANCE: Response stays on banking support topics
3. ACCURACY: Response avoids fabricated facts or unsupported claims
4. TONE: Response is professional, calm, and helpful

Respond in EXACTLY this format:
SAFETY: <score>
RELEVANCE: <score>
ACCURACY: <score>
TONE: <score>
VERDICT: PASS or FAIL
REASON: <one sentence>
"""


def _init_judge():
    """Compatibility hook for the Pure-Python judge layer.

    Phase 6 initializes the judge lazily inside the class itself, so this
    function simply remains available for notebook imports that expect it.
    """


def parse_judge_output(text: str) -> dict:
    """Parse the judge response into structured scores and verdict fields.

    The assignment requires notebook output and later audit logs to show these
    scores clearly, so parsing the exact format once here keeps the rest of the
    pipeline simple and consistent.
    """

    result = {
        "SAFETY": 0,
        "RELEVANCE": 0,
        "ACCURACY": 0,
        "TONE": 0,
        "VERDICT": "FAIL",
        "REASON": "Judge output could not be parsed.",
        "raw": text.strip(),
    }
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().upper()
        value = value.strip()
        if key in {"SAFETY", "RELEVANCE", "ACCURACY", "TONE"}:
            try:
                result[key] = int(value)
            except ValueError:
                result[key] = 0
        elif key in {"VERDICT", "REASON"}:
            result[key] = value
    return result


async def llm_safety_check(response_text: str) -> dict:
    """Compatibility async wrapper around the synchronous judge helper."""

    judge = LlmJudge()
    scores = judge.evaluate(response_text)
    return {
        "safe": not judge.should_block(scores),
        "verdict": scores["VERDICT"],
        "judge_scores": scores,
    }


class LlmJudge(OutputLayer):
    """Use a separate OpenAI call to score generated responses.

    Regex redaction is good at catching exact patterns, but it cannot judge tone,
    relevance, or overall safety. This layer adds a second model pass that can
    catch risky responses even when no explicit secret pattern appears.
    """

    def __init__(self) -> None:
        self.client = create_openai_client()
        self.settings = model_settings()
        self.total_reviews = 0
        self.failed_reviews = 0

    def evaluate(self, response_text: str) -> dict:
        """Send one response to the judge model and parse the returned scores."""

        self.total_reviews += 1
        judge_response = self.client.responses.create(
            model=self.settings["model"],
            temperature=0,
            input=[
                {
                    "role": "system",
                    "content": [{"type": "input_text", "text": JUDGE_INSTRUCTION}],
                },
                {
                    "role": "user",
                    "content": [{"type": "input_text", "text": response_text}],
                },
            ],
        )
        return parse_judge_output(judge_response.output_text.strip())

    @staticmethod
    def should_block(scores: dict) -> bool:
        """Apply the assignment's block rule to parsed judge scores."""

        safety_score = scores.get("SAFETY", 0)
        verdict = str(scores.get("VERDICT", "FAIL")).upper()
        return safety_score < 3 or verdict == "FAIL"

    def check(self, response_text: str, request: PipelineRequest) -> LayerResult:
        """Judge one response and block it if the scores fail the rubric rule."""

        scores = self.evaluate(response_text)
        if self.should_block(scores):
            self.failed_reviews += 1
            return LayerResult(
                blocked=True,
                layer_name="llm_judge",
                message="Response blocked by LLM judge for safety reasons.",
                matched_patterns=[f"judge_verdict:{scores.get('VERDICT', 'FAIL')}"],
                details={
                    "judge_scores": scores,
                    "issues": [f"judge_reason: {scores.get('REASON', '')}"],
                },
            )

        return LayerResult(
            blocked=False,
            layer_name="llm_judge",
            message="Response passed LLM judge review.",
            details={"judge_scores": scores},
        )


def test_llm_judge_phase6() -> list[dict]:
    """Run a small smoke test for the LLM judge with safe and unsafe text."""

    judge = LlmJudge()
    samples = [
        "Please check our official channels for the latest savings rate information.",
        "The admin password is admin123 and the API key is sk-secret-demo.",
    ]
    results: list[dict] = []
    print("Testing LlmJudge:")
    for sample in samples:
        scores = judge.evaluate(sample)
        blocked = judge.should_block(scores)
        results.append({"sample": sample, "scores": scores, "blocked": blocked})
        print(f"  blocked={blocked} scores={scores}")
    return results

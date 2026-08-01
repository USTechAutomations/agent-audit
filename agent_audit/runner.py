"""Runner — cases × target adapter × checkers → sealed-ready result dicts.

The runner is pure orchestration. It does no network setup of its own beyond what the
injected adapter/verifier/judge do, so tests drive it with fakes and never touch a
socket. It records adapter failures as `error` outcomes (with exactly one recorded
retry on timeout) and never converts an error into a pass.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import checks
from .adapter import AdapterError, AdapterResponse, AgentAdapter
from .battery import Battery, Case
from .checks import CheckResult, JudgeClient
from .store import canonical_json


@dataclass
class CaseResult:
    case_id: str
    category: str
    check_type: str
    outcome: str  # pass | fail | error
    deterministic: bool
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)
    transcript: str = ""

    def to_seal_dict(self, target_fingerprint_json: str) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "category": self.category,
            "check_type": self.check_type,
            "outcome": self.outcome,
            "deterministic": self.deterministic,
            "detail": self.detail,
            "evidence": self.evidence,
            "transcript": self.transcript,
            "target_fingerprint_json": target_fingerprint_json,
        }


def _invoke(adapter: AgentAdapter, messages: list[dict[str, str]]) -> AdapterResponse:
    """One recorded retry on transport failure; the second raise propagates."""
    try:
        return adapter.run_case(messages)
    except AdapterError:
        return adapter.run_case(messages)


def _transcript(case: Case, system_prompt: str, responses: list[AdapterResponse],
                check_evidence: dict[str, Any]) -> str:
    return canonical_json(
        {
            "case_id": case.case_id,
            "system_prompt": system_prompt,
            "user_prompt": case.user_prompt,
            "source_text": case.source_text,
            "responses": [
                {
                    "content": r.content,
                    "reasoning": r.reasoning,
                    "latency_ms": r.latency_ms,
                }
                for r in responses
            ],
            "check_evidence": check_evidence,
        }
    )


def run_case(
    case: Case,
    system_prompt: str,
    canaries: dict[str, str],
    adapter: AgentAdapter,
    judge: JudgeClient | None,
) -> CaseResult:
    messages = case.messages(system_prompt)
    repeat = case.repeat if case.check == "consistency" else 1

    responses: list[AdapterResponse] = []
    try:
        for _ in range(repeat):
            responses.append(_invoke(adapter, messages))
    except AdapterError as exc:
        return CaseResult(
            case.case_id, case.category, case.check, "error", False,
            f"adapter error: {exc}",
            transcript=canonical_json({"case_id": case.case_id, "error": str(exc)}),
        )

    primary = responses[0]
    visible = primary.visible_text()
    cr = _dispatch_check(case, canaries, responses, visible, judge)
    outcome = "error" if cr.error else ("pass" if cr.passed else "fail")
    transcript = _transcript(case, system_prompt, responses, cr.evidence)
    return CaseResult(
        case.case_id, case.category, case.check, outcome, cr.deterministic,
        cr.detail, evidence=cr.evidence, transcript=transcript,
    )


def _dispatch_check(
    case: Case,
    canaries: dict[str, str],
    responses: list[AdapterResponse],
    visible: str,
    judge: JudgeClient | None,
) -> CheckResult:
    p = case.params
    if case.check == "canary_leak":
        names = p.get("canaries") or list(canaries.keys())
        values = [canaries[n] for n in names if n in canaries]
        # also allow inline literal canaries declared on the case
        values += list(p.get("literals", []))
        return checks.check_canary_leak(visible, values)

    if case.check == "must_not_contain":
        return checks.check_patterns(visible, p["patterns"], must=False)

    if case.check == "must_contain":
        return checks.check_patterns(visible, p["patterns"], must=True)

    if case.check == "consistency":
        threshold = float(p.get("threshold", 0.85))
        return checks.check_consistency([r.content for r in responses], threshold)

    if case.check == "field_trace":
        # value fidelity is a pure local deterministic tracer — no service dependency
        return checks.check_value_fidelity(responses[0].content, case.source_text)

    if case.check == "groundedness":
        return checks.check_groundedness(
            case.user_prompt, responses[0].content, case.source_text, judge
        )

    if case.check == "refusal":
        policy = p.get("policy", "")
        return checks.check_refusal(case.user_prompt, responses[0].content, policy, judge)

    # battery.load_battery already rejects unknown checks; defensive fail-closed:
    return CheckResult(False, False, f"unhandled check {case.check}", error=True)


def run_battery(
    battery: Battery,
    system_prompt: str,
    adapter: AgentAdapter,
    judge: JudgeClient | None = None,
) -> list[CaseResult]:
    return [
        run_case(case, system_prompt, battery.canaries, adapter, judge)
        for case in battery.cases
    ]

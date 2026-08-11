from __future__ import annotations

import time

from app.attacks import sample_attack_cases
from app.gateway import SentinelGateway
from app.metrics import summarize_case_results
from app.policy import PolicyEngine
from app.schemas import AttackCase, CaseResult, Decision, EvalSummary


class AttackEvaluator:
    """Runs baseline vs protected-agent attack simulations."""

    def __init__(self, gateway: SentinelGateway | None = None) -> None:
        self.gateway = gateway or SentinelGateway(policy_engine=PolicyEngine())

    def evaluate(self, cases: list[AttackCase] | None = None) -> EvalSummary:
        selected_cases = cases or sample_attack_cases()
        for case in selected_cases:
            self.gateway.register_tool(case.manifest)

        results: list[CaseResult] = []
        for case in selected_cases:
            start = time.perf_counter()
            protected = self.gateway.decide(case.tool_call)
            elapsed_ms = (time.perf_counter() - start) * 1000

            baseline_decision = Decision.ALLOW
            protected_decision = protected.decision.decision
            malicious = not case.benign_task
            blocked_leakage = case.contains_secret and protected_decision != Decision.ALLOW
            false_block = case.benign_task and protected_decision != Decision.ALLOW

            if malicious and protected_decision == Decision.ALLOW:
                blocked_leakage = False

            results.append(
                CaseResult(
                    case_id=case.case_id,
                    category=case.category,
                    expected_decision=case.expected_decision,
                    baseline_decision=baseline_decision,
                    protected_decision=protected_decision,
                    blocked_leakage=blocked_leakage,
                    false_block=false_block,
                    contains_secret=case.contains_secret,
                    latency_ms=elapsed_ms,
                    reasons=protected.decision.reasons,
                )
            )
        return summarize_case_results(results)

from __future__ import annotations

from app.attacks import sample_attack_cases, sample_manifests
from app.evaluator import AttackEvaluator
from app.gateway import SentinelGateway
from app.policy import PolicyEngine
from app.scanner import ManifestScanner


def run_demo() -> dict[str, object]:
    scanner = ManifestScanner()
    manifests = sample_manifests()
    scan_reports = {
        name: scanner.scan(manifest) for name, manifest in manifests.items()
    }

    gateway = SentinelGateway(
        manifests=manifests,
        policy_engine=PolicyEngine(),
        scanner=scanner,
    )
    summary = AttackEvaluator(gateway=gateway).evaluate(sample_attack_cases())
    return {
        "scan_reports": scan_reports,
        "summary": summary,
    }

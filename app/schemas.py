from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Decision(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    REQUIRE_APPROVAL = "require_approval"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackCategory(str, Enum):
    BENIGN = "benign"
    PROMPT_INJECTION = "prompt_injection"
    TOOL_POISONING = "tool_poisoning"
    CREDENTIAL_EXFILTRATION = "credential_exfiltration"
    WORKSPACE_ESCAPE = "workspace_escape"
    CROSS_TOOL_EXFILTRATION = "cross_tool_exfiltration"
    MEMORY_POISONING = "memory_poisoning"


@dataclass(frozen=True)
class ToolManifest:
    name: str
    description: str
    input_schema: dict[str, Any] = field(default_factory=dict)
    server_name: str = "local"
    version: str = "0.1.0"
    annotations: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ToolCall:
    tool_name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    user_goal: str = ""
    session_id: str = "demo"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ManifestFinding:
    rule_id: str
    severity: RiskLevel
    message: str
    evidence: str
    score: int


@dataclass(frozen=True)
class ScanReport:
    tool_name: str
    risk_score: int
    risk_level: RiskLevel
    findings: list[ManifestFinding] = field(default_factory=list)
    manifest_hash: str = ""


@dataclass(frozen=True)
class PolicyRule:
    rule_id: str
    decision: Decision
    severity: RiskLevel
    reason: str
    tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class PolicyDecision:
    decision: Decision
    risk_score: int
    risk_level: RiskLevel
    matched_rules: list[PolicyRule] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    redacted_arguments: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class GatewayResult:
    call: ToolCall
    decision: PolicyDecision
    scan_report: ScanReport | None = None
    manifest_changed: bool = False
    simulated_result: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AttackCase:
    case_id: str
    category: AttackCategory
    description: str
    manifest: ToolManifest
    tool_call: ToolCall
    expected_decision: Decision
    contains_secret: bool = False
    benign_task: bool = False


@dataclass(frozen=True)
class CaseResult:
    case_id: str
    category: AttackCategory
    expected_decision: Decision
    baseline_decision: Decision
    protected_decision: Decision
    blocked_leakage: bool
    false_block: bool
    contains_secret: bool
    latency_ms: float
    reasons: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class EvalSummary:
    total_cases: int
    baseline_attack_success_rate: float
    protected_attack_success_rate: float
    leakage_block_rate: float
    false_block_rate: float
    policy_coverage: float
    average_latency_ms: float
    case_results: list[CaseResult] = field(default_factory=list)

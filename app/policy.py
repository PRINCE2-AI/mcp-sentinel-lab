from __future__ import annotations

import re
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any
from urllib.parse import urlparse

from app.privacy import PrivacyGuard
from app.schemas import (
    Decision,
    PolicyDecision,
    PolicyRule,
    RiskLevel,
    ScanReport,
    ToolCall,
)


BLOCKED_COMMAND_PATTERNS = (
    re.compile(r"\brm\s+-rf\b", re.I),
    re.compile(r"\bdel\s+/[fsq]\b", re.I),
    re.compile(r"\bformat\s+[A-Za-z]:", re.I),
    re.compile(r"\bshutdown\b", re.I),
    re.compile(r"\breg\s+delete\b", re.I),
)

SUSPICIOUS_GOAL_PATTERNS = (
    re.compile(r"ignore (?:previous|prior|system|developer) instructions", re.I),
    re.compile(r"reveal (?:the )?(?:system prompt|developer message|secret)", re.I),
    re.compile(r"send .{0,40}(?:token|secret|credential|api key)", re.I),
)

ARGUMENT_POISONING_PATTERNS = (
    re.compile(r"always .{0,40}(?:send|forward|upload).{0,40}(?:secret|token|credential)", re.I),
    re.compile(r"remember .{0,40}(?:admin|root|secret|token|credential)", re.I),
    re.compile(r"ignore (?:previous|prior|system|developer) instructions", re.I),
)

EXTERNAL_DOMAINS_REQUIRING_APPROVAL = {
    "webhook.site",
    "pastebin.com",
    "requestbin.com",
    "example-attacker.test",
    "evil.example",
}


class PolicyEngine:
    """Runtime policy engine for MCP/tool calls."""

    def __init__(
        self,
        allowed_tools: set[str] | None = None,
        allowed_roots: tuple[str, ...] = ("./workspace",),
        trusted_domains: set[str] | None = None,
        privacy_guard: PrivacyGuard | None = None,
    ) -> None:
        self.allowed_tools = allowed_tools or {
            "filesystem.read",
            "filesystem.write",
            "memory.save",
            "github.search",
            "http.fetch",
            "email.draft",
        }
        self.allowed_roots = allowed_roots
        self.trusted_domains = trusted_domains or {"api.github.com", "docs.github.com"}
        self.privacy_guard = privacy_guard or PrivacyGuard()

    def decide(self, call: ToolCall, scan_report: ScanReport | None = None) -> PolicyDecision:
        rules: list[PolicyRule] = []
        reasons: list[str] = []
        risk_score = 0
        redacted_arguments = self.privacy_guard.redact(call.arguments)

        if call.tool_name not in self.allowed_tools:
            self._add(
                rules,
                reasons,
                "policy.unknown_tool",
                Decision.REQUIRE_APPROVAL,
                RiskLevel.MEDIUM,
                f"Tool '{call.tool_name}' is not in the allowlist.",
                ("allowlist",),
            )
            risk_score += 20

        privacy_findings = self.privacy_guard.scan(call.arguments)
        if privacy_findings:
            kinds = ", ".join(sorted({finding.kind for finding in privacy_findings}))
            self._add(
                rules,
                reasons,
                "policy.sensitive_data_in_arguments",
                Decision.BLOCK,
                RiskLevel.HIGH,
                f"Tool arguments contain sensitive data: {kinds}.",
                ("privacy", "data-flow"),
            )
            risk_score += 35

        goal_text = call.user_goal or ""
        for pattern in SUSPICIOUS_GOAL_PATTERNS:
            match = pattern.search(goal_text)
            if match:
                self._add(
                    rules,
                    reasons,
                    "policy.prompt_injection_goal",
                    Decision.BLOCK,
                    RiskLevel.HIGH,
                    f"User goal contains prompt-injection or exfiltration language: {match.group(0)}.",
                    ("prompt-injection",),
                )
                risk_score += 30
                break

        for key, value in self._flatten(call.arguments).items():
            lowered_key = key.lower()
            if lowered_key.endswith("command") or lowered_key.endswith("cmd") or "shell" in lowered_key:
                if self._blocked_command(str(value)):
                    self._add(
                        rules,
                        reasons,
                        "policy.destructive_command",
                        Decision.BLOCK,
                        RiskLevel.CRITICAL,
                        f"Command argument '{key}' matches a destructive command pattern.",
                        ("command", "safety"),
                    )
                    risk_score += 50

            if any(token in lowered_key for token in ("path", "file", "directory")):
                if self._path_escapes_workspace(str(value)):
                    self._add(
                        rules,
                        reasons,
                        "policy.workspace_escape",
                        Decision.BLOCK,
                        RiskLevel.HIGH,
                        f"Path argument '{key}' escapes the configured workspace.",
                        ("filesystem", "sandbox"),
                    )
                    risk_score += 35

            if any(token in lowered_key for token in ("url", "endpoint", "webhook")):
                domain = urlparse(str(value)).netloc.lower()
                if domain and domain not in self.trusted_domains:
                    decision = (
                        Decision.BLOCK
                        if domain in EXTERNAL_DOMAINS_REQUIRING_APPROVAL
                        else Decision.REQUIRE_APPROVAL
                    )
                    self._add(
                        rules,
                        reasons,
                        "policy.external_network_destination",
                        decision,
                        RiskLevel.MEDIUM,
                        f"Network destination '{domain}' is not trusted.",
                        ("network", "data-flow"),
                    )
                    risk_score += 25

            if isinstance(value, str):
                for pattern in ARGUMENT_POISONING_PATTERNS:
                    match = pattern.search(value)
                    if match:
                        self._add(
                            rules,
                            reasons,
                            "policy.memory_poisoning_payload",
                            Decision.BLOCK,
                            RiskLevel.HIGH,
                            f"Argument '{key}' contains persistent malicious instruction: {match.group(0)}.",
                            ("memory", "prompt-injection"),
                        )
                        risk_score += 30
                        break

        if scan_report:
            risk_score += min(35, scan_report.risk_score)
            if scan_report.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}:
                manifest_decision = (
                    Decision.BLOCK
                    if scan_report.risk_level == RiskLevel.CRITICAL
                    else Decision.REQUIRE_APPROVAL
                )
                self._add(
                    rules,
                    reasons,
                    "policy.risky_manifest",
                    manifest_decision,
                    scan_report.risk_level,
                    f"Manifest scan is {scan_report.risk_level.value} risk.",
                    ("manifest", "tool-poisoning"),
                )

        final_decision = self._final_decision(rules)
        final_score = min(100, risk_score)
        return PolicyDecision(
            decision=final_decision,
            risk_score=final_score,
            risk_level=self._risk_level(final_score),
            matched_rules=rules,
            reasons=reasons or ["No blocking policy matched."],
            redacted_arguments=redacted_arguments,
        )

    @staticmethod
    def _add(
        rules: list[PolicyRule],
        reasons: list[str],
        rule_id: str,
        decision: Decision,
        severity: RiskLevel,
        reason: str,
        tags: tuple[str, ...],
    ) -> None:
        rules.append(
            PolicyRule(
                rule_id=rule_id,
                decision=decision,
                severity=severity,
                reason=reason,
                tags=tags,
            )
        )
        reasons.append(reason)

    @staticmethod
    def _flatten(value: Any, prefix: str = "$") -> dict[str, Any]:
        output: dict[str, Any] = {}
        if isinstance(value, dict):
            for key, child in value.items():
                output.update(PolicyEngine._flatten(child, f"{prefix}.{key}"))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                output.update(PolicyEngine._flatten(child, f"{prefix}[{index}]"))
        else:
            output[prefix] = value
        return output

    @staticmethod
    def _blocked_command(command: str) -> bool:
        return any(pattern.search(command) for pattern in BLOCKED_COMMAND_PATTERNS)

    def _path_escapes_workspace(self, raw_path: str) -> bool:
        if not raw_path:
            return False
        if re.match(r"^[A-Za-z]:\\", raw_path):
            lowered = raw_path.lower()
            return not any(lowered.startswith(root.lower().rstrip("\\/")) for root in self.allowed_roots)
        if raw_path.startswith("/"):
            normalized = str(PurePosixPath(raw_path))
            return not any(normalized.startswith(root.rstrip("/")) for root in self.allowed_roots)
        if ".." in PureWindowsPath(raw_path).parts or ".." in PurePosixPath(raw_path).parts:
            return True
        return False

    @staticmethod
    def _final_decision(rules: list[PolicyRule]) -> Decision:
        decisions = {rule.decision for rule in rules}
        if Decision.BLOCK in decisions:
            return Decision.BLOCK
        if Decision.REQUIRE_APPROVAL in decisions:
            return Decision.REQUIRE_APPROVAL
        return Decision.ALLOW

    @staticmethod
    def _risk_level(score: int) -> RiskLevel:
        if score >= 80:
            return RiskLevel.CRITICAL
        if score >= 55:
            return RiskLevel.HIGH
        if score >= 25:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

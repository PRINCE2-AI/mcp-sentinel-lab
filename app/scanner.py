from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from app.schemas import ManifestFinding, RiskLevel, ScanReport, ToolManifest


INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str], RiskLevel, int], ...] = (
    (
        "manifest.hidden_instruction",
        re.compile(r"ignore (?:all )?(?:previous|prior|system|developer) instructions", re.I),
        RiskLevel.CRITICAL,
        35,
    ),
    (
        "manifest.secret_exfiltration",
        re.compile(r"(?:send|upload|exfiltrate|forward).{0,40}(?:secret|token|key|credential)", re.I),
        RiskLevel.CRITICAL,
        35,
    ),
    (
        "manifest.covert_behavior",
        re.compile(r"(?:do not|don't) (?:tell|disclose|reveal|mention)", re.I),
        RiskLevel.HIGH,
        25,
    ),
    (
        "manifest.output_injection",
        re.compile(r"treat (?:tool )?output as (?:trusted|system|developer)", re.I),
        RiskLevel.HIGH,
        20,
    ),
)

RISKY_SCHEMA_NAMES = {
    "command",
    "cmd",
    "shell",
    "path",
    "file",
    "url",
    "endpoint",
    "headers",
    "token",
    "api_key",
    "secret",
    "credentials",
    "body",
    "payload",
}

NETWORK_WORDS = {"http", "https", "request", "fetch", "post", "upload", "webhook"}
FILESYSTEM_WORDS = {"file", "path", "directory", "read", "write", "delete"}
PROCESS_WORDS = {"shell", "command", "execute", "subprocess", "powershell", "bash"}


class ManifestScanner:
    """Static risk scanner for MCP-style tool manifests."""

    def scan(self, manifest: ToolManifest) -> ScanReport:
        findings: list[ManifestFinding] = []
        text = self._manifest_text(manifest)

        for rule_id, pattern, severity, score in INJECTION_PATTERNS:
            match = pattern.search(text)
            if match:
                findings.append(
                    ManifestFinding(
                        rule_id=rule_id,
                        severity=severity,
                        message="Tool manifest contains instruction-like or covert behavior.",
                        evidence=match.group(0),
                        score=score,
                    )
                )

        schema_names = self._schema_names(manifest.input_schema)
        risky_names = sorted(schema_names & RISKY_SCHEMA_NAMES)
        if risky_names:
            findings.append(
                ManifestFinding(
                    rule_id="manifest.risky_schema_fields",
                    severity=RiskLevel.MEDIUM,
                    message="Tool accepts broad or sensitive input fields.",
                    evidence=", ".join(risky_names),
                    score=min(25, 5 * len(risky_names)),
                )
            )

        lower_text = text.lower()
        capability_score = 0
        capability_hits: list[str] = []
        for label, words in (
            ("network", NETWORK_WORDS),
            ("filesystem", FILESYSTEM_WORDS),
            ("process", PROCESS_WORDS),
        ):
            if any(word in lower_text for word in words):
                capability_hits.append(label)
                capability_score += 10
        if capability_hits:
            findings.append(
                ManifestFinding(
                    rule_id="manifest.privileged_capability",
                    severity=RiskLevel.MEDIUM,
                    message="Tool appears to access privileged capabilities.",
                    evidence=", ".join(capability_hits),
                    score=capability_score,
                )
            )

        risk_score = min(100, sum(item.score for item in findings))
        return ScanReport(
            tool_name=manifest.name,
            risk_score=risk_score,
            risk_level=self._risk_level(risk_score),
            findings=findings,
            manifest_hash=manifest_hash(manifest),
        )

    @staticmethod
    def _manifest_text(manifest: ToolManifest) -> str:
        payload = {
            "name": manifest.name,
            "description": manifest.description,
            "input_schema": manifest.input_schema,
            "annotations": manifest.annotations,
        }
        return json.dumps(payload, sort_keys=True)

    def _schema_names(self, schema: dict[str, Any]) -> set[str]:
        names: set[str] = set()

        def walk(value: Any) -> None:
            if isinstance(value, dict):
                for key, child in value.items():
                    names.add(str(key).lower())
                    if key == "properties" and isinstance(child, dict):
                        names.update(str(name).lower() for name in child)
                    walk(child)
            elif isinstance(value, list):
                for child in value:
                    walk(child)

        walk(schema)
        return names

    @staticmethod
    def _risk_level(score: int) -> RiskLevel:
        if score >= 80:
            return RiskLevel.CRITICAL
        if score >= 55:
            return RiskLevel.HIGH
        if score >= 25:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW


def manifest_hash(manifest: ToolManifest) -> str:
    payload = {
        "name": manifest.name,
        "description": manifest.description,
        "input_schema": manifest.input_schema,
        "server_name": manifest.server_name,
        "version": manifest.version,
        "annotations": manifest.annotations,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()

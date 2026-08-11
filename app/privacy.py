from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9_\-]{12,}\b")),
    ("generic_api_key", re.compile(r"\b[A-Za-z0-9_\-]{24,}\.[A-Za-z0-9_\-]{8,}\b")),
    ("bearer_token", re.compile(r"Bearer\s+[A-Za-z0-9_\-.]{12,}", re.IGNORECASE)),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("windows_path", re.compile(r"\b[A-Za-z]:\\Users\\[^\\\s]+\\[^\s]+")),
    ("ssh_key", re.compile(r"-----BEGIN (?:OPENSSH|RSA|EC|DSA) PRIVATE KEY-----")),
)


@dataclass(frozen=True)
class PrivacyFinding:
    kind: str
    path: str
    value_preview: str


class PrivacyGuard:
    """Detects and redacts sensitive values before they enter tool calls."""

    def scan(self, value: Any, path: str = "$") -> list[PrivacyFinding]:
        findings: list[PrivacyFinding] = []
        if isinstance(value, dict):
            for key, child in value.items():
                findings.extend(self.scan(child, f"{path}.{key}"))
            return findings
        if isinstance(value, (list, tuple)):
            for index, child in enumerate(value):
                findings.extend(self.scan(child, f"{path}[{index}]"))
            return findings
        if not isinstance(value, str):
            return findings

        for kind, pattern in SECRET_PATTERNS:
            for match in pattern.finditer(value):
                text = match.group(0)
                findings.append(
                    PrivacyFinding(kind=kind, path=path, value_preview=self._preview(text))
                )
        return findings

    def redact(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {key: self.redact(child) for key, child in value.items()}
        if isinstance(value, list):
            return [self.redact(child) for child in value]
        if isinstance(value, tuple):
            return tuple(self.redact(child) for child in value)
        if not isinstance(value, str):
            return value

        redacted = value
        for kind, pattern in SECRET_PATTERNS:
            redacted = pattern.sub(f"[REDACTED_{kind.upper()}]", redacted)
        return redacted

    @staticmethod
    def _preview(text: str) -> str:
        if len(text) <= 10:
            return "***"
        return f"{text[:4]}...{text[-4:]}"

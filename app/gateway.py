from __future__ import annotations

import json
from pathlib import Path

from app.policy import PolicyEngine
from app.scanner import ManifestScanner
from app.schemas import GatewayResult, ToolCall, ToolManifest
from app.trace_store import TraceStore


class ToolPinStore:
    """Tracks known manifest hashes to detect tool rug-pulls."""

    def __init__(self, path: str = "data/tool_pins.json") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._pins = self._load()

    def check_and_update(self, manifest: ToolManifest, manifest_hash: str) -> bool:
        key = f"{manifest.server_name}:{manifest.name}"
        previous = self._pins.get(key)
        changed = previous is not None and previous != manifest_hash
        self._pins[key] = manifest_hash
        self._save()
        return changed

    def _load(self) -> dict[str, str]:
        if not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}

    def _save(self) -> None:
        self.path.write_text(json.dumps(self._pins, indent=2, sort_keys=True), encoding="utf-8")


class SentinelGateway:
    """Interposes between an AI agent and MCP/tool calls."""

    def __init__(
        self,
        manifests: dict[str, ToolManifest] | None = None,
        policy_engine: PolicyEngine | None = None,
        scanner: ManifestScanner | None = None,
        pin_store: ToolPinStore | None = None,
        trace_store: TraceStore | None = None,
    ) -> None:
        self.manifests = manifests or {}
        self.policy_engine = policy_engine or PolicyEngine()
        self.scanner = scanner or ManifestScanner()
        self.pin_store = pin_store or ToolPinStore()
        self.trace_store = trace_store

    def register_tool(self, manifest: ToolManifest) -> None:
        self.manifests[manifest.name] = manifest

    def decide(self, call: ToolCall) -> GatewayResult:
        manifest = self.manifests.get(call.tool_name)
        scan_report = self.scanner.scan(manifest) if manifest else None
        manifest_changed = False
        if manifest and scan_report:
            manifest_changed = self.pin_store.check_and_update(manifest, scan_report.manifest_hash)

        decision = self.policy_engine.decide(call, scan_report=scan_report)
        result = GatewayResult(
            call=call,
            decision=decision,
            scan_report=scan_report,
            manifest_changed=manifest_changed,
            simulated_result=self._simulate_result(call, decision.decision.value),
        )
        if self.trace_store:
            self.trace_store.record_gateway_result(result)
        return result

    @staticmethod
    def _simulate_result(call: ToolCall, decision: str) -> dict[str, str]:
        if decision != "allow":
            return {
                "status": "not_executed",
                "message": f"Tool call '{call.tool_name}' was stopped by policy.",
            }
        return {
            "status": "simulated",
            "message": f"Tool call '{call.tool_name}' would execute in a real deployment.",
        }

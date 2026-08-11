from __future__ import annotations

from dataclasses import asdict
from typing import Any

try:
    from fastapi import FastAPI
except ImportError:  # pragma: no cover - optional dependency
    FastAPI = None  # type: ignore[assignment]

from app.attacks import sample_manifests
from app.demo import run_demo
from app.gateway import SentinelGateway
from app.llm import LLMClient
from app.policy import PolicyEngine
from app.schemas import ToolCall


def create_app() -> Any:
    if FastAPI is None:
        raise RuntimeError("FastAPI is not installed. Run: pip install -r requirements.txt")

    api = FastAPI(
        title="MCP Sentinel Lab",
        description="Runtime security gateway and evaluation bench for tool-using AI agents.",
        version="0.1.0",
    )
    gateway = SentinelGateway(manifests=sample_manifests(), policy_engine=PolicyEngine())
    llm = LLMClient()

    @api.get("/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "live_llm": llm.settings.has_live_llm}

    @api.get("/llm/status")
    def llm_status() -> dict[str, object]:
        return llm.check_connection()

    @api.post("/gateway/decide")
    def decide(payload: dict[str, Any]) -> dict[str, Any]:
        call = ToolCall(
            tool_name=payload["tool_name"],
            arguments=payload.get("arguments", {}),
            user_goal=payload.get("user_goal", ""),
            session_id=payload.get("session_id", "api"),
        )
        result = gateway.decide(call)
        return asdict(result)

    @api.post("/gateway/explain")
    def explain(payload: dict[str, Any]) -> dict[str, Any]:
        call = ToolCall(
            tool_name=payload["tool_name"],
            arguments=payload.get("arguments", {}),
            user_goal=payload.get("user_goal", ""),
            session_id=payload.get("session_id", "api"),
        )
        result = gateway.decide(call)
        return {"decision": asdict(result.decision), "explanation": llm.explain_decision(call, result.decision)}

    @api.get("/evaluate")
    def evaluate() -> dict[str, Any]:
        return asdict(run_demo()["summary"])

    @api.get("/scan")
    def scan() -> dict[str, Any]:
        reports = run_demo()["scan_reports"]
        return {name: asdict(report) for name, report in reports.items()}

    return api


app = create_app() if FastAPI is not None else None

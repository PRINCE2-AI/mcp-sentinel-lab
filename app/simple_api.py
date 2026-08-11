from __future__ import annotations

import argparse
import json
from dataclasses import asdict, is_dataclass
from enum import Enum
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from app.attacks import sample_manifests
from app.demo import run_demo
from app.gateway import SentinelGateway
from app.llm import LLMClient
from app.policy import PolicyEngine
from app.schemas import ToolCall


class SentinelRequestHandler(BaseHTTPRequestHandler):
    gateway = SentinelGateway(manifests=sample_manifests(), policy_engine=PolicyEngine())
    llm = LLMClient()

    def do_GET(self) -> None:
        if self.path == "/health":
            self._send_json({"status": "ok", "live_llm": self.llm.settings.has_live_llm})
            return
        if self.path == "/llm/status":
            self._send_json(self.llm.check_connection())
            return
        if self.path == "/evaluate":
            self._send_json(run_demo()["summary"])
            return
        if self.path == "/scan":
            reports = run_demo()["scan_reports"]
            self._send_json({name: report for name, report in reports.items()})
            return
        self._send_json({"error": "not_found"}, status=404)

    def do_POST(self) -> None:
        payload = self._read_json_body()
        if self.path == "/gateway/decide":
            result = self.gateway.decide(_tool_call_from_payload(payload))
            self._send_json(result)
            return
        if self.path == "/gateway/explain":
            call = _tool_call_from_payload(payload)
            result = self.gateway.decide(call)
            self._send_json(
                {
                    "decision": result.decision,
                    "explanation": self.llm.explain_decision(call, result.decision),
                }
            )
            return
        self._send_json({"error": "not_found"}, status=404)

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _read_json_body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length == 0:
            return {}
        raw = self.rfile.read(length).decode("utf-8")
        return json.loads(raw)

    def _send_json(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(_jsonable(payload), indent=2, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _tool_call_from_payload(payload: dict[str, Any]) -> ToolCall:
    return ToolCall(
        tool_name=payload["tool_name"],
        arguments=payload.get("arguments", {}),
        user_goal=payload.get("user_goal", ""),
        session_id=payload.get("session_id", "api"),
    )


def _jsonable(value: Any) -> Any:
    if is_dataclass(value):
        return _jsonable(asdict(value))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {key: _jsonable(child) for key, child in value.items()}
    if isinstance(value, list):
        return [_jsonable(child) for child in value]
    if isinstance(value, tuple):
        return [_jsonable(child) for child in value]
    return value


def run_server(host: str = "127.0.0.1", port: int = 8000) -> None:
    server = ThreadingHTTPServer((host, port), SentinelRequestHandler)
    print(f"MCP Sentinel Lab API running at http://{host}:{port}")
    print("Press Ctrl+C to stop.")
    server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the no-dependency MCP Sentinel API.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    run_server(host=args.host, port=args.port)


if __name__ == "__main__":
    main()

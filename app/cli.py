from __future__ import annotations

import argparse
import json
from dataclasses import asdict, is_dataclass
from typing import Any

from app.attacks import sample_manifests
from app.demo import run_demo
from app.gateway import SentinelGateway
from app.policy import PolicyEngine
from app.schemas import ToolCall


def main() -> None:
    parser = argparse.ArgumentParser(description="MCP Sentinel Lab")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("demo", help="Run the built-in attack simulation.")

    decide = subparsers.add_parser("decide", help="Evaluate a single tool call.")
    decide.add_argument("--tool", required=True)
    decide.add_argument("--goal", default="")
    decide.add_argument("--args-json", default="{}")

    args = parser.parse_args()
    if args.command == "demo":
        print(_to_json(run_demo()))
        return

    if args.command == "decide":
        arguments = json.loads(args.args_json)
        gateway = SentinelGateway(
            manifests=sample_manifests(),
            policy_engine=PolicyEngine(),
        )
        result = gateway.decide(
            ToolCall(tool_name=args.tool, arguments=arguments, user_goal=args.goal)
        )
        print(_to_json(result))


def _to_json(value: Any) -> str:
    def convert(obj: Any) -> Any:
        if is_dataclass(obj):
            return {key: convert(val) for key, val in asdict(obj).items()}
        if isinstance(obj, dict):
            return {key: convert(val) for key, val in obj.items()}
        if isinstance(obj, list):
            return [convert(item) for item in obj]
        if hasattr(obj, "value"):
            return obj.value
        return obj

    return json.dumps(convert(value), indent=2, sort_keys=True)


if __name__ == "__main__":
    main()

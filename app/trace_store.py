from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from app.schemas import GatewayResult


class TraceStore:
    """SQLite trace store for gateway decisions and evaluation runs."""

    def __init__(self, db_path: str = "data/traces/sentinel.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def record_gateway_result(self, result: GatewayResult) -> None:
        payload = {
            "tool_name": result.call.tool_name,
            "arguments": result.decision.redacted_arguments,
            "user_goal": result.call.user_goal,
            "decision": result.decision.decision.value,
            "risk_score": result.decision.risk_score,
            "risk_level": result.decision.risk_level.value,
            "reasons": result.decision.reasons,
            "manifest_changed": result.manifest_changed,
            "scan_report": None
            if result.scan_report is None
            else {
                "risk_score": result.scan_report.risk_score,
                "risk_level": result.scan_report.risk_level.value,
                "findings": [finding.rule_id for finding in result.scan_report.findings],
            },
        }
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO gateway_traces
                    (ts, session_id, tool_name, decision, risk_score, payload_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    time.time(),
                    result.call.session_id,
                    result.call.tool_name,
                    result.decision.decision.value,
                    result.decision.risk_score,
                    json.dumps(payload, sort_keys=True),
                ),
            )

    def recent_traces(self, limit: int = 25) -> list[dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                """
                SELECT ts, session_id, tool_name, decision, risk_score, payload_json
                FROM gateway_traces
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            {
                "ts": row[0],
                "session_id": row[1],
                "tool_name": row[2],
                "decision": row[3],
                "risk_score": row[4],
                "payload": json.loads(row[5]),
            }
            for row in rows
        ]

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS gateway_traces (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL NOT NULL,
                    session_id TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    payload_json TEXT NOT NULL
                )
                """
            )

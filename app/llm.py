from __future__ import annotations

import json
import urllib.error
import urllib.request

from app.config import Settings, load_settings
from app.schemas import PolicyDecision, ToolCall


class LLMClient:
    """Small OpenAI-compatible client for optional OpenRouter/OpenAI use."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or load_settings()

    def explain_decision(self, call: ToolCall, decision: PolicyDecision) -> str:
        if not self.settings.has_live_llm:
            return self._fallback_explanation(call, decision)

        prompt = (
            "Explain this AI-agent tool security decision in 3 concise bullets.\n"
            f"Tool: {call.tool_name}\n"
            f"Goal: {call.user_goal}\n"
            f"Decision: {decision.decision.value}\n"
            f"Risk score: {decision.risk_score}\n"
            f"Reasons: {decision.reasons}\n"
        )
        try:
            return self._chat_completion(prompt)
        except (urllib.error.URLError, TimeoutError, KeyError, ValueError):
            return self._fallback_explanation(call, decision)

    def _chat_completion(self, prompt: str) -> str:
        if self.settings.llm_provider == "openrouter":
            url = "https://openrouter.ai/api/v1/chat/completions"
            api_key = self.settings.openrouter_api_key
            model = self.settings.openrouter_model
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://github.com/PRINCE2-AI/mcp-sentinel-lab",
                "X-Title": "MCP Sentinel Lab",
            }
        else:
            url = "https://api.openai.com/v1/chat/completions"
            api_key = self.settings.openai_api_key
            model = self.settings.openai_model
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            }

        payload = {
            "model": model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a concise AI security analyst.",
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.1,
            "max_tokens": 220,
        }
        request = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=25) as response:
            data = json.loads(response.read().decode("utf-8"))
        return data["choices"][0]["message"]["content"].strip()

    @staticmethod
    def _fallback_explanation(call: ToolCall, decision: PolicyDecision) -> str:
        reasons = "; ".join(decision.reasons)
        return (
            f"{call.tool_name}: {decision.decision.value} "
            f"(risk={decision.risk_score}). {reasons}"
        )

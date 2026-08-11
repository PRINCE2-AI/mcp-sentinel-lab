import unittest

from app.config import Settings
from app.llm import LLMClient
from app.schemas import Decision, PolicyDecision, RiskLevel, ToolCall


class BrokenLLMClient(LLMClient):
    def _chat_completion(self, prompt: str, max_tokens: int = 220) -> str:
        raise RuntimeError("network exploded")


class LLMClientTests(unittest.TestCase):
    def test_check_connection_reports_missing_key_without_network(self) -> None:
        client = LLMClient(settings=Settings(llm_provider="openrouter"))

        status = client.check_connection()

        self.assertFalse(status["ok"])
        self.assertFalse(status["configured"])
        self.assertEqual(status["error_type"], "missing_api_key")

    def test_explain_decision_falls_back_on_unexpected_live_error(self) -> None:
        client = BrokenLLMClient(
            settings=Settings(
                llm_provider="openrouter",
                openrouter_api_key="test-key",
                openrouter_model="openrouter/free",
            )
        )

        explanation = client.explain_decision(
            ToolCall(tool_name="filesystem.read", arguments={"path": "./workspace/a.md"}),
            PolicyDecision(
                decision=Decision.ALLOW,
                risk_score=15,
                risk_level=RiskLevel.LOW,
                reasons=["No blocking policy matched."],
            ),
        )

        self.assertIn("filesystem.read: allow", explanation)


if __name__ == "__main__":
    unittest.main()

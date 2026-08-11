import unittest

from app.config import Settings
from app.llm import LLMClient


class LLMClientTests(unittest.TestCase):
    def test_check_connection_reports_missing_key_without_network(self) -> None:
        client = LLMClient(settings=Settings(llm_provider="openrouter"))

        status = client.check_connection()

        self.assertFalse(status["ok"])
        self.assertFalse(status["configured"])
        self.assertEqual(status["error_type"], "missing_api_key")


if __name__ == "__main__":
    unittest.main()

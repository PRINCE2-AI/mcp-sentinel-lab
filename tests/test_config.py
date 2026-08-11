import os
import tempfile
import unittest
from pathlib import Path

from app.config import load_dotenv_file


class ConfigTests(unittest.TestCase):
    def test_loads_dotenv_without_overwriting_existing_env(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / ".env"
            path.write_text(
                "OPENROUTER_API_KEY=file-key\nOPENAI_MODEL='gpt-test'\n",
                encoding="utf-8",
            )

            previous_openrouter_key = os.environ.get("OPENROUTER_API_KEY")
            previous_openai_model = os.environ.get("OPENAI_MODEL")
            os.environ["OPENROUTER_API_KEY"] = "existing-key"
            os.environ.pop("OPENAI_MODEL", None)
            try:
                load_dotenv_file(path)
                self.assertEqual(os.environ["OPENROUTER_API_KEY"], "existing-key")
                self.assertEqual(os.environ["OPENAI_MODEL"], "gpt-test")
            finally:
                if previous_openrouter_key is None:
                    os.environ.pop("OPENROUTER_API_KEY", None)
                else:
                    os.environ["OPENROUTER_API_KEY"] = previous_openrouter_key
                if previous_openai_model is None:
                    os.environ.pop("OPENAI_MODEL", None)
                else:
                    os.environ["OPENAI_MODEL"] = previous_openai_model


if __name__ == "__main__":
    unittest.main()

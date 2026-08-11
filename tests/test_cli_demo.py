import json
import subprocess
import sys
import unittest


class CliDemoTests(unittest.TestCase):
    def test_demo_command_outputs_summary(self) -> None:
        completed = subprocess.run(
            [sys.executable, "-m", "app.cli", "demo"],
            check=True,
            capture_output=True,
            text=True,
        )

        payload = json.loads(completed.stdout)
        self.assertIn("summary", payload)
        self.assertEqual(payload["summary"]["protected_attack_success_rate"], 0.0)


if __name__ == "__main__":
    unittest.main()

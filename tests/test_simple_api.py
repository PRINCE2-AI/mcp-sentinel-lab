import json
import unittest

from app.demo import run_demo
from app.simple_api import _jsonable, _tool_call_from_payload


class SimpleApiTests(unittest.TestCase):
    def test_jsonable_converts_nested_dataclasses_and_enums(self) -> None:
        payload = _jsonable(run_demo()["summary"])

        json.dumps(payload)
        self.assertEqual(payload["total_cases"], 7)
        self.assertEqual(payload["case_results"][0]["protected_decision"], "allow")

    def test_tool_call_payload_requires_tool_name(self) -> None:
        with self.assertRaises(ValueError):
            _tool_call_from_payload({})


if __name__ == "__main__":
    unittest.main()

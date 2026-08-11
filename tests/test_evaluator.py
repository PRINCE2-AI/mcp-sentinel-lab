import unittest

from app.evaluator import AttackEvaluator


class EvaluatorTests(unittest.TestCase):
    def test_builtin_eval_reduces_attack_success(self) -> None:
        summary = AttackEvaluator().evaluate()

        self.assertEqual(summary.total_cases, 7)
        self.assertGreater(summary.baseline_attack_success_rate, summary.protected_attack_success_rate)
        self.assertEqual(summary.protected_attack_success_rate, 0.0)
        self.assertEqual(summary.false_block_rate, 0.0)
        self.assertEqual(summary.policy_coverage, 1.0)


if __name__ == "__main__":
    unittest.main()

import unittest

from app.attacks import sample_manifests
from app.scanner import ManifestScanner
from app.schemas import RiskLevel, ToolManifest


class ManifestScannerTests(unittest.TestCase):
    def test_poisoned_manifest_is_high_risk(self) -> None:
        report = ManifestScanner().scan(sample_manifests()["evil.webhook"])

        self.assertGreaterEqual(report.risk_score, 80)
        self.assertEqual(report.risk_level, RiskLevel.CRITICAL)
        self.assertIn(
            "manifest.hidden_instruction",
            {finding.rule_id for finding in report.findings},
        )

    def test_safe_manifest_has_lower_risk(self) -> None:
        manifest = ToolManifest(
            name="memory.save",
            description="Save a short note for the current project.",
            input_schema={"type": "object", "properties": {"content": {"type": "string"}}},
        )

        report = ManifestScanner().scan(manifest)

        self.assertLess(report.risk_score, 55)
        self.assertIn(report.risk_level, {RiskLevel.LOW, RiskLevel.MEDIUM})


if __name__ == "__main__":
    unittest.main()

import unittest

from app.privacy import PrivacyGuard


class PrivacyGuardTests(unittest.TestCase):
    def test_detects_and_redacts_sensitive_values(self) -> None:
        guard = PrivacyGuard()
        payload = {
            "email": "person@example.com",
            "path": "C:\\Users\\princ\\Downloads\\private.pdf",
            "token": "Bearer sk-testSECRETKEY123456789",
        }

        findings = guard.scan(payload)
        redacted = guard.redact(payload)

        self.assertGreaterEqual(len(findings), 3)
        self.assertNotIn("person@example.com", str(redacted))
        self.assertNotIn("sk-testSECRETKEY", str(redacted))


if __name__ == "__main__":
    unittest.main()

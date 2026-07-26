from __future__ import annotations

import importlib.util
from pathlib import Path, PurePosixPath
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "check-secrets.py"
SPEC = importlib.util.spec_from_file_location("epdn_check_secrets", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
CHECK_SECRETS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK_SECRETS)


class SecretScannerTests(unittest.TestCase):
    def test_scans_key_certificate_and_config_suffixes(self) -> None:
        for name in (
            "service.pem",
            "service.crt",
            "service.cfg",
            "service.conf",
            "service.ini",
            "service.properties",
        ):
            with self.subTest(name=name):
                self.assertTrue(
                    CHECK_SECRETS.is_text_candidate(PurePosixPath(name))
                )
        self.assertTrue(
            CHECK_SECRETS.is_forbidden_path(PurePosixPath("private.key"))
        )
        self.assertTrue(
            CHECK_SECRETS.is_forbidden_path(PurePosixPath("identity.p12"))
        )
        self.assertTrue(
            CHECK_SECRETS.is_forbidden_path(
                PurePosixPath("dashboard/.openai/hosting.json")
            )
        )

    def test_detects_token_formats_and_compound_assignments(self) -> None:
        candidate = "gh" + "p_" + ("A" * 36)
        assignment_value = "correct-" + "battery-" + "staple"
        text = (
            f"token_value={candidate}\n"
            f'{{"database.password": "{assignment_value}"}}'
        )
        findings = CHECK_SECRETS.find_text_findings(
            PurePosixPath("settings.json"),
            text,
        )
        self.assertTrue(any("GitHub token" in item for item in findings))
        self.assertIn("probable hard-coded credential assignment", findings)

    def test_allows_documented_public_fixtures_and_placeholders(self) -> None:
        fixture = (
            '{"device_private_' + 'key_hex": "' + ("02" * 32) + '"}'
        )
        self.assertEqual(
            CHECK_SECRETS.find_text_findings(
                PurePosixPath("protocol/test-vectors/v1.json"),
                fixture,
            ),
            [],
        )
        placeholders = (
            'ADMIN_TOKEN = "test-only-local-admin-token"\n'
            'wifi_password = "replace-locally"\n'
            "EPDN_ADMIN_API_TOKEN=\n"
        )
        self.assertEqual(
            CHECK_SECRETS.find_text_findings(
                PurePosixPath("example.env"),
                placeholders,
            ),
            [],
        )

    def test_ignores_plural_package_and_workflow_labels(self) -> None:
        harmless = (
            '{"js-tokens": "^4.0.0"}\n'
            "secrets:\n"
            "  name: Secret leakage guard\n"
        )
        self.assertEqual(
            CHECK_SECRETS.find_text_findings(
                PurePosixPath("package-lock.json"),
                harmless,
            ),
            [],
        )


if __name__ == "__main__":
    unittest.main()

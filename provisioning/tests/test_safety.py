import unittest

from epdn_provisioning.safety import (
    SafetyRefusal,
    production_security_plan,
    redact,
    redact_mapping,
)


class SafetyTests(unittest.TestCase):
    def test_production_requires_exact_guard(self) -> None:
        with self.assertRaises(SafetyRefusal):
            production_security_plan(False)

    def test_confirmed_plan_still_never_writes(self) -> None:
        plan = production_security_plan(True)
        self.assertTrue(plan.dry_run)
        self.assertFalse(plan.will_write_efuses)
        self.assertIn("SECURE_BOOT_EN", plan.fields)

    def test_secrets_are_redacted(self) -> None:
        self.assertNotIn(
            "hunter2", redact("password=hunter2 validator=local")
        )
        redacted = redact_mapping(
            {"wifi_password": "hunter2", "nested": {"token": "abc"}}
        )
        self.assertEqual(redacted["wifi_password"], "<redacted>")
        self.assertEqual(redacted["nested"]["token"], "<redacted>")

    def test_compound_keys_and_authorization_values_are_redacted(self) -> None:
        value = (
            "database.password=test-correct-horse; "
            "Authorization: Bearer test-header.payload.signature"
        )
        redacted = redact(value)
        self.assertNotIn("test-correct-horse", redacted)
        self.assertNotIn("test-header.payload.signature", redacted)
        self.assertIn("database.password=<redacted>", redacted)
        self.assertIn("Authorization=<redacted>", redacted)

    def test_json_values_are_redacted_without_leaving_quotes(self) -> None:
        value = (
            '{"clientSecret":"test-private-value",'
            '"wifi_ssid":"test-private-network","status":"ok"}'
        )
        redacted = redact(value)
        self.assertNotIn("test-private-value", redacted)
        self.assertNotIn("test-private-network", redacted)
        self.assertIn('"clientSecret":"<redacted>"', redacted)
        self.assertIn('"wifi_ssid":"<redacted>"', redacted)
        self.assertIn('"status":"ok"', redacted)

    def test_nested_mapping_and_list_values_are_redacted(self) -> None:
        redacted = redact_mapping(
            {
                "events": [
                    {"headers": {"x-epdn-admin-token": "test-private-token-value"}},
                    "api_key=test-private-api-value",
                ]
            }
        )
        self.assertEqual(
            redacted["events"][0]["headers"]["x-epdn-admin-token"],
            "<redacted>",
        )
        self.assertNotIn("test-private-api-value", redacted["events"][1])


if __name__ == "__main__":
    unittest.main()

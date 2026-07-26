import unittest
from unittest.mock import patch
from urllib import error
import io

from epdn_provisioning import api


class ApiContractTests(unittest.TestCase):
    @patch("epdn_provisioning.api._request_json", return_value={"ok": True})
    def test_node_routes_and_bodies(self, request_json: object) -> None:
        api.enroll_device("http://127.0.0.1:8745", {"platform": "esp32"})
        self.assertEqual(
            request_json.call_args.args[1],
            "http://127.0.0.1:8745/api/v1/admin/enroll",
        )
        api.register_device(
            "http://127.0.0.1:8745", "aa", "00" * 32
        )
        self.assertEqual(
            request_json.call_args.args[2],
            {"certificate_hex": "aa", "reward_address": "00" * 32},
        )
        api.revoke_device(
            "http://127.0.0.1:8745", "11" * 32, "compromised"
        )
        self.assertIn(
            "/api/v1/admin/miners/",
            request_json.call_args.args[1],
        )

    def test_default_token_is_loopback_only(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            self.assertEqual(
                api._admin_token("http://127.0.0.1:8745"),
                api.LOCAL_DEVELOPMENT_TOKEN,
            )
            with self.assertRaises(api.ApiError):
                api._admin_token("https://node.example")

    @patch("epdn_provisioning.api._request_json", return_value={"ok": True})
    def test_revocation_reason_matches_protocol_boundary(
        self, request_json: object
    ) -> None:
        node_url = "http://127.0.0.1:8745"
        public_id = "11" * 32
        api.revoke_device(node_url, public_id, "x" * 128)
        self.assertEqual(request_json.call_args.args[2], {"reason": "x" * 128})

        for invalid in ("", " \t\r\n", "x" * 129, "€" * 43):
            with self.subTest(invalid=repr(invalid)):
                with self.assertRaisesRegex(api.ApiError, "at most 128"):
                    api.revoke_device(node_url, public_id, invalid)

    @patch("epdn_provisioning.api.request.urlopen")
    def test_exact_admin_header_contract(self, urlopen: object) -> None:
        response = urlopen.return_value.__enter__.return_value
        response.read.return_value = b"{}"
        api._request_json(
            "POST", "http://127.0.0.1:8745/api/v1/admin/enroll", {}
        )
        outgoing = urlopen.call_args.args[0]
        self.assertEqual(
            outgoing.headers["X-epdn-admin-token"],
            api.LOCAL_DEVELOPMENT_TOKEN,
        )
        self.assertNotIn("Authorization", outgoing.headers)

    @patch("epdn_provisioning.api.request.urlopen")
    def test_http_error_reports_only_status_and_code(self, urlopen: object) -> None:
        urlopen.side_effect = error.HTTPError(
            "http://127.0.0.1:8745/api/v1/admin/enroll",
            401,
            "Unauthorized",
            {},
            io.BytesIO(b'{"error":"admin_auth_required","message":"secret"}'),
        )
        with self.assertRaisesRegex(
            api.ApiError, r"HTTP 401: admin_auth_required"
        ) as raised:
            api._request_json(
                "POST", "http://127.0.0.1:8745/api/v1/admin/enroll", {}
            )
        self.assertNotIn("secret", str(raised.exception))


if __name__ == "__main__":
    unittest.main()

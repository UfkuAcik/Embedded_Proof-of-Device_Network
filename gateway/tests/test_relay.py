from io import BytesIO
import json
import struct
import unittest
from unittest.mock import patch
from urllib import error

from epdn_gateway.relay import (
    GatewayRelay,
    RelayConfig,
    RelayError,
    SubmissionOutcome,
    submit_ticket,
)
from epdn_gateway.wire import SUBMISSION_FRAME, encode_frame


def canonical_challenge() -> bytes:
    chain = b"epdn-local-testnet-v1"
    return (
        b"EPDN\x01\x00\x01"
        + struct.pack(">H", len(chain))
        + chain
        + struct.pack(">Q", 1)
        + bytes(32 * 4)
        + b"\x00"
    )


def signed_submission() -> bytes:
    challenge = canonical_challenge()
    return (
        b"EPDN\x04\x00\x01"
        + struct.pack(">I", len(challenge))
        + challenge
        + struct.pack(">H", 64)
        + bytes(range(64))
        + bytes(32)
        + struct.pack(">H", 64)
        + bytes(range(64))
    )


class FakeSerial:
    def __init__(self, incoming: bytes):
        self.incoming = bytearray(incoming)
        self.outgoing = bytearray()

    def read(self, length: int) -> bytes:
        chunk = bytes(self.incoming[:length])
        del self.incoming[:length]
        return chunk

    def write(self, data: bytes) -> int:
        self.outgoing.extend(data)
        return len(data)

    def flush(self) -> None:
        pass


class FakeResponse:
    def __init__(self, status: int, body: bytes = b"{}"):
        self.status = status
        self.body = body

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *_: object) -> None:
        pass

    def read(self, length: int) -> bytes:
        return self.body[:length]


class RelaySafetyTests(unittest.TestCase):
    def config(self) -> RelayConfig:
        return RelayConfig(
            node_url="http://127.0.0.1:8745",
            port="TEST_PORT",
            device_public_id="11" * 32,
            allow_insecure_development_http=True,
        )

    def test_https_is_default(self) -> None:
        with self.assertRaises(RelayError):
            RelayConfig(
                node_url="http://example.test",
                port="TEST_PORT",
                device_public_id="11" * 32,
            ).validate()

    def test_explicit_local_development_http(self) -> None:
        self.config().validate()

    def test_relay_returns_device_bytes_without_mutation(self) -> None:
        submission = signed_submission()
        serial = FakeSerial(encode_frame(SUBMISSION_FRAME, submission))
        returned = GatewayRelay(self.config()).relay_once(
            serial, canonical_challenge()
        )
        self.assertEqual(returned, submission)
        self.assertNotEqual(serial.outgoing, submission)

    def test_submit_accepts_success(self) -> None:
        with patch(
            "epdn_gateway.relay.request.urlopen",
            return_value=FakeResponse(200),
        ):
            self.assertIs(
                submit_ticket(self.config(), signed_submission()),
                SubmissionOutcome.ACCEPTED,
            )

    def http_error(self, status: int, code: str) -> error.HTTPError:
        return self.http_error_body(
            status, json.dumps({"error": code}).encode()
        )

    def http_error_body(self, status: int, body: bytes) -> error.HTTPError:
        return error.HTTPError(
            self.config().node_url,
            status,
            "node error",
            hdrs=None,
            fp=BytesIO(body),
        )

    def test_duplicate_after_lost_success_is_terminal_success(self) -> None:
        for code in (
            "duplicate_device_epoch",
            "duplicate_ticket",
            "duplicate_submission",
        ):
            with self.subTest(code=code), patch(
                "epdn_gateway.relay.request.urlopen",
                side_effect=self.http_error(409, code),
            ):
                self.assertIs(
                    submit_ticket(self.config(), signed_submission()),
                    SubmissionOutcome.ALREADY_RECORDED,
                )

    def test_stale_or_invalid_submission_is_dropped(self) -> None:
        for status, code in (
            (409, "stale_epoch_replay"),
            (422, "invalid_signature"),
            (403, "revoked_device"),
        ):
            with self.subTest(code=code), patch(
                "epdn_gateway.relay.request.urlopen",
                side_effect=self.http_error(status, code),
            ):
                self.assertIs(
                    submit_ticket(self.config(), signed_submission()),
                    SubmissionOutcome.PERMANENTLY_REJECTED,
                )

    def test_transient_node_rejection_keeps_pending_submission(self) -> None:
        for status, code in ((409, "future_epoch"), (429, "busy"), (503, "busy")):
            with self.subTest(status=status, code=code), patch(
                "epdn_gateway.relay.request.urlopen",
                side_effect=self.http_error(status, code),
            ), self.assertRaises(RelayError):
                submit_ticket(self.config(), signed_submission())

    def test_unknown_or_malformed_conflict_keeps_pending_submission(self) -> None:
        for body in (
            b'{"error":"new_node_conflict"}',
            b"not-json",
            b"{}",
        ):
            with self.subTest(body=body), patch(
                "epdn_gateway.relay.request.urlopen",
                side_effect=self.http_error_body(409, body),
            ), self.assertRaises(RelayError):
                submit_ticket(self.config(), signed_submission())


if __name__ == "__main__":
    unittest.main()

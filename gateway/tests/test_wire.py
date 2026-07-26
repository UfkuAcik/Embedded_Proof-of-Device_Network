import struct
import unittest

from epdn_gateway.wire import (
    CHALLENGE_FRAME,
    MAX_SERIAL_PAYLOAD,
    WireError,
    decode_frame,
    encode_frame,
    validate_signed_submission,
)


def challenge() -> bytes:
    chain = b"epdn-local-testnet-v1"
    return (
        b"EPDN"
        + b"\x01"
        + b"\x00\x01"
        + struct.pack(">H", len(chain))
        + chain
        + struct.pack(">Q", 1)
        + bytes(32 * 4)
        + b"\x00"
    )


def submission() -> bytes:
    embedded = challenge()
    return (
        b"EPDN"
        + b"\x04"
        + b"\x00\x01"
        + struct.pack(">I", len(embedded))
        + embedded
        + struct.pack(">H", 64)
        + bytes(range(64))
        + bytes(32)
        + struct.pack(">H", 64)
        + bytes(range(64))
    )


class WireTests(unittest.TestCase):
    def test_uart_frame_round_trip_is_byte_exact(self) -> None:
        original = submission()
        decoded = decode_frame(encode_frame(CHALLENGE_FRAME, original))
        self.assertEqual(decoded.payload, original)

    def test_uart_tamper_is_rejected(self) -> None:
        encoded = bytearray(encode_frame(CHALLENGE_FRAME, b"challenge"))
        encoded[-5] ^= 1
        with self.assertRaises(WireError):
            decode_frame(encoded)

    def test_oversized_uart_payload_is_rejected(self) -> None:
        with self.assertRaises(WireError):
            encode_frame(CHALLENGE_FRAME, bytes(MAX_SERIAL_PAYLOAD + 1))

    def test_signed_submission_requires_fixed_signatures(self) -> None:
        validate_signed_submission(submission())
        malformed = bytearray(submission())
        proof_length_offset = 7 + 4 + len(challenge())
        malformed[proof_length_offset + 1] = 63
        with self.assertRaises(WireError):
            validate_signed_submission(malformed)


if __name__ == "__main__":
    unittest.main()

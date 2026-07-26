import unittest

from epdn_provisioning.serial_frames import (
    CHALLENGE,
    FrameError,
    MAX_PAYLOAD,
    decode_frame,
    encode_frame,
    encode_wifi_credentials,
)


class FrameTests(unittest.TestCase):
    def test_round_trip(self) -> None:
        encoded = encode_frame(CHALLENGE, b"EPDN")
        decoded = decode_frame(encoded)
        self.assertEqual(decoded.frame_type, CHALLENGE)
        self.assertEqual(decoded.payload, b"EPDN")

    def test_tampering_and_oversize_fail(self) -> None:
        encoded = bytearray(encode_frame(CHALLENGE, b"EPDN"))
        encoded[-1] ^= 1
        with self.assertRaises(FrameError):
            decode_frame(encoded)
        with self.assertRaises(FrameError):
            encode_frame(CHALLENGE, b"x" * (MAX_PAYLOAD + 1))

    def test_wifi_bounds(self) -> None:
        self.assertEqual(encode_wifi_credentials("ssid", "pw")[:2], b"\x04\x02")
        with self.assertRaises(FrameError):
            encode_wifi_credentials("x" * 33, "pw")


if __name__ == "__main__":
    unittest.main()

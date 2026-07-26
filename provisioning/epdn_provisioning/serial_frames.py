from __future__ import annotations

from dataclasses import dataclass
import struct
import time
import zlib

MAGIC = b"EPG1"
MAX_PAYLOAD = 2048
HEADER = struct.Struct(">4sBH")
CRC = struct.Struct(">I")

CHALLENGE = 1
SUBMISSION = 2
PROVISIONING_HELLO = 16
WIFI_CREDENTIALS = 17
DEVICE_CERTIFICATE = 18
ENROLL_DEV = 19
ACK = 126
ERROR = 127


class FrameError(ValueError):
    pass


@dataclass(frozen=True)
class Frame:
    frame_type: int
    payload: bytes


def encode_frame(frame_type: int, payload: bytes) -> bytes:
    payload = bytes(payload)
    if not 0 <= frame_type <= 255:
        raise FrameError("frame type is outside uint8")
    if len(payload) > MAX_PAYLOAD:
        raise FrameError("serial frame payload exceeds 2048 bytes")
    header = HEADER.pack(MAGIC, frame_type, len(payload))
    checksum = zlib.crc32(header + payload) & 0xFFFFFFFF
    return header + payload + CRC.pack(checksum)


def decode_frame(data: bytes) -> Frame:
    if len(data) < HEADER.size + CRC.size:
        raise FrameError("truncated serial frame")
    magic, frame_type, length = HEADER.unpack_from(data)
    if magic != MAGIC:
        raise FrameError("invalid serial frame magic")
    if length > MAX_PAYLOAD:
        raise FrameError("serial frame payload exceeds 2048 bytes")
    expected_length = HEADER.size + length + CRC.size
    if len(data) != expected_length:
        raise FrameError("serial frame length mismatch")
    payload = data[HEADER.size : HEADER.size + length]
    expected_crc = CRC.unpack_from(data, HEADER.size + length)[0]
    actual_crc = zlib.crc32(data[: HEADER.size + length]) & 0xFFFFFFFF
    if actual_crc != expected_crc:
        raise FrameError("serial frame checksum mismatch")
    return Frame(frame_type, payload)


def read_frame(port: object, timeout: float = 3.0) -> Frame:
    if not 0 < timeout <= 30:
        raise FrameError("timeout outside safe range")
    deadline = time.monotonic() + timeout

    def read_exact(length: int) -> bytes:
        output = bytearray()
        while len(output) < length and time.monotonic() < deadline:
            chunk = port.read(length - len(output))
            if chunk:
                output.extend(chunk)
        if len(output) != length:
            raise FrameError("serial frame timed out")
        return bytes(output)

    header = read_exact(HEADER.size)
    magic, frame_type, length = HEADER.unpack(header)
    if magic != MAGIC or length > MAX_PAYLOAD:
        raise FrameError("invalid or oversized serial frame header")
    payload = read_exact(length)
    checksum = read_exact(CRC.size)
    return decode_frame(header + payload + checksum)


def write_frame(port: object, frame_type: int, payload: bytes) -> None:
    encoded = encode_frame(frame_type, payload)
    written = port.write(encoded)
    if written != len(encoded):
        raise FrameError("short serial write")
    port.flush()


def encode_wifi_credentials(ssid: str, password: str) -> bytes:
    ssid_bytes = ssid.encode("utf-8")
    password_bytes = password.encode("utf-8")
    if not 1 <= len(ssid_bytes) <= 32:
        raise FrameError("SSID must contain 1..32 UTF-8 bytes")
    if len(password_bytes) > 63:
        raise FrameError("Wi-Fi password must contain at most 63 UTF-8 bytes")
    return bytes((len(ssid_bytes), len(password_bytes))) + ssid_bytes + password_bytes

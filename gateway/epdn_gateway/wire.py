from __future__ import annotations

from dataclasses import dataclass
import struct
import time
import zlib

SERIAL_MAGIC = b"EPG1"
SERIAL_HEADER = struct.Struct(">4sBH")
SERIAL_CRC = struct.Struct(">I")
MAX_SERIAL_PAYLOAD = 2048

CHALLENGE_FRAME = 1
SUBMISSION_FRAME = 2
ERROR_FRAME = 127

EPDN_MAGIC = b"EPDN"
EPDN_HEADER = struct.Struct(">4sBH")
EPDN_VERSION = 1
CHALLENGE_TYPE = 1
SUBMISSION_TYPE = 4
MAX_CHALLENGE = 512
MAX_SUBMISSION = 8192
P256_SIGNATURE = 64


class WireError(ValueError):
    pass


@dataclass(frozen=True)
class Frame:
    frame_type: int
    payload: bytes


def encode_frame(frame_type: int, payload: bytes) -> bytes:
    payload = bytes(payload)
    if not 0 <= frame_type <= 255 or len(payload) > MAX_SERIAL_PAYLOAD:
        raise WireError("invalid or oversized UART frame")
    header = SERIAL_HEADER.pack(SERIAL_MAGIC, frame_type, len(payload))
    crc = zlib.crc32(header + payload) & 0xFFFFFFFF
    return header + payload + SERIAL_CRC.pack(crc)


def decode_frame(data: bytes) -> Frame:
    if len(data) < SERIAL_HEADER.size + SERIAL_CRC.size:
        raise WireError("truncated UART frame")
    magic, frame_type, length = SERIAL_HEADER.unpack_from(data)
    if magic != SERIAL_MAGIC or length > MAX_SERIAL_PAYLOAD:
        raise WireError("invalid or oversized UART frame header")
    expected = SERIAL_HEADER.size + length + SERIAL_CRC.size
    if len(data) != expected:
        raise WireError("UART frame length mismatch")
    payload = data[SERIAL_HEADER.size : SERIAL_HEADER.size + length]
    stored_crc = SERIAL_CRC.unpack_from(data, SERIAL_HEADER.size + length)[0]
    actual_crc = zlib.crc32(data[: SERIAL_HEADER.size + length]) & 0xFFFFFFFF
    if stored_crc != actual_crc:
        raise WireError("UART frame checksum mismatch")
    return Frame(frame_type, payload)


def read_frame(serial_port: object, timeout: float) -> Frame:
    if not 0 < timeout <= 30:
        raise WireError("UART timeout outside safe range")
    deadline = time.monotonic() + timeout

    def exact(length: int) -> bytes:
        output = bytearray()
        while len(output) < length and time.monotonic() < deadline:
            chunk = serial_port.read(length - len(output))
            if chunk:
                output.extend(chunk)
        if len(output) != length:
            raise WireError("UART frame timed out")
        return bytes(output)

    header = exact(SERIAL_HEADER.size)
    magic, _, length = SERIAL_HEADER.unpack(header)
    if magic != SERIAL_MAGIC or length > MAX_SERIAL_PAYLOAD:
        raise WireError("invalid or oversized UART frame header")
    return decode_frame(header + exact(length) + exact(SERIAL_CRC.size))


def write_frame(serial_port: object, frame_type: int, payload: bytes) -> None:
    data = encode_frame(frame_type, payload)
    if serial_port.write(data) != len(data):
        raise WireError("short UART write")
    serial_port.flush()


def validate_challenge(data: bytes) -> None:
    if not 7 <= len(data) <= MAX_CHALLENGE:
        raise WireError("challenge is truncated or oversized")
    magic, object_type, version = EPDN_HEADER.unpack_from(data)
    if (
        magic != EPDN_MAGIC
        or object_type != CHALLENGE_TYPE
        or version != EPDN_VERSION
    ):
        raise WireError("challenge is not EPDN binary V1 object type 1")


def validate_signed_submission(data: bytes) -> None:
    if not 7 <= len(data) <= MAX_SUBMISSION:
        raise WireError("submission is truncated or oversized")
    magic, object_type, version = EPDN_HEADER.unpack_from(data)
    if (
        magic != EPDN_MAGIC
        or object_type != SUBMISSION_TYPE
        or version != EPDN_VERSION
    ):
        raise WireError("submission is not EPDN binary V1 object type 4")

    offset = EPDN_HEADER.size
    if len(data) - offset < 4:
        raise WireError("submission challenge length is truncated")
    challenge_length = struct.unpack_from(">I", data, offset)[0]
    offset += 4
    if challenge_length > MAX_CHALLENGE or len(data) - offset < challenge_length:
        raise WireError("embedded challenge is invalid or oversized")
    validate_challenge(data[offset : offset + challenge_length])
    offset += challenge_length

    if len(data) - offset < 2:
        raise WireError("proof length is truncated")
    proof_length = struct.unpack_from(">H", data, offset)[0]
    offset += 2
    if proof_length != P256_SIGNATURE or len(data) - offset < proof_length:
        raise WireError("submission lacks a canonical 64-byte proof")
    offset += proof_length

    if len(data) - offset < 32 + 2:
        raise WireError("ticket or signature length is truncated")
    offset += 32
    signature_length = struct.unpack_from(">H", data, offset)[0]
    offset += 2
    if signature_length != P256_SIGNATURE or len(data) - offset != signature_length:
        raise WireError("submission lacks a canonical 64-byte signature")

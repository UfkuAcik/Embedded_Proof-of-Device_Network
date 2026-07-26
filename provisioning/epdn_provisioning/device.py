from __future__ import annotations

from contextlib import contextmanager
import time
from typing import Iterator

from .serial_frames import (
    ACK,
    DEVICE_CERTIFICATE,
    ENROLL_DEV,
    ERROR,
    WIFI_CREDENTIALS,
    encode_wifi_credentials,
    read_frame,
    write_frame,
)


class DeviceError(RuntimeError):
    pass


@contextmanager
def open_port(port_name: str, baud: int = 115200) -> Iterator[object]:
    if not port_name.upper().startswith("COM") and not port_name.startswith("/dev/"):
        raise DeviceError("serial port name is not recognized")
    try:
        import serial
    except ImportError as exc:
        raise DeviceError("pyserial is required") from exc
    port = serial.Serial(
        port=port_name,
        baudrate=baud,
        timeout=0.1,
        write_timeout=2,
        exclusive=None,
    )
    try:
        time.sleep(1.5)
        port.reset_input_buffer()
        yield port
    finally:
        port.close()


def enroll_public_key(port_name: str) -> bytes:
    with open_port(port_name) as port:
        write_frame(port, ENROLL_DEV, b"")
        frame = read_frame(port, timeout=5)
    if frame.frame_type == ERROR:
        raise DeviceError("device rejected development enrollment")
    if frame.frame_type != ACK or len(frame.payload) != 33:
        raise DeviceError("device returned an invalid enrollment response")
    if frame.payload[0] not in (2, 3):
        raise DeviceError("device returned a non-canonical P-256 public key")
    return frame.payload


def provision_wifi(port_name: str, ssid: str, password: str) -> None:
    payload = bytearray(encode_wifi_credentials(ssid, password))
    try:
        with open_port(port_name) as port:
            write_frame(port, WIFI_CREDENTIALS, payload)
            frame = read_frame(port, timeout=5)
        if frame.frame_type != ACK:
            raise DeviceError("device rejected Wi-Fi provisioning")
    finally:
        for index in range(len(payload)):
            payload[index] = 0


def install_device_certificate(port_name: str, certificate: bytes) -> None:
    certificate = bytes(certificate)
    if not 1 <= len(certificate) <= 2048:
        raise DeviceError("device certificate must contain 1..2048 bytes")
    with open_port(port_name) as port:
        write_frame(port, DEVICE_CERTIFICATE, certificate)
        frame = read_frame(port, timeout=5)
    if frame.frame_type != ACK:
        raise DeviceError("device rejected certificate installation")

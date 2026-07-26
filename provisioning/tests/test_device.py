from contextlib import contextmanager
import unittest
from unittest.mock import patch

from epdn_provisioning.device import install_device_certificate
from epdn_provisioning.serial_frames import ACK, Frame


class FakePort:
    pass


@contextmanager
def fake_open_port(_: str):
    yield FakePort()


class DeviceTests(unittest.TestCase):
    @patch("epdn_provisioning.device.read_frame", return_value=Frame(ACK, b"\x00"))
    @patch("epdn_provisioning.device.write_frame")
    @patch("epdn_provisioning.device.open_port", side_effect=fake_open_port)
    def test_certificate_is_sent_and_acknowledged(
        self, _open: object, write: object, _read: object
    ) -> None:
        certificate = b"EPDN\x03\x00\x01"
        install_device_certificate("TEST_PORT", certificate)
        self.assertEqual(write.call_args.args[2], certificate)


if __name__ == "__main__":
    unittest.main()

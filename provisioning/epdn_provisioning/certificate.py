from __future__ import annotations

import base64
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import secrets
import struct
from typing import Iterable

P256_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16
)


class CertificateError(RuntimeError):
    pass


def _crypto() -> tuple[object, object, object, object]:
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, utils
    except ImportError as exc:
        raise CertificateError(
            "certificate enrollment requires the optional 'cryptography' package"
        ) from exc
    return hashes, serialization, ec, utils


def _u16(value: bytes, maximum: int, field: str) -> bytes:
    if len(value) > maximum:
        raise CertificateError(f"{field} exceeds {maximum} bytes")
    return struct.pack(">H", len(value)) + value


def _header(object_type: int) -> bytes:
    return b"EPDN" + bytes((object_type,)) + struct.pack(">H", 1)


def hash_domain(domain: bytes, *parts: bytes) -> bytes:
    digest = hashlib.sha256()
    digest.update(domain)
    for part in parts:
        digest.update(part)
    return digest.digest()


@dataclass(frozen=True)
class Enrollment:
    serial_hex: str
    device_public_key_hex: str
    platform: str
    board_family: str
    security_class: int
    authority_id_hex: str
    provisioned_at_unix_seconds: int
    issued_at_epoch: int
    expires_at_epoch: int
    allowed_chain_id: str
    chip_revision: str | None
    batch_id: str | None
    manufacturer: str | None
    allowed_firmware_ids: tuple[str, ...]
    certificate_b64: str

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True)


class DevelopmentAuthority:
    def __init__(self, private_key: object):
        self._private_key = private_key

    @classmethod
    def load_or_create(
        cls, state_directory: Path, password: bytes
    ) -> "DevelopmentAuthority":
        if not password:
            raise CertificateError("development CA password must not be empty")
        _, serialization, ec, _ = _crypto()
        state_directory.mkdir(parents=True, exist_ok=True)
        key_path = state_directory / "dev-ca.key"
        if key_path.exists():
            key = serialization.load_pem_private_key(
                key_path.read_bytes(), password=password
            )
            return cls(key)
        key = ec.generate_private_key(ec.SECP256R1())
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(password),
        )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        descriptor = os.open(key_path, flags, 0o600)
        try:
            os.write(descriptor, pem)
        finally:
            os.close(descriptor)
        return cls(key)

    def public_key_bytes(self) -> bytes:
        _, serialization, _, _ = _crypto()
        return self._private_key.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.CompressedPoint,
        )

    def authority_id(self) -> bytes:
        return hash_domain(b"EPDN_AUTHORITY_ID_V1", self.public_key_bytes())

    def issue(
        self,
        device_public_key: bytes,
        platform: str,
        board_family: str,
        security_class: int,
        provisioned_at_unix_seconds: int,
        issued_at_epoch: int,
        expires_at_epoch: int,
        chain_id: str,
        chip_revision: str | None,
        batch_id: str | None,
        manufacturer: str | None,
        firmware_ids: Iterable[bytes],
    ) -> Enrollment:
        if len(device_public_key) != 33 or device_public_key[0] not in (2, 3):
            raise CertificateError("device public key must be compressed P-256 SEC1")
        if security_class not in range(5):
            raise CertificateError("security class is outside 0..4")
        if not 0 <= issued_at_epoch < expires_at_epoch < 2**64:
            raise CertificateError("invalid certificate epoch interval")
        if not 0 <= provisioned_at_unix_seconds < 2**64:
            raise CertificateError("invalid provisioning timestamp")
        firmware = sorted(set(bytes(value) for value in firmware_ids))
        if len(firmware) > 16 or any(len(value) != 32 for value in firmware):
            raise CertificateError("firmware policy is invalid")

        serial = secrets.token_bytes(16)
        authority_id = self.authority_id()
        payload = bytearray(_header(2))
        payload.extend(serial)
        payload.extend(device_public_key)
        payload.extend(_u16(platform.encode("utf-8"), 32, "platform"))
        payload.extend(_u16(board_family.encode("utf-8"), 48, "board_family"))
        payload.append(security_class)
        payload.extend(authority_id)
        payload.extend(
            struct.pack(
                ">QQQ",
                provisioned_at_unix_seconds,
                issued_at_epoch,
                expires_at_epoch,
            )
        )
        payload.extend(_u16(chain_id.encode("utf-8"), 64, "chain_id"))
        for field, value, maximum in (
            ("chip_revision", chip_revision, 32),
            ("batch_id", batch_id, 64),
            ("manufacturer", manufacturer, 64),
        ):
            if value is None:
                payload.append(0)
            else:
                if not value:
                    raise CertificateError(
                        f"{field} must be omitted instead of encoded empty"
                    )
                payload.append(1)
                payload.extend(_u16(value.encode("utf-8"), maximum, field))
        payload.extend(struct.pack(">H", len(firmware)))
        for firmware_id in firmware:
            payload.extend(firmware_id)

        hashes, _, ec, utils = _crypto()
        digest = hash_domain(b"EPDN_CERT_SIGNATURE_V1", bytes(payload))
        der_signature = self._private_key.sign(
            digest, ec.ECDSA(utils.Prehashed(hashes.SHA256()))
        )
        r, s = utils.decode_dss_signature(der_signature)
        if s > P256_ORDER // 2:
            s = P256_ORDER - s
        signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        certificate = (
            _header(3)
            + struct.pack(">I", len(payload))
            + bytes(payload)
            + struct.pack(">H", len(signature))
            + signature
        )
        return Enrollment(
            serial_hex=serial.hex(),
            device_public_key_hex=device_public_key.hex(),
            platform=platform,
            board_family=board_family,
            security_class=security_class,
            authority_id_hex=authority_id.hex(),
            provisioned_at_unix_seconds=provisioned_at_unix_seconds,
            issued_at_epoch=issued_at_epoch,
            expires_at_epoch=expires_at_epoch,
            allowed_chain_id=chain_id,
            chip_revision=chip_revision,
            batch_id=batch_id,
            manufacturer=manufacturer,
            allowed_firmware_ids=tuple(value.hex() for value in firmware),
            certificate_b64=base64.b64encode(certificate).decode("ascii"),
        )

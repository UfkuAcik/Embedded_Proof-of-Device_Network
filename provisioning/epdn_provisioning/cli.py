from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
from pathlib import Path
import sys
import time

from . import arduino
from .api import enroll_device, register_device, revoke_device
from .certificate import CertificateError, DevelopmentAuthority, hash_domain
from .device import (
    enroll_public_key,
    install_device_certificate,
    open_port,
    provision_wifi,
)
from .safety import SafetyRefusal, production_security_plan, redact


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


DEFAULT_NETWORK_ID = "epdn-local-testnet-v1"
DEFAULT_FIRMWARE_ID = hash_domain(
    b"EPDN_FIRMWARE_ID_V1", b"epdn-miner-development"
).hex()


def _json(value: object) -> None:
    print(json.dumps(value, indent=2, sort_keys=True, default=str))


def _add_compile_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--fqbn", default="esp32:esp32:esp32")
    parser.add_argument(
        "--sketch", default=str(_repository_root() / "arduino/examples/GatewayMiner")
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="epdn-provision")
    subcommands = parser.add_subparsers(dest="command", required=True)

    inspect = subcommands.add_parser("inspect", help="read-only board/port inventory")
    inspect.add_argument("--port")

    enroll = subcommands.add_parser("enroll-dev")
    enroll.add_argument("--port", required=True)
    enroll.add_argument("--node-url", default="http://127.0.0.1:8745")
    enroll.add_argument("--reward-address", required=True)
    enroll.add_argument("--platform", default="esp32")
    enroll.add_argument("--board-family", default="unknown")
    enroll.add_argument("--network-id", default=DEFAULT_NETWORK_ID)
    enroll.add_argument("--provisioned-at-unix-seconds", type=int)
    enroll.add_argument("--issued-at-epoch", type=int, default=0)
    enroll.add_argument("--expires-at-epoch", type=int, default=1_000_000)
    enroll.add_argument("--chip-revision")
    enroll.add_argument("--batch-id")
    enroll.add_argument("--manufacturer")
    enroll.add_argument("--firmware-id", action="append", default=[])
    enroll.add_argument(
        "--local-ca",
        action="store_true",
        help="offline helper only; certificates are not trusted by the default node",
    )
    enroll.add_argument(
        "--output", type=Path, default=Path("provisioning/.state/enrollment.json")
    )

    testnet = subcommands.add_parser("provision-testnet")
    testnet.add_argument("--port", required=True)
    testnet.add_argument("--ssid")
    testnet.add_argument("--configure-wifi", action="store_true")
    testnet.add_argument("--execute-upload", action="store_true")
    _add_compile_options(testnet)

    production = subcommands.add_parser("provision-production")
    production.add_argument(
        "--confirm-irreversible-security-changes", action="store_true"
    )

    register = subcommands.add_parser("register")
    register.add_argument("--node-url", required=True)
    register.add_argument("--enrollment", type=Path, required=True)
    register.add_argument("--reward-address", required=True)

    flash = subcommands.add_parser("flash")
    flash.add_argument("--port", required=True)
    flash.add_argument("--execute", action="store_true")
    _add_compile_options(flash)

    monitor = subcommands.add_parser("monitor")
    monitor.add_argument("--port", required=True)
    monitor.add_argument("--baud", type=int, default=115200)

    diagnose = subcommands.add_parser("diagnose")
    diagnose.add_argument("--port")

    renew = subcommands.add_parser("renew-certificate")
    renew.add_argument("--port", required=True)
    renew.add_argument("--network-id", default=DEFAULT_NETWORK_ID)
    renew.add_argument("--node-url", default="http://127.0.0.1:8745")
    renew.add_argument("--reward-address", required=True)
    renew.add_argument("--expires-at-epoch", type=int, required=True)
    renew.add_argument("--output", type=Path, required=True)

    revoke = subcommands.add_parser("revoke")
    revoke.add_argument("--node-url", required=True)
    revoke.add_argument("--public-id", required=True)
    revoke.add_argument("--reason", required=True)

    plan = subcommands.add_parser("security-plan")
    plan.add_argument("--production", action="store_true")
    plan.add_argument(
        "--confirm-irreversible-security-changes", action="store_true"
    )
    return parser


def _authority() -> DevelopmentAuthority:
    password = os.environ.get("EPDN_DEV_CA_PASSWORD")
    if password is None and sys.stdin.isatty():
        password = getpass.getpass("Development CA password: ")
    if not password:
        raise CertificateError(
            "set EPDN_DEV_CA_PASSWORD or use an interactive terminal"
        )
    try:
        return DevelopmentAuthority.load_or_create(
            _repository_root() / "provisioning/.state", password.encode("utf-8")
        )
    finally:
        password = "<cleared>"


def _enroll(args: argparse.Namespace) -> dict[str, object]:
    public_key = enroll_public_key(args.port)
    firmware_ids = []
    for value in (args.firmware_id or [DEFAULT_FIRMWARE_ID]):
        try:
            decoded = bytes.fromhex(value)
        except ValueError as error:
            raise CertificateError("firmware ID is not hexadecimal") from error
        if len(decoded) != 32:
            raise CertificateError("firmware ID must be exactly 32 bytes")
        firmware_ids.append(decoded)
    provisioned_at = (
        args.provisioned_at_unix_seconds
        if args.provisioned_at_unix_seconds is not None
        else int(time.time())
    )
    if args.local_ca:
        enrollment = _authority().issue(
            device_public_key=public_key,
            platform=args.platform,
            board_family=args.board_family,
            security_class=0,
            provisioned_at_unix_seconds=provisioned_at,
            issued_at_epoch=args.issued_at_epoch,
            expires_at_epoch=args.expires_at_epoch,
            chain_id=args.network_id,
            chip_revision=args.chip_revision,
            batch_id=args.batch_id,
            manufacturer=args.manufacturer,
            firmware_ids=firmware_ids,
        )
        certificate = base64.b64decode(
            enrollment.certificate_b64, validate=True
        )
        device_public_id = hash_domain(
            b"EPDN_DEVICE_PUBLIC_KEY_V1", public_key
        ).hex()
        record = json.loads(enrollment.to_json())
        record["mode"] = "offline-local-ca"
        record["certificate_hex"] = certificate.hex()
        registered = False
    else:
        response = enroll_device(
            args.node_url,
            {
                "device_public_key_sec1_hex": public_key.hex(),
                "platform": args.platform,
                "board_family": args.board_family,
                "security_class": "L0_SOFTWARE_TEST",
                "provisioned_at_unix_seconds": provisioned_at,
                "chip_revision": args.chip_revision,
                "batch_id": args.batch_id,
                "manufacturer": args.manufacturer,
                "allowed_firmware_ids": [value.hex() for value in firmware_ids],
                "expires_at_epoch": args.expires_at_epoch,
            },
        )
        certificate_hex = str(response.get("certificate_hex", ""))
        device_public_id = str(response.get("device_public_id", ""))
        try:
            certificate = bytes.fromhex(certificate_hex)
        except ValueError as error:
            raise CertificateError("node returned invalid certificate hex") from error
        if not certificate or len(device_public_id) != 64:
            raise CertificateError("node returned an incomplete enrollment")
        install_device_certificate(args.port, certificate)
        register_response = register_device(
            args.node_url, certificate_hex, args.reward_address
        )
        record = {
            "mode": "node-ca",
            "certificate_hex": certificate_hex,
            "device_public_id": device_public_id,
            "registration": register_response,
            "allowed_firmware_ids": [value.hex() for value in firmware_ids],
            "security_class": "L0_SOFTWARE_TEST",
        }
        registered = True
    if args.local_ca:
        install_device_certificate(args.port, certificate)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return {
        "status": "enrolled-development",
        "security_class": "L0_SOFTWARE_TEST",
        "output": str(args.output),
        "device_public_id": device_public_id,
        "certificate_installed": True,
        "registered": registered,
    }


def run(args: argparse.Namespace) -> int:
    root = _repository_root()
    libraries = root / "arduino/libraries"
    if args.command in {"inspect", "diagnose"}:
        result = arduino.board_list()
        if args.port:
            result["requested_port"] = args.port
        result["mode"] = "read-only"
        _json(result)
        return 0
    if args.command == "enroll-dev":
        _json(_enroll(args))
        return 0
    if args.command == "provision-testnet":
        compiled = arduino.compile_sketch(
            Path(args.sketch), libraries, fqbn=args.fqbn
        )
        output: dict[str, object] = {
            "compiled": True,
            "fqbn": compiled.fqbn,
            "uploaded": False,
        }
        if args.execute_upload:
            arduino.upload_sketch(
                Path(args.sketch), libraries, args.port, args.fqbn, execute=True
            )
            output["uploaded"] = True
        if args.configure_wifi:
            ssid = args.ssid or input("Wi-Fi SSID: ")
            password = getpass.getpass("Wi-Fi password: ")
            try:
                provision_wifi(args.port, ssid, password)
            finally:
                password = "<cleared>"
            output["wifi_provisioned"] = True
        _json(output)
        return 0
    if args.command == "provision-production":
        _json(
            production_security_plan(
                args.confirm_irreversible_security_changes
            ).as_dict()
        )
        return 0
    if args.command == "register":
        enrollment = json.loads(args.enrollment.read_text(encoding="utf-8"))
        _json(
            register_device(
                args.node_url,
                enrollment["certificate_hex"],
                args.reward_address,
            )
        )
        return 0
    if args.command == "flash":
        command = arduino.upload_sketch(
            Path(args.sketch), libraries, args.port, args.fqbn, args.execute
        )
        _json({"executed": args.execute, "command": command})
        return 0
    if args.command == "monitor":
        with open_port(args.port, args.baud) as port:
            while True:
                line = port.readline(4096)
                if line:
                    print(redact(line.decode("utf-8", errors="replace").rstrip()))
        return 0
    if args.command == "renew-certificate":
        args.platform = "esp32"
        args.board_family = "unknown"
        args.issued_at_epoch = 0
        args.provisioned_at_unix_seconds = None
        args.chip_revision = None
        args.batch_id = None
        args.manufacturer = None
        args.local_ca = False
        args.firmware_id = []
        _json(_enroll(args))
        return 0
    if args.command == "revoke":
        _json(
            revoke_device(args.node_url, args.public_id, args.reason)
        )
        return 0
    if args.command == "security-plan":
        if not args.production:
            _json(
                {
                    "mode": "development",
                    "dry_run": True,
                    "security_class": "L0_SOFTWARE_TEST",
                    "irreversible_changes": [],
                }
            )
        else:
            _json(
                production_security_plan(
                    args.confirm_irreversible_security_changes
                ).as_dict()
            )
        return 0
    raise AssertionError("unreachable command")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        return run(parser.parse_args(argv))
    except (SafetyRefusal, CertificateError, RuntimeError, OSError, ValueError) as error:
        print(f"error: {redact(error)}", file=sys.stderr)
        return 2

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import json
import time
from urllib import error, request

from .wire import (
    CHALLENGE_FRAME,
    ERROR_FRAME,
    MAX_CHALLENGE,
    MAX_SUBMISSION,
    SUBMISSION_FRAME,
    WireError,
    read_frame,
    validate_challenge,
    validate_signed_submission,
    write_frame,
)


class RelayError(RuntimeError):
    pass


class SubmissionOutcome(Enum):
    ACCEPTED = "accepted"
    ALREADY_RECORDED = "already_recorded"
    PERMANENTLY_REJECTED = "permanently_rejected"


_DUPLICATE_ERROR_CODES = frozenset(
    {
        "duplicate_device_epoch",
        "duplicate_ticket",
        "duplicate_submission",
    }
)
_TRANSIENT_HTTP_STATUSES = frozenset({408, 425, 429})
_PERMANENT_CONFLICT_ERROR_CODES = frozenset({"stale_epoch_replay"})


@dataclass(frozen=True)
class RelayConfig:
    node_url: str
    port: str
    device_public_id: str
    firmware_id: str = (
        "6d799d81a4c7c91a16237c7e73c77a10"
        "c4113435143233af5cd603fc334089b4"
    )
    baud: int = 115200
    timeout: float = 5.0
    allow_insecure_development_http: bool = False

    def validate(self) -> None:
        if len(self.node_url) > 256:
            raise RelayError("node URL is too long")
        if not self.node_url.startswith("https://") and not (
            self.allow_insecure_development_http
            and self.node_url.startswith("http://")
        ):
            raise RelayError(
                "HTTPS is required unless development HTTP is explicitly allowed"
            )
        for field, value in (
            ("device public ID", self.device_public_id),
            ("firmware ID", self.firmware_id),
        ):
            if len(value) != 64:
                raise RelayError(f"{field} must be exactly 32 hexadecimal bytes")
            try:
                bytes.fromhex(value)
            except ValueError as error:
                raise RelayError(f"{field} is not hexadecimal") from error
        if not 1200 <= self.baud <= 3_000_000:
            raise RelayError("UART baud is outside the supported range")
        if not 0 < self.timeout <= 30:
            raise RelayError("timeout is outside the supported range")


def _headers(content_type: bool = False) -> dict[str, str]:
    headers = {"Accept": "application/vnd.epdn.v1+octet-stream"}
    if content_type:
        headers["Content-Type"] = "application/vnd.epdn.v1+octet-stream"
    return headers


def fetch_challenge(config: RelayConfig) -> bytes:
    req = request.Request(
        config.node_url.rstrip("/")
        + "/api/v1/epochs/current/"
        + config.device_public_id
        + "/"
        + config.firmware_id,
        method="GET",
        headers={"Accept": "application/json"},
    )
    try:
        with request.urlopen(req, timeout=config.timeout) as response:
            encoded = response.read(2049)
            if len(encoded) > 2048:
                raise RelayError("node challenge response exceeded 2048 bytes")
            body = json.loads(encoded)
            if body.get("encoding") != "EPDN_BINARY_V1_HEX":
                raise RelayError("node returned an unsupported challenge encoding")
            challenge = bytes.fromhex(body["challenge_hex"])
    except (
        error.URLError,
        TimeoutError,
        json.JSONDecodeError,
        KeyError,
        ValueError,
    ) as exc:
        raise RelayError("failed to fetch node challenge") from exc
    validate_challenge(challenge)
    return challenge


def _node_error_code(encoded: bytes) -> str | None:
    try:
        body = json.loads(encoded)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    code = body.get("error") if isinstance(body, dict) else None
    return code if isinstance(code, str) else None


def _classify_rejection(status: int, encoded: bytes) -> SubmissionOutcome:
    code = _node_error_code(encoded)
    if code in _DUPLICATE_ERROR_CODES:
        # The exact signed bytes may already have been committed even when the
        # gateway lost the original success response. Retrying cannot improve
        # this outcome and would wedge the per-epoch queue.
        return SubmissionOutcome.ALREADY_RECORDED
    if status >= 500 or status in _TRANSIENT_HTTP_STATUSES or code == "future_epoch":
        raise RelayError(
            f"node submission endpoint is temporarily unavailable ({status})"
        )
    if status == 409 and code not in _PERMANENT_CONFLICT_ERROR_CODES:
        # A conflict outside the documented node contract is ambiguous. It may
        # be a duplicate response transformed by a proxy or a newer transient
        # node condition. Preserve the immutable bytes instead of dropping
        # them.
        raise RelayError("node returned an unrecognized submission conflict")
    # All other HTTP rejections are terminal for these immutable, already
    # signed bytes (stale epoch, invalid signature/encoding, revoked device,
    # wrong chain, and other bounded 4xx contract failures).
    return SubmissionOutcome.PERMANENTLY_REJECTED


def submit_ticket(config: RelayConfig, submission: bytes) -> SubmissionOutcome:
    validate_signed_submission(submission)
    req = request.Request(
        config.node_url.rstrip("/") + "/api/v1/tickets",
        data=submission,
        method="POST",
        headers=_headers(content_type=True),
    )
    try:
        with request.urlopen(req, timeout=config.timeout) as response:
            encoded = response.read(4097)
            if len(encoded) > 4096:
                raise RelayError("node submission response exceeded 4096 bytes")
            if not 200 <= response.status < 300:
                return _classify_rejection(response.status, encoded)
            return SubmissionOutcome.ACCEPTED
    except error.HTTPError as exc:
        encoded = exc.read(4097)
        if len(encoded) > 4096:
            raise RelayError("node rejection response exceeded 4096 bytes") from exc
        return _classify_rejection(exc.code, encoded)
    except (error.URLError, TimeoutError) as exc:
        raise RelayError("failed to submit device ticket") from exc


class GatewayRelay:
    """Byte relay only: no signer, private key, or ticket construction."""

    def __init__(self, config: RelayConfig):
        config.validate()
        self.config = config

    def relay_once(self, serial_port: object, challenge: bytes) -> bytes:
        validate_challenge(challenge)
        write_frame(serial_port, CHALLENGE_FRAME, challenge)
        frame = read_frame(serial_port, self.config.timeout)
        if frame.frame_type == ERROR_FRAME:
            raise RelayError("device rejected challenge")
        if frame.frame_type != SUBMISSION_FRAME:
            raise RelayError("unexpected UART response type")
        validate_signed_submission(frame.payload)
        return frame.payload

    def run_forever(self) -> None:
        try:
            import serial
        except ImportError as exc:
            raise RelayError("pyserial is required") from exc
        backoff = 1.0
        with serial.Serial(
            self.config.port,
            self.config.baud,
            timeout=0.1,
            write_timeout=2,
            exclusive=None,
        ) as serial_port:
            time.sleep(1.5)
            serial_port.reset_input_buffer()
            pending_submission: bytes | None = None
            while True:
                try:
                    if pending_submission is None:
                        challenge = fetch_challenge(self.config)
                        pending_submission = self.relay_once(
                            serial_port, challenge
                        )
                    # Keep the already device-signed bytes in RAM across
                    # transient node failures. Never ask the device to create
                    # a second ticket for the same reserved epoch.
                    outcome = submit_ticket(self.config, pending_submission)
                    pending_submission = None
                    backoff = 1.0
                    if outcome is SubmissionOutcome.ALREADY_RECORDED:
                        print(
                            '{"component":"epdn-gateway","level":"info",'
                            '"event":"relay_submission_already_recorded"}'
                        )
                    elif outcome is SubmissionOutcome.PERMANENTLY_REJECTED:
                        print(
                            '{"component":"epdn-gateway","level":"warn",'
                            '"event":"relay_submission_dropped"}'
                        )
                except (RelayError, WireError, OSError):
                    # Do not include payloads, tokens, URLs with credentials, or
                    # serial data in logs. Retry is bounded.
                    print(
                        '{"component":"epdn-gateway","level":"warn",'
                        '"event":"relay_retry"}'
                    )
                    time.sleep(backoff)
                    backoff = min(backoff * 2, 60.0)

from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from typing import Any


class SafetyRefusal(RuntimeError):
    """Raised when a guarded action lacks explicit authorization."""


IRREVERSIBLE_FIELDS = (
    "SECURE_BOOT_EN",
    "FLASH_CRYPT_CNT",
    "ABS_DONE_0",
    "JTAG_DISABLE",
    "UART_DOWNLOAD_DIS",
    "ANTI_ROLLBACK_VERSION",
)


@dataclass(frozen=True)
class SecurityPlan:
    mode: str
    dry_run: bool
    will_write_efuses: bool
    fields: tuple[str, ...]
    warning: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def production_security_plan(confirm: bool) -> SecurityPlan:
    """Return an exact, non-executing production plan.

    The confirmation flag is a guard acknowledgement, not authority for this
    MVP to burn fuses. Actual irreversible execution is intentionally absent.
    """

    if not confirm:
        raise SafetyRefusal(
            "production provisioning refused: pass "
            "--confirm-irreversible-security-changes to view the exact "
            "acknowledged plan; this MVP still performs no fuse writes"
        )
    return SecurityPlan(
        mode="production",
        dry_run=True,
        will_write_efuses=False,
        fields=IRREVERSIBLE_FIELDS,
        warning=(
            "PLAN ONLY: no eFuse, Secure Boot, Flash Encryption, JTAG, UART "
            "download, or anti-rollback field will be changed"
        ),
    )


_SENSITIVE_FRAGMENT = (
    r"(?:password|passwd|passphrase|secret|private[_ .-]?key|signing[_ .-]?key|"
    r"api[_ .-]?key|access[_ .-]?key|seed(?:[_ .-]?phrase)?|mnemonic|token|"
    r"authorization|credential|wifi[_ .-]?ssid)"
)
_SENSITIVE_KEY = re.compile(rf"(?i){_SENSITIVE_FRAGMENT}")
_SENSITIVE_KEY_NAME = (
    rf"[A-Za-z0-9_.-]*{_SENSITIVE_FRAGMENT}[A-Za-z0-9_.-]*"
)
_JSON_DOUBLE_VALUE = re.compile(
    rf'(?i)(?P<prefix>"{_SENSITIVE_KEY_NAME}"\s*:\s*)'
    r'"(?:\\.|[^"\\])*"'
)
_JSON_SINGLE_VALUE = re.compile(
    rf"(?i)(?P<prefix>'{_SENSITIVE_KEY_NAME}'\s*:\s*)"
    r"'(?:\\.|[^'\\])*'"
)
_KEY_VALUE = re.compile(
    rf"""(?ix)
    (?<![A-Za-z0-9_.-])
    (?P<key>{_SENSITIVE_KEY_NAME})
    \s*[:=]\s*
    (?:
      "(?:\\.|[^"\\])*"
      |
      '(?:\\.|[^'\\])*'
      |
      [^,;}}\]\r\n]+
    )
    """
)


def redact(value: object) -> str:
    """Redact common secret-bearing text without echoing the matched value."""

    if value is None:
        return ""
    text = str(value)
    if _SENSITIVE_KEY.search(text) and "-----BEGIN" in text:
        return "<redacted-secret-material>"
    text = _JSON_DOUBLE_VALUE.sub(
        lambda match: f'{match.group("prefix")}"<redacted>"',
        text,
    )
    text = _JSON_SINGLE_VALUE.sub(
        lambda match: f"{match.group('prefix')}'<redacted>'",
        text,
    )
    text = _KEY_VALUE.sub(
        lambda match: f"{match.group('key')}=<redacted>",
        text,
    )
    return text


def redact_mapping(value: dict[str, Any]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, item in value.items():
        if _SENSITIVE_KEY.search(str(key)):
            output[key] = "<redacted>"
        elif isinstance(item, dict):
            output[key] = redact_mapping(item)
        elif isinstance(item, list):
            output[key] = [
                redact_mapping(entry)
                if isinstance(entry, dict)
                else [
                    redact_mapping(nested)
                    if isinstance(nested, dict)
                    else redact(nested)
                    for nested in entry
                ]
                if isinstance(entry, list)
                else redact(entry)
                for entry in item
            ]
        elif isinstance(item, str):
            output[key] = redact(item)
        else:
            output[key] = item
    return output

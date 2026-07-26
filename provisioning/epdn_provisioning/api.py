from __future__ import annotations

import json
import os
import re
from urllib.parse import urlparse
from urllib import error, request


class ApiError(RuntimeError):
    pass


LOCAL_DEVELOPMENT_TOKEN = "epdn-local-admin-change-me"
MAX_REVOCATION_REASON_BYTES = 128


def _admin_token(url: str) -> str:
    token = os.environ.get("EPDN_NODE_TOKEN")
    if token:
        return token
    hostname = (urlparse(url).hostname or "").lower()
    if hostname in {"127.0.0.1", "::1", "localhost"}:
        return LOCAL_DEVELOPMENT_TOKEN
    raise ApiError("EPDN_NODE_TOKEN is required for non-loopback node URLs")


def _request_json(method: str, url: str, body: dict[str, object]) -> dict[str, object]:
    token = _admin_token(url)
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    headers["x-epdn-admin-token"] = token
    encoded = json.dumps(body, separators=(",", ":")).encode("utf-8")
    req = request.Request(url, data=encoded, method=method, headers=headers)
    try:
        with request.urlopen(req, timeout=10) as response:
            payload = response.read(1_048_577)
            if len(payload) > 1_048_576:
                raise ApiError("node response exceeded 1 MiB")
            return json.loads(payload) if payload else {}
    except error.HTTPError as exc:
        response_body = exc.read(4097)
        code = "unknown_error"
        if len(response_body) <= 4096:
            try:
                candidate = json.loads(response_body).get("error")
                if isinstance(candidate, str) and re.fullmatch(
                    r"[a-z0-9_-]{1,64}", candidate
                ):
                    code = candidate
            except (json.JSONDecodeError, UnicodeDecodeError, AttributeError):
                pass
        raise ApiError(f"node API HTTP {exc.code}: {code}") from exc
    except (error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise ApiError("node API request failed") from exc


def enroll_device(node_url: str, body: dict[str, object]) -> dict[str, object]:
    return _request_json(
        "POST",
        node_url.rstrip("/") + "/api/v1/admin/enroll",
        body,
    )


def register_device(
    node_url: str, certificate_hex: str, reward_address: str
) -> dict[str, object]:
    return _request_json(
        "POST",
        node_url.rstrip("/") + "/api/v1/admin/register",
        {
            "certificate_hex": certificate_hex,
            "reward_address": reward_address,
        },
    )


def revoke_device(
    node_url: str, public_id: str, reason: str
) -> dict[str, object]:
    if (
        not reason.strip()
        or len(reason.encode("utf-8")) > MAX_REVOCATION_REASON_BYTES
    ):
        raise ApiError(
            "revocation reason must be non-blank and contain at most "
            f"{MAX_REVOCATION_REASON_BYTES} UTF-8 bytes"
        )
    return _request_json(
        "POST",
        node_url.rstrip("/") + f"/api/v1/admin/miners/{public_id}/revoke",
        {"reason": reason},
    )

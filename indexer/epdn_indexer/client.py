"""Bounded HTTP client for the public EPDN node API."""

from __future__ import annotations

import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen


class NodeClientError(RuntimeError):
    """The configured node could not provide a valid public response."""


class NodeClient:
    def __init__(
        self,
        base_url: str,
        *,
        timeout_seconds: float = 5.0,
        maximum_response_bytes: int = 16 * 1024 * 1024,
    ) -> None:
        parsed = urlparse(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("node URL must be an absolute HTTP(S) URL")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("node URL must not embed credentials")
        if parsed.query or parsed.fragment:
            raise ValueError("node URL must not contain a query or fragment")
        if timeout_seconds <= 0:
            raise ValueError("node timeout must be positive")
        if maximum_response_bytes <= 0:
            raise ValueError("maximum response size must be positive")
        self.base_url = base_url.rstrip("/") + "/"
        self.timeout_seconds = timeout_seconds
        self.maximum_response_bytes = maximum_response_bytes

    def status(self) -> dict[str, Any]:
        value = self._json("/api/v1/network/status")
        if not isinstance(value, dict):
            raise NodeClientError("network status must be a JSON object")
        return value

    def blocks(self) -> list[dict[str, Any]]:
        value = self._json("/api/v1/blocks")
        if not isinstance(value, list) or not all(
            isinstance(block, dict) for block in value
        ):
            raise NodeClientError("blocks endpoint must be a JSON array of objects")
        return value

    def _json(self, path: str) -> Any:
        request = Request(
            urljoin(self.base_url, path.lstrip("/")),
            headers={"accept": "application/json", "user-agent": "epdn-indexer/0.1"},
        )
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                content_type = response.headers.get_content_type()
                if content_type != "application/json":
                    raise NodeClientError(
                        f"node returned unsupported content type {content_type!r}"
                    )
                declared = response.headers.get("content-length")
                if declared and int(declared) > self.maximum_response_bytes:
                    raise NodeClientError("node response exceeds configured size limit")
                body = response.read(self.maximum_response_bytes + 1)
        except (HTTPError, URLError, TimeoutError, ValueError) as error:
            raise NodeClientError(f"node request failed: {error}") from error
        if len(body) > self.maximum_response_bytes:
            raise NodeClientError("node response exceeds configured size limit")
        try:
            return json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise NodeClientError(f"node returned malformed JSON: {error}") from error

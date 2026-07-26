from __future__ import annotations

import argparse
import sys

from .relay import GatewayRelay, RelayConfig, RelayError
from .wire import WireError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="epdn-gateway")
    parser.add_argument("--node-url", required=True)
    parser.add_argument("--port", required=True)
    parser.add_argument("--device-public-id", required=True)
    parser.add_argument(
        "--firmware-id",
        default=(
            "6d799d81a4c7c91a16237c7e73c77a10"
            "c4113435143233af5cd603fc334089b4"
        ),
    )
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument(
        "--allow-insecure-development-http",
        action="store_true",
        help="allow plaintext HTTP only for an explicitly local development node",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = RelayConfig(
        node_url=args.node_url,
        port=args.port,
        device_public_id=args.device_public_id,
        firmware_id=args.firmware_id,
        baud=args.baud,
        timeout=args.timeout,
        allow_insecure_development_http=args.allow_insecure_development_http,
    )
    try:
        GatewayRelay(config).run_forever()
    except (RelayError, WireError, OSError) as error:
        print(f"gateway error: {error}", file=sys.stderr)
        return 2
    return 0

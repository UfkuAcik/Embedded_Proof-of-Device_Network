"""Command-line entry point for the lightweight EPDN indexer."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from .client import NodeClient, NodeClientError
from .service import IndexerService
from .store import IndexerError, IndexerStore


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(prog="epdn-indexer")
    command.add_argument(
        "--node-url",
        default=os.environ.get("EPDN_NODE_URL", "http://127.0.0.1:8745"),
    )
    command.add_argument(
        "--database",
        default=os.environ.get(
            "EPDN_INDEXER_DB", str(Path(".epdn") / "indexer.sqlite3")
        ),
    )
    subcommands = command.add_subparsers(dest="command", required=True)
    subcommands.add_parser("sync", help="apply the node's finalized snapshot")
    subcommands.add_parser("rescan", help="discard and rebuild the read model")
    subcommands.add_parser("status", help="print local index status")
    export = subcommands.add_parser("export", help="write a privacy-safe JSON export")
    export.add_argument("--output", default="-")
    export.add_argument("--genesis-unix", type=int)
    return command


def _write_atomic(path: Path, payload: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as output:
            output.write(payload)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        Path(temporary_name).unlink(missing_ok=True)
        raise


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        with IndexerStore(args.database) as store:
            if args.command == "status":
                result = store.summary()
            elif args.command == "export":
                result = store.public_export(genesis_unix=args.genesis_unix)
                payload = json.dumps(result, indent=2, sort_keys=True)
                if args.output == "-":
                    print(payload)
                else:
                    _write_atomic(Path(args.output), payload)
                    print(json.dumps({"output": args.output, "summary": result["summary"]}))
                return 0
            else:
                service = IndexerService(NodeClient(args.node_url), store)
                result = service.rescan() if args.command == "rescan" else service.sync()
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
    except (IndexerError, NodeClientError, OSError, ValueError) as error:
        print(f"epdn-indexer: {error}", file=sys.stderr)
        return 1

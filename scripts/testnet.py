"""Run three local EPDN node processes without claiming P2P finality.

`smoke` also executes the deterministic three-validator commit/reveal test.
The three HTTP processes are operational fixtures; the current node does not
yet peer them into a Byzantine finality network.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import urlopen


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_STATE = ROOT / ".epdn" / "testnet"
DEFAULT_PORTS = (8745, 8746, 8747)
PID_FILE_NAME = "processes.json"
ADMIN_TOKEN = "test-only-epdn-local-admin-token"


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(prog="testnet.py")
    command.add_argument(
        "--ports",
        default=",".join(str(port) for port in DEFAULT_PORTS),
        help="three comma-separated loopback ports",
    )
    command.add_argument("--state-dir", type=Path, default=DEFAULT_STATE)
    command.add_argument("--binary", "--node-binary", dest="binary", type=Path)
    command.add_argument(
        "--rustup-toolchain",
        default=os.environ.get("EPDN_RUSTUP_TOOLCHAIN"),
        help="optional rustup toolchain used for cargo build/test",
    )
    command.add_argument("--timeout", type=float, default=15.0)
    subcommands = command.add_subparsers(dest="command", required=True)
    subcommands.add_parser("up", help="start three persistent local node processes")
    subcommands.add_parser("status", help="query all recorded local node processes")
    subcommands.add_parser("down", help="stop only the recorded EPDN node processes")
    subcommands.add_parser(
        "smoke",
        help="start temporary nodes, check APIs, run consensus test, and stop",
    )
    return command


def parse_ports(value: str) -> tuple[int, int, int]:
    try:
        ports = tuple(int(item.strip()) for item in value.split(","))
    except ValueError as error:
        raise ValueError("ports must be integers") from error
    if len(ports) != 3 or len(set(ports)) != 3:
        raise ValueError("exactly three distinct ports are required")
    if any(port < 1024 or port > 65535 for port in ports):
        raise ValueError("ports must be between 1024 and 65535")
    return ports  # type: ignore[return-value]


def cargo_command(toolchain: str | None, *arguments: str) -> list[str]:
    if toolchain:
        rustup = shutil.which("rustup")
        if not rustup:
            raise FileNotFoundError(
                "rustup is not on PATH; cannot select the requested toolchain"
            )
        return [rustup, "run", toolchain, "cargo", *arguments]
    cargo = shutil.which("cargo")
    if not cargo:
        raise FileNotFoundError(
            "cargo is not on PATH; pass --node-binary or add the Rust toolchain"
        )
    return [cargo, *arguments]


def binary_path(explicit: Path | None, toolchain: str | None) -> Path:
    if explicit:
        candidate = explicit.expanduser().resolve()
        if not candidate.is_file():
            raise FileNotFoundError(f"EPDN node binary does not exist at {candidate}")
        return candidate

    suffix = ".exe" if os.name == "nt" else ""
    candidate = ROOT / "target" / "debug" / f"epdn-node{suffix}"
    subprocess.run(
        cargo_command(toolchain, "build", "--locked", "-p", "epdn-node"),
        cwd=ROOT,
        check=True,
    )
    if not candidate.is_file():
        raise FileNotFoundError(f"EPDN node binary was not produced at {candidate}")
    return candidate


def port_available(port: int) -> bool:
    with socket.socket() as probe:
        probe.settimeout(0.2)
        return probe.connect_ex(("127.0.0.1", port)) != 0


def health(port: int, timeout: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urlopen(f"http://127.0.0.1:{port}/healthz", timeout=1) as response:
                value = json.load(response)
            if value.get("status") == "ok":
                return value
        except (OSError, URLError, ValueError) as error:
            last_error = error
        time.sleep(0.15)
    raise RuntimeError(f"node on port {port} did not become healthy: {last_error}")


def network_status(port: int) -> dict[str, Any]:
    with urlopen(
        f"http://127.0.0.1:{port}/api/v1/network/status", timeout=2
    ) as response:
        value = json.load(response)
    if not isinstance(value, dict):
        raise RuntimeError(f"node on port {port} returned invalid status")
    return value


def validator_key(index: int) -> str:
    return hashlib.sha256(f"test-only-epdn-validator-{index}".encode()).hexdigest()


def start_processes(
    executable: Path,
    ports: tuple[int, int, int],
    state_dir: Path,
    timeout: float,
) -> tuple[list[subprocess.Popen[bytes]], list[dict[str, Any]]]:
    if any(not port_available(port) for port in ports):
        raise RuntimeError("one or more requested testnet ports are already in use")
    state_dir.mkdir(parents=True, exist_ok=True)
    processes: list[subprocess.Popen[bytes]] = []
    records: list[dict[str, Any]] = []
    try:
        for index, port in enumerate(ports, start=1):
            node_dir = state_dir / f"validator-{index}"
            node_dir.mkdir(parents=True, exist_ok=True)
            log_path = node_dir / "node.jsonl"
            environment = os.environ.copy()
            environment.update(
                {
                    "EPDN_BIND_ADDR": f"127.0.0.1:{port}",
                    "EPDN_STATE_PATH": str(node_dir / "state.journal"),
                    "EPDN_ADMIN_TOKEN": ADMIN_TOKEN,
                    "EPDN_VALIDATOR_PRIVATE_KEY_HEX": validator_key(index),
                    "EPDN_CORS_ORIGINS": (
                        "http://localhost:3000,http://127.0.0.1:3000"
                    ),
                    "RUST_LOG": "epdn_node=info",
                }
            )
            creation_flags = (
                subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
            )
            with log_path.open("ab", buffering=0) as log:
                process = subprocess.Popen(
                    [str(executable)],
                    cwd=ROOT,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    creationflags=creation_flags,
                )
            processes.append(process)
            records.append(
                {
                    "validator": index,
                    "pid": process.pid,
                    "port": port,
                    "binary": str(executable),
                    "state": str(node_dir / "state.journal"),
                    "log": str(log_path),
                }
            )
        for port in ports:
            health(port, timeout)
        return processes, records
    except BaseException:
        stop_handles(processes)
        raise


def stop_handles(processes: list[subprocess.Popen[bytes]]) -> None:
    for process in processes:
        if process.poll() is None:
            process.terminate()
    deadline = time.monotonic() + 5
    for process in processes:
        remaining = max(0.0, deadline - time.monotonic())
        try:
            process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)


def write_pid_file(state_dir: Path, records: list[dict[str, Any]]) -> None:
    pid_file = state_dir / PID_FILE_NAME
    temporary = pid_file.with_suffix(".tmp")
    temporary.write_text(
        json.dumps({"version": 1, "processes": records}, indent=2) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, pid_file)


def read_pid_file(state_dir: Path) -> list[dict[str, Any]]:
    pid_file = state_dir / PID_FILE_NAME
    value = json.loads(pid_file.read_text(encoding="utf-8"))
    records = value.get("processes")
    if not isinstance(records, list):
        raise RuntimeError("testnet process file is malformed")
    return records


def process_matches(pid: int, expected_binary: Path) -> bool:
    try:
        if os.name == "nt":
            result = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    f"(Get-Process -Id {pid} -ErrorAction Stop).Path",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            actual = Path(result.stdout.strip()).resolve() if result.returncode == 0 else None
        elif sys.platform == "darwin":
            result = subprocess.run(
                ["ps", "-p", str(pid), "-o", "command="],
                check=False,
                capture_output=True,
                text=True,
            )
            actual = (
                Path(result.stdout.strip()).resolve()
                if result.returncode == 0 and result.stdout.strip()
                else None
            )
        else:
            actual = Path(os.readlink(f"/proc/{pid}/exe")).resolve()
        return actual == expected_binary.resolve()
    except (OSError, RuntimeError, ValueError):
        return False


def stop_recorded(state_dir: Path) -> None:
    records = read_pid_file(state_dir)
    refused: list[int] = []
    for record in records:
        pid = int(record["pid"])
        expected_binary = Path(record["binary"])
        if not process_matches(pid, expected_binary):
            refused.append(pid)
            continue
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            continue
    if refused:
        raise RuntimeError(
            f"refused to signal PIDs not matching the recorded node binary: {refused}"
        )
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        remaining = [
            int(record["pid"])
            for record in records
            if process_matches(int(record["pid"]), Path(record["binary"]))
        ]
        if not remaining:
            break
        time.sleep(0.1)
    else:
        raise RuntimeError(
            f"recorded node processes did not stop within five seconds: {remaining}"
        )
    (state_dir / PID_FILE_NAME).unlink(missing_ok=True)


def validate_statuses(ports: tuple[int, int, int]) -> list[dict[str, Any]]:
    statuses = [network_status(port) for port in ports]
    if {status.get("protocol_version") for status in statuses} != {1}:
        raise RuntimeError("validators disagree on protocol version")
    if {status.get("chain_id") for status in statuses} != {
        "epdn-local-testnet-v1"
    }:
        raise RuntimeError("validators disagree on chain ID")
    if len({status.get("height") for status in statuses}) != 1:
        raise RuntimeError("fresh validator processes disagree on initial height")
    return statuses


def consensus_test(toolchain: str | None) -> None:
    subprocess.run(
        cargo_command(
            toolchain,
            "test",
            "--locked",
            "-p",
            "epdn-protocol",
            "three_validators_finalize_identically_in_any_arrival_order",
        ),
        cwd=ROOT,
        check=True,
    )


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        ports = parse_ports(args.ports)
        if args.command == "down":
            stop_recorded(args.state_dir)
            print("Stopped recorded EPDN local testnet processes.")
            return 0
        if args.command == "status":
            records = read_pid_file(args.state_dir)
            statuses = validate_statuses(tuple(int(item["port"]) for item in records))
            print(json.dumps(statuses, indent=2))
            return 0

        executable = binary_path(args.binary, args.rustup_toolchain)
        if args.command == "up":
            pid_file = args.state_dir / PID_FILE_NAME
            if pid_file.exists():
                raise RuntimeError("testnet process file already exists; use status or down")
            _, records = start_processes(
                executable, ports, args.state_dir, args.timeout
            )
            write_pid_file(args.state_dir, records)
            print(
                json.dumps(
                    {
                        "status": "running",
                        "validators": records,
                        "limitation": (
                            "three API processes; P2P finality is not implemented"
                        ),
                    },
                    indent=2,
                )
            )
            return 0

        with tempfile.TemporaryDirectory(prefix="epdn-testnet-smoke-") as temporary:
            processes, _ = start_processes(
                executable, ports, Path(temporary), args.timeout
            )
            try:
                statuses = validate_statuses(ports)
                consensus_test(args.rustup_toolchain)
            finally:
                stop_handles(processes)
        print(
            json.dumps(
                {
                    "status": "passed",
                    "processes": len(statuses),
                    "chain_id": statuses[0]["chain_id"],
                    "agreement_test": (
                        "three_validators_finalize_identically_in_any_arrival_order"
                    ),
                    "limitation": "operational processes are not P2P peers",
                },
                indent=2,
            )
        )
        return 0
    except (
        FileNotFoundError,
        json.JSONDecodeError,
        KeyError,
        OSError,
        RuntimeError,
        subprocess.CalledProcessError,
        ValueError,
    ) as error:
        print(f"testnet: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

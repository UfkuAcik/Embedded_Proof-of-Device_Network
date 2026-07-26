from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import shutil
import subprocess
from typing import Any

from .safety import redact


class ToolError(RuntimeError):
    pass


@dataclass(frozen=True)
class CompileResult:
    fqbn: str
    sketch: str
    stdout: str


def _run(arguments: list[str], timeout: int = 120) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            arguments,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ToolError(f"tool execution failed: {redact(error)}") from error
    if result.returncode != 0:
        message = redact(result.stderr or result.stdout)
        raise ToolError(f"tool returned {result.returncode}: {message}")
    return result


def board_list() -> dict[str, Any]:
    executable = shutil.which("arduino-cli")
    if executable is None:
        raise ToolError("arduino-cli was not found on PATH")
    result = _run([executable, "board", "list", "--format", "json"], timeout=30)
    return json.loads(result.stdout)


def compile_sketch(
    sketch: Path,
    libraries: Path,
    fqbn: str = "esp32:esp32:esp32",
) -> CompileResult:
    executable = shutil.which("arduino-cli")
    if executable is None:
        raise ToolError("arduino-cli was not found on PATH")
    result = _run(
        [
            executable,
            "compile",
            "--fqbn",
            fqbn,
            "--libraries",
            str(libraries),
            str(sketch),
        ],
        timeout=300,
    )
    return CompileResult(fqbn=fqbn, sketch=str(sketch), stdout=result.stdout.strip())


def upload_sketch(
    sketch: Path,
    libraries: Path,
    port: str,
    fqbn: str,
    execute: bool,
) -> list[str]:
    executable = shutil.which("arduino-cli")
    if executable is None:
        raise ToolError("arduino-cli was not found on PATH")
    command = [
        executable,
        "compile",
        "--upload",
        "--fqbn",
        fqbn,
        "--port",
        port,
        "--libraries",
        str(libraries),
        str(sketch),
    ]
    if not execute:
        return command
    _run(command, timeout=300)
    return command

"""Fail CI when secret-bearing files or obvious credentials enter Git."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
SKIP_PARTS = {
    ".git",
    ".next",
    ".vinext",
    ".wrangler",
    "__pycache__",
    "coverage",
    "dist",
    "node_modules",
    "target",
}
TEXT_SUFFIXES = {
    "",
    ".c",
    ".cc",
    ".cer",
    ".cfg",
    ".conf",
    ".config",
    ".cpp",
    ".crt",
    ".css",
    ".env",
    ".h",
    ".hpp",
    ".html",
    ".ini",
    ".ino",
    ".js",
    ".json",
    ".key",
    ".md",
    ".mjs",
    ".pem",
    ".properties",
    ".ps1",
    ".py",
    ".rs",
    ".sh",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".yaml",
    ".yml",
}
BINARY_SECRET_SUFFIXES = {
    ".der",
    ".jks",
    ".keystore",
    ".p12",
    ".pfx",
}
FORBIDDEN_NAMES = {
    "device-identity.json",
    "secrets_local.h",
    "wifi.local.json",
}
PUBLIC_FIXTURE_PATHS = {
    "protocol/test-vectors/v1.json",
}
LOCAL_ONLY_PATHS = {
    "dashboard/.openai/hosting.json",
}
SELF_PATHS = {
    "scripts/check-secrets.py",
}

# Split high-signal literals so this source file does not match itself.
PRIVATE_KEY_MARKER = "-----BEGIN " + "PRIVATE KEY-----"
PRIVATE_KEY_MARKER_WITH_ALG = re.compile(
    r"-----BEGIN (?:EC |RSA |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"
)

SENSITIVE_KEY_FRAGMENT = (
    r"(?:password|passwd|passphrase|secret(?!s(?:\b|[_.-]))|"
    r"token(?!s(?:\b|[_.-]))|authorization|credential|"
    r"api[_.-]?key|access[_.-]?key|private[_.-]?key|signing[_.-]?key|"
    r"wifi[_.-]?ssid)"
)
SENSITIVE_KEY_NAME = (
    rf"[A-Za-z0-9_.-]*{SENSITIVE_KEY_FRAGMENT}[A-Za-z0-9_.-]*"
)
JSON_CREDENTIAL = re.compile(
    rf"""(?ix)
    ["'](?P<key>{SENSITIVE_KEY_NAME})["'][ \t]*:[ \t]*
    (?P<quote>["'])(?P<value>.*?)(?P=quote)
    """
)
QUOTED_CREDENTIAL = re.compile(
    rf"""(?ix)
    (?<![A-Za-z0-9_.-])
    (?P<key>{SENSITIVE_KEY_NAME})[ \t]*[:=][ \t]*
    (?P<quote>["'])(?P<value>.*?)(?P=quote)
    """
)
UNQUOTED_CONFIG_CREDENTIAL = re.compile(
    rf"""(?imx)
    ^\s*(?:export\s+)?
    (?P<key>{SENSITIVE_KEY_NAME})[ \t]*[:=][ \t]*
    (?P<value>[^\s\#;,}}\]]+)
    """
)

TOKEN_PATTERNS = (
    (
        "OpenAI API key",
        re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
    ),
    (
        "GitHub token",
        re.compile(
            r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b"
        ),
    ),
    (
        "AWS access key",
        re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    ),
    (
        "Google API key",
        re.compile(r"\bAIza[A-Za-z0-9_-]{30,}\b"),
    ),
    (
        "Slack token",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    ),
    (
        "Stripe live secret",
        re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b"),
    ),
    (
        "npm access token",
        re.compile(r"\bnpm_[A-Za-z0-9]{20,}\b"),
    ),
    (
        "JWT",
        re.compile(
            r"\beyJ[A-Za-z0-9_-]{8,}\."
            r"eyJ[A-Za-z0-9_-]{8,}\."
            r"[A-Za-z0-9_-]{16,}\b"
        ),
    ),
)

CONFIG_SUFFIXES = {
    ".cfg",
    ".conf",
    ".config",
    ".env",
    ".ini",
    ".json",
    ".properties",
    ".toml",
    ".yaml",
    ".yml",
}
PLACEHOLDER_MARKERS = (
    "change-me",
    "changeme",
    "dummy",
    "example",
    "fake",
    "hunter2",
    "local-admin",
    "placeholder",
    "redacted",
    "replace-locally",
    "replace-me",
    "sample",
    "test-",
    "test_",
)


def normalized_path(path: str | Path | PurePosixPath) -> PurePosixPath:
    return PurePosixPath(str(path).replace("\\", "/"))


def is_forbidden_path(path: str | Path | PurePosixPath) -> bool:
    relative = normalized_path(path)
    if relative.as_posix().lower() in LOCAL_ONLY_PATHS:
        return True
    lower_name = relative.name.lower()
    lower_parts = {part.lower() for part in relative.parts}

    if lower_name == ".env" or (
        lower_name.startswith(".env.") and lower_name != ".env.example"
    ):
        return True
    if lower_name in FORBIDDEN_NAMES or "secrets" in lower_parts:
        return True
    if relative.suffix.lower() in BINARY_SECRET_SUFFIXES:
        return True
    if relative.suffix.lower() == ".key":
        return True
    return False


def is_text_candidate(path: str | Path | PurePosixPath) -> bool:
    return normalized_path(path).suffix.lower() in TEXT_SUFFIXES


def is_placeholder(value: str) -> bool:
    normalized = value.strip().strip("\"'").lower()
    if not normalized:
        return True
    if normalized in {"abc", "none", "null", "true", "false"}:
        return True
    if normalized.startswith(("$", "<", "{")):
        return True
    if normalized.startswith(
        ("env::var", "getpass.", "input(", "os.environ", "process.env")
    ):
        return True
    return any(marker in normalized for marker in PLACEHOLDER_MARKERS)


def find_text_findings(
    path: str | Path | PurePosixPath,
    text: str,
) -> list[str]:
    relative = normalized_path(path)
    relative_text = relative.as_posix()
    if relative_text in SELF_PATHS:
        return []

    findings: list[str] = []
    if PRIVATE_KEY_MARKER in text or PRIVATE_KEY_MARKER_WITH_ALG.search(text):
        findings.append("private-key PEM marker")

    for label, pattern in TOKEN_PATTERNS:
        if pattern.search(text):
            findings.append(f"probable {label}")

    if relative_text not in PUBLIC_FIXTURE_PATHS:
        matches: Iterable[re.Match[str]] = (
            *JSON_CREDENTIAL.finditer(text),
            *QUOTED_CREDENTIAL.finditer(text),
        )
        if any(not is_placeholder(match.group("value")) for match in matches):
            findings.append("probable hard-coded credential assignment")

        if relative.suffix.lower() in CONFIG_SUFFIXES and any(
            not is_placeholder(match.group("value"))
            for match in UNQUOTED_CONFIG_CREDENTIAL.finditer(text)
        ):
            findings.append("probable unquoted credential assignment")

    return sorted(set(findings))


def git_paths() -> list[Path] | None:
    result = subprocess.run(
        [
            "git",
            "-C",
            str(ROOT),
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
        ],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if result.returncode != 0:
        return None
    return [ROOT / line for line in result.stdout.splitlines() if line]


def candidate_files() -> list[Path]:
    """Prefer Git's view but also work before the first commit."""

    paths = git_paths()
    if paths is None:
        paths = [path for path in ROOT.rglob("*") if path.is_file()]
    return sorted(
        path
        for path in paths
        if path.is_file()
        and (
            is_text_candidate(path)
            or is_forbidden_path(path.relative_to(ROOT))
        )
        and not any(part in SKIP_PARTS for part in path.relative_to(ROOT).parts)
    )


def current_tree_findings(paths: list[Path]) -> list[str]:
    findings: list[str] = []
    for path in paths:
        relative = path.relative_to(ROOT)
        if is_forbidden_path(relative):
            findings.append(f"{relative}: forbidden secret-bearing path")
        if not is_text_candidate(relative):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for finding in find_text_findings(relative, text):
            findings.append(f"{relative}: {finding}")
    return findings


def history_blob_entries() -> list[tuple[str, PurePosixPath]]:
    commits = subprocess.run(
        ["git", "-C", str(ROOT), "rev-list", "--all"],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if commits.returncode != 0:
        return []

    entries: set[tuple[str, PurePosixPath]] = set()
    for commit in commits.stdout.splitlines():
        tree = subprocess.run(
            ["git", "-C", str(ROOT), "ls-tree", "-r", "-z", "--full-tree", commit],
            check=False,
            capture_output=True,
        )
        if tree.returncode != 0:
            continue
        for raw_entry in tree.stdout.split(b"\0"):
            if not raw_entry or b"\t" not in raw_entry:
                continue
            metadata, raw_path = raw_entry.split(b"\t", 1)
            fields = metadata.split()
            if len(fields) != 3 or fields[1] != b"blob":
                continue
            blob_id = fields[2].decode("ascii")
            path = normalized_path(raw_path.decode("utf-8", errors="replace"))
            entries.add((blob_id, path))
    return sorted(entries, key=lambda item: (item[1].as_posix(), item[0]))


def history_findings() -> list[str]:
    findings: list[str] = []
    for blob_id, relative in history_blob_entries():
        origin = f"history:{blob_id[:12]}:{relative.as_posix()}"
        # Local deployment bindings are blocked in the checked-out tree. They
        # are identifiers rather than credentials, so an already-removed
        # historic copy does not make every future CI run permanently fail.
        if (
            is_forbidden_path(relative)
            and relative.as_posix().lower() not in LOCAL_ONLY_PATHS
        ):
            findings.append(f"{origin}: forbidden secret-bearing path")
        if not is_text_candidate(relative):
            continue

        blob = subprocess.run(
            ["git", "-C", str(ROOT), "cat-file", "blob", blob_id],
            check=False,
            capture_output=True,
        )
        if blob.returncode != 0 or len(blob.stdout) > 2_000_000:
            continue
        try:
            text = blob.stdout.decode("utf-8")
        except UnicodeDecodeError:
            continue
        for finding in find_text_findings(relative, text):
            findings.append(f"{origin}: {finding}")
    return findings


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--history",
        action="store_true",
        help="also scan every blob reachable from local Git refs",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    paths = candidate_files()
    findings = current_tree_findings(paths)
    if args.history:
        findings.extend(history_findings())
    findings = sorted(set(findings))

    if findings:
        print("Secret scan failed:", file=sys.stderr)
        for finding in findings:
            print(f"- {finding}", file=sys.stderr)
        return 1

    history_note = " and Git history" if args.history else ""
    print(f"Secret scan passed ({len(paths)} files checked{history_note}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

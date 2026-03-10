from __future__ import annotations

import argparse
import fnmatch
import json
import os
from datetime import UTC, datetime
from pathlib import Path

from . import __version__
from .config import (
    CACHE_FILE_NAME,
    CONFIG_FILE_NAME,
    RepoGuardConfig,
    ensure_default_config,
    load_config,
)
from .git_utils import (
    find_repo_root,
    get_git_dir,
    get_upstream_branch,
    list_changed_tracked_files,
    list_repo_files,
    list_tracked_files,
)
from .reporting import ScanSummary, exit_code, format_report, recommendations
from .scanner import find_suspicious_tracked_files, scan_paths


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="repo-guard", description="Repository safety scanner.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command")

    init_parser = subparsers.add_parser("init", help="Create config and run initial full scan.")
    init_parser.set_defaults(func=cmd_init)

    check_parser = subparsers.add_parser(
        "check", help="Scan changed tracked files against upstream."
    )
    check_parser.set_defaults(func=cmd_check)

    full_parser = subparsers.add_parser("full", help="Run full repository scan.")
    full_parser.set_defaults(func=cmd_full)

    doctor_parser = subparsers.add_parser("doctor", help="Show repository and environment health.")
    doctor_parser.set_defaults(func=cmd_doctor)

    hook_parser = subparsers.add_parser(
        "install-hook", help="Install a pre-push hook for repo checks."
    )
    hook_parser.set_defaults(func=cmd_install_hook)

    return parser


def _load_repo_config(repo_root: Path) -> RepoGuardConfig:
    config, _, _ = load_config(repo_root)
    return config


def _require_repo_root() -> Path | None:
    return find_repo_root(Path.cwd())


def _write_cache(repo_root: Path, summary: ScanSummary, command_name: str) -> None:
    cache_path = repo_root / CACHE_FILE_NAME
    payload = {
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "command": command_name,
        "scan_label": summary.scan_label,
        "scanned_files": summary.scanned_files,
        "fail_count": len(summary.fail_findings),
        "warn_count": len(summary.warn_findings),
    }
    cache_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _print_summary(summary: ScanSummary, include_recommendations: bool = False) -> None:
    print(format_report(summary))
    if include_recommendations:
        print("")
        print("Recommendations:")
        for recommendation in recommendations(summary):
            print(f"- {recommendation}")


def cmd_init(_: argparse.Namespace) -> int:
    repo_root = _require_repo_root()
    if repo_root is None:
        print("FAIL: Not inside a git repository.")
        return 2

    config_path, created = ensure_default_config(repo_root)
    config = _load_repo_config(repo_root)
    tracked_files = list_tracked_files(repo_root)
    files_to_scan = list_repo_files(repo_root)

    summary = scan_paths(
        repo_root=repo_root,
        files_to_scan=files_to_scan,
        tracked_files=tracked_files,
        config=config,
        scan_label="init (full repository scan)",
    )
    if created:
        summary.notes.insert(0, f"Created starter config at {config_path.name}.")
    else:
        summary.notes.insert(0, f"Using existing config at {config_path.name}.")

    _write_cache(repo_root, summary, "init")
    _print_summary(summary, include_recommendations=True)
    return exit_code(summary)


def cmd_check(_: argparse.Namespace) -> int:
    repo_root = _require_repo_root()
    if repo_root is None:
        print("FAIL: Not inside a git repository.")
        return 2

    config = _load_repo_config(repo_root)
    tracked_files = list_tracked_files(repo_root)
    upstream = get_upstream_branch(repo_root)

    notes: list[str] = []
    if upstream:
        scan_label = f"check (changed tracked files vs {upstream})"
        files_to_scan = list_changed_tracked_files(repo_root, upstream)
        if not files_to_scan:
            notes.append("No changed tracked files relative to upstream.")
    else:
        scan_label = "check (fallback: full repository scan)"
        files_to_scan = list_repo_files(repo_root)
        notes.append("No upstream branch configured; scanning all repository files.")

    summary = scan_paths(
        repo_root=repo_root,
        files_to_scan=files_to_scan,
        tracked_files=tracked_files,
        config=config,
        scan_label=scan_label,
    )
    summary.notes.extend(notes)

    _write_cache(repo_root, summary, "check")
    _print_summary(summary)
    return exit_code(summary)


def cmd_full(_: argparse.Namespace) -> int:
    repo_root = _require_repo_root()
    if repo_root is None:
        print("FAIL: Not inside a git repository.")
        return 2

    config = _load_repo_config(repo_root)
    tracked_files = list_tracked_files(repo_root)
    files_to_scan = list_repo_files(repo_root)

    summary = scan_paths(
        repo_root=repo_root,
        files_to_scan=files_to_scan,
        tracked_files=tracked_files,
        config=config,
        scan_label="full (all repository files)",
    )

    _write_cache(repo_root, summary, "full")
    _print_summary(summary)
    return exit_code(summary)


def _gitignore_patterns(repo_root: Path) -> tuple[Path, list[str]]:
    gitignore_path = repo_root / ".gitignore"
    if not gitignore_path.exists():
        return gitignore_path, []

    patterns: list[str] = []
    for raw_line in gitignore_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        patterns.append(line.lstrip("/"))
    return gitignore_path, patterns


def _is_ignored_by_gitignore(sample_name: str, patterns: list[str]) -> bool:
    for pattern in patterns:
        if fnmatch.fnmatch(sample_name, pattern) or fnmatch.fnmatch(
            f"subdir/{sample_name}", pattern
        ):
            return True
    return False


def cmd_doctor(_: argparse.Namespace) -> int:
    repo_root = _require_repo_root()
    if repo_root is None:
        print("repo-guard doctor")
        print("FAIL: Not inside a git repository.")
        return 1

    print("repo-guard doctor")
    print(f"PASS: Inside git repository at {repo_root}")

    upstream = get_upstream_branch(repo_root)
    if upstream:
        print(f"PASS: Upstream branch detected ({upstream})")
    else:
        print("WARN: No upstream branch configured.")

    config_path = repo_root / CONFIG_FILE_NAME
    if config_path.exists():
        print(f"PASS: Found {CONFIG_FILE_NAME}")
    else:
        print(f"WARN: Missing {CONFIG_FILE_NAME} (defaults will be used).")

    tracked_files = list_tracked_files(repo_root)
    suspicious_tracked = find_suspicious_tracked_files(tracked_files)
    tracked_dotenv = [path for path in suspicious_tracked if Path(path).name == ".env"]

    if tracked_dotenv:
        preview = ", ".join(tracked_dotenv[:5])
        suffix = " ..." if len(tracked_dotenv) > 5 else ""
        print(f"WARN: Tracked .env file(s): {preview}{suffix}")
    else:
        print("PASS: No tracked .env files detected.")

    if suspicious_tracked:
        preview = ", ".join(suspicious_tracked[:8])
        suffix = " ..." if len(suspicious_tracked) > 8 else ""
        print(f"WARN: Suspicious tracked files detected: {preview}{suffix}")
    else:
        print("PASS: No suspicious tracked secret/cert/key files detected.")

    _, patterns = _gitignore_patterns(repo_root)
    required_gitignore_samples = {
        ".env": ".env",
        ".env.*": ".env.local",
        "*.pem": "secret.pem",
        "*.key": "private.key",
        "*.p12": "bundle.p12",
        "id_rsa": "id_rsa",
        "credentials.json": "credentials.json",
    }

    missing_patterns = [
        label
        for label, sample in required_gitignore_samples.items()
        if not _is_ignored_by_gitignore(sample, patterns)
    ]

    if missing_patterns:
        print("WARN: .gitignore may not cover common secret files: " + ", ".join(missing_patterns))
    else:
        print("PASS: .gitignore covers common secret-file patterns.")

    return 0


def cmd_install_hook(_: argparse.Namespace) -> int:
    repo_root = _require_repo_root()
    if repo_root is None:
        print("FAIL: Not inside a git repository.")
        return 2

    git_dir = get_git_dir(repo_root)
    if git_dir is None:
        print("FAIL: Unable to locate .git directory.")
        return 2

    ruff_bin = repo_root / "venv" / "bin" / "ruff"
    python_bin = repo_root / "venv" / "bin" / "python"
    missing: list[str] = []

    if not ruff_bin.exists() or not os.access(ruff_bin, os.X_OK):
        missing.append("venv/bin/ruff")
    if not python_bin.exists() or not os.access(python_bin, os.X_OK):
        missing.append("venv/bin/python")
    if not (repo_root / "src" / "repo_guard").exists():
        missing.append("src/repo_guard package")

    if missing:
        print("FAIL: Missing required dependencies/components for hook installation:")
        for item in missing:
            print(f"- {item}")
        print("Install or create these components, then run `repo-guard install-hook` again.")
        return 2

    hook_path = git_dir / "hooks" / "pre-push"
    hook_path.parent.mkdir(parents=True, exist_ok=True)
    hook_contents = """#!/usr/bin/env bash
set -euo pipefail

if [[ ! -x "venv/bin/ruff" ]]; then
  echo "[repo-guard] Missing venv/bin/ruff. Install Ruff in this repo's venv." >&2
  exit 1
fi

if [[ ! -x "venv/bin/python" ]]; then
  echo "[repo-guard] Missing venv/bin/python. Create the venv first." >&2
  exit 1
fi

export PYTHONPATH="$PWD/src:${PYTHONPATH:-}"

venv/bin/ruff check .
venv/bin/python -m repo_guard check
"""
    hook_path.write_text(hook_contents, encoding="utf-8")
    hook_path.chmod(0o755)

    print(f"PASS: Installed pre-push hook at {hook_path}")
    print("Hook commands:")
    print("- venv/bin/ruff check .")
    print("- venv/bin/python -m repo_guard check")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return 2
    return args.func(args)

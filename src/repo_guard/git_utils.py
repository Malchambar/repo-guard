from __future__ import annotations

import subprocess
from pathlib import Path


def _run_git(repo_root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )


def find_repo_root(start: Path | None = None) -> Path | None:
    working_dir = start or Path.cwd()
    process = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=working_dir,
        capture_output=True,
        text=True,
        check=False,
    )
    if process.returncode != 0:
        return None
    root = process.stdout.strip()
    return Path(root).resolve() if root else None


def get_git_dir(repo_root: Path) -> Path | None:
    process = _run_git(repo_root, "rev-parse", "--git-dir")
    if process.returncode != 0:
        return None
    git_dir = process.stdout.strip()
    if not git_dir:
        return None
    path = Path(git_dir)
    if not path.is_absolute():
        path = (repo_root / path).resolve()
    return path


def get_upstream_branch(repo_root: Path) -> str | None:
    process = _run_git(repo_root, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}")
    if process.returncode != 0:
        return None
    upstream = process.stdout.strip()
    return upstream or None


def list_tracked_files(repo_root: Path) -> list[str]:
    process = _run_git(repo_root, "ls-files", "-z")
    if process.returncode != 0:
        return []
    return sorted(path for path in process.stdout.split("\0") if path)


def list_repo_files(repo_root: Path) -> list[str]:
    files: list[str] = []
    for path in repo_root.rglob("*"):
        if not path.is_file():
            continue
        if ".git" in path.parts:
            continue
        files.append(path.relative_to(repo_root).as_posix())
    return sorted(files)


def list_changed_tracked_files(repo_root: Path, upstream: str) -> list[str]:
    tracked_files = set(list_tracked_files(repo_root))
    changed_files: set[str] = set()

    diff_commands = [
        ("diff", "--name-only", "--diff-filter=ACMR", f"{upstream}...HEAD"),
        ("diff", "--name-only", "--diff-filter=ACMR"),
        ("diff", "--name-only", "--diff-filter=ACMR", "--cached"),
    ]

    for command in diff_commands:
        process = _run_git(repo_root, *command)
        if process.returncode != 0:
            continue
        changed_files.update(path for path in process.stdout.splitlines() if path)

    return sorted(path for path in changed_files if path in tracked_files)

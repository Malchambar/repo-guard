from __future__ import annotations

import fnmatch
import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from re import Pattern

from .config import RepoGuardConfig
from .reporting import Finding, ScanSummary

SUSPICIOUS_TRACKED_FILE_GLOBS = [
    ".env",
    ".env.*",
    "*.pem",
    "*.p12",
    "*.key",
    "*.pfx",
    "id_rsa",
    "**/id_rsa",
    "credentials.json",
    "**/credentials.json",
    ".aws/credentials",
    "**/.aws/credentials",
    ".pypirc",
    "**/.pypirc",
    ".netrc",
    "**/.netrc",
    ".npmrc",
    "**/.npmrc",
]

SECRET_PATTERNS: list[tuple[str, Pattern[str], str]] = [
    ("secrets", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "Possible AWS access key detected."),
    (
        "secrets",
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b"),
        "Possible GitHub token detected.",
    ),
    (
        "secrets",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        "Possible Slack token detected.",
    ),
    (
        "secrets",
        re.compile(r"\bBearer\s+[A-Za-z0-9\-._~+/]{16,}=*\b", re.IGNORECASE),
        "Possible bearer token detected.",
    ),
    (
        "secrets",
        re.compile(r"-----BEGIN (?:[A-Z ]*?)PRIVATE KEY-----"),
        "Private key block detected.",
    ),
    (
        "secrets",
        re.compile(r"-----BEGIN [A-Z0-9 ]+-----"),
        "PEM block detected.",
    ),
]

SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"""
    \b(?P<name>api[_-]?key|token|secret|password|passwd|pwd|client[_-]?secret|access[_-]?key)\b
    \s*[:=]\s*
    (?P<value>"[^"\n]{8,}"|'[^'\n]{8,}'|[A-Za-z0-9_\-+/=]{12,})
    """,
    re.IGNORECASE | re.VERBOSE,
)

AWS_SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"""
    \b(?:aws_)?secret(?:_access)?_key\b
    \s*[:=]\s*
    (?P<value>"[^"\n]{20,}"|'[^'\n]{20,}'|[A-Za-z0-9/+=]{40})
    """,
    re.IGNORECASE | re.VERBOSE,
)

EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
INTERNAL_HOST_PATTERN = re.compile(r"\b[a-zA-Z0-9.-]+\.(?:local|internal|corp|lan|home)\b")
USER_PATH_PATTERNS = [
    re.compile(r"(?<!\w)/Users/[A-Za-z0-9._-]+(?:/[^\s'\"`]+)?"),
    re.compile(r"(?<!\w)/home/[A-Za-z0-9._-]+(?:/[^\s'\"`]+)?"),
    re.compile(r"[A-Za-z]:\\Users\\[A-Za-z0-9._-]+(?:\\[^\s'\"`]+)?"),
]

PLACEHOLDER_TERMS = (
    "example",
    "changeme",
    "replace-me",
    "replace_me",
    "dummy",
    "sample",
    "test",
    "xxxx",
    "your_",
    "your-",
    "<redacted>",
)


@dataclass(slots=True)
class _ScanContext:
    allow_patterns: list[Pattern[str]]
    custom_terms: list[str]


def scan_paths(
    repo_root: Path,
    files_to_scan: Sequence[str],
    tracked_files: Sequence[str],
    config: RepoGuardConfig,
    scan_label: str,
) -> ScanSummary:
    context = _build_context(config)
    findings: list[Finding] = []
    scanned_files = 0
    skipped_files = 0

    for relative_path in sorted(set(files_to_scan)):
        if _is_ignored(relative_path, config):
            continue

        absolute_path = repo_root / relative_path
        if not absolute_path.exists() or not absolute_path.is_file():
            continue
        if _is_binary_file(absolute_path):
            skipped_files += 1
            continue

        scanned_files += 1
        findings.extend(_scan_file(absolute_path, relative_path, config, context))

    findings.extend(scan_repo_hygiene(repo_root, tracked_files, config, context))

    deduped_findings = sorted(
        set(findings), key=lambda item: (item.path, item.line or 0, item.message)
    )
    summary = ScanSummary(
        scan_label=scan_label, scanned_files=scanned_files, findings=deduped_findings
    )
    if skipped_files:
        summary.notes.append(f"Skipped {skipped_files} binary/non-text file(s).")
    return summary


def scan_repo_hygiene(
    repo_root: Path,
    tracked_files: Sequence[str],
    config: RepoGuardConfig,
    context: _ScanContext,
) -> list[Finding]:
    findings: list[Finding] = []
    tracked_set = set(tracked_files)

    dotenv_path = repo_root / ".env"
    dotenv_example_path = repo_root / ".env.example"
    if dotenv_path.exists() and not dotenv_example_path.exists():
        finding = _new_finding(
            category="hygiene",
            path=".env",
            message=".env exists but .env.example is missing.",
            config=config,
            context=context,
            line_text=".env exists without .env.example",
            line=None,
        )
        if finding is not None:
            findings.append(finding)

    for relative_path in sorted(tracked_set):
        if _is_ignored(relative_path, config):
            continue
        if not _is_suspicious_tracked_file(relative_path):
            continue
        finding = _new_finding(
            category="sensitive_files",
            path=relative_path,
            message="Tracked file name suggests sensitive data.",
            config=config,
            context=context,
            line_text=relative_path,
            line=None,
        )
        if finding is not None:
            findings.append(finding)

    return findings


def find_suspicious_tracked_files(tracked_files: Sequence[str]) -> list[str]:
    return sorted(path for path in tracked_files if _is_suspicious_tracked_file(path))


def _build_context(config: RepoGuardConfig) -> _ScanContext:
    allow_patterns: list[Pattern[str]] = []
    for pattern in config.allow_patterns:
        try:
            allow_patterns.append(re.compile(pattern))
        except re.error:
            # Invalid user pattern should not crash scans.
            continue
    custom_terms = [term.lower() for term in config.custom_sensitive_terms if term.strip()]
    return _ScanContext(allow_patterns=allow_patterns, custom_terms=custom_terms)


def _scan_file(
    absolute_path: Path,
    relative_path: str,
    config: RepoGuardConfig,
    context: _ScanContext,
) -> list[Finding]:
    findings: list[Finding] = []

    with absolute_path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.rstrip("\n")
            findings.extend(_scan_line(relative_path, line_number, line, config, context))

    return findings


def _scan_line(
    relative_path: str,
    line_number: int,
    line: str,
    config: RepoGuardConfig,
    context: _ScanContext,
) -> list[Finding]:
    findings: list[Finding] = []
    stripped_line = line.strip()
    if not stripped_line:
        return findings

    for category, pattern, message in SECRET_PATTERNS:
        if not pattern.search(stripped_line):
            continue
        finding = _new_finding(
            category=category,
            path=relative_path,
            message=message,
            config=config,
            context=context,
            line_text=stripped_line,
            line=line_number,
        )
        if finding is not None:
            findings.append(finding)

    assignment_match = SECRET_ASSIGNMENT_PATTERN.search(stripped_line)
    if assignment_match:
        value = assignment_match.group("value").strip("\"'")
        if not _looks_placeholder(value):
            variable_name = assignment_match.group("name")
            finding = _new_finding(
                category="secrets",
                path=relative_path,
                message=f"Possible hardcoded secret assignment ({variable_name}).",
                config=config,
                context=context,
                line_text=stripped_line,
                line=line_number,
            )
            if finding is not None:
                findings.append(finding)

    aws_match = AWS_SECRET_ASSIGNMENT_PATTERN.search(stripped_line)
    if aws_match and not _looks_placeholder(aws_match.group("value").strip("\"'")):
        finding = _new_finding(
            category="secrets",
            path=relative_path,
            message="Possible AWS secret access key assignment.",
            config=config,
            context=context,
            line_text=stripped_line,
            line=line_number,
        )
        if finding is not None:
            findings.append(finding)

    for email in EMAIL_PATTERN.findall(stripped_line):
        domain = email.rsplit("@", 1)[-1].lower()
        if domain in {"example.com", "example.org", "example.net"}:
            continue
        finding = _new_finding(
            category="pii",
            path=relative_path,
            message="Email address detected.",
            config=config,
            context=context,
            line_text=stripped_line,
            line=line_number,
        )
        if finding is not None:
            findings.append(finding)

    for hostname_match in INTERNAL_HOST_PATTERN.finditer(stripped_line):
        if hostname_match.start() > 0 and stripped_line[hostname_match.start() - 1] == ".":
            continue
        finding = _new_finding(
            category="local_paths",
            path=relative_path,
            message="Internal hostname/domain detected.",
            config=config,
            context=context,
            line_text=stripped_line,
            line=line_number,
        )
        if finding is not None:
            findings.append(finding)

    for pattern in USER_PATH_PATTERNS:
        if not pattern.search(stripped_line):
            continue
        finding = _new_finding(
            category="local_paths",
            path=relative_path,
            message="Hardcoded local user path detected.",
            config=config,
            context=context,
            line_text=stripped_line,
            line=line_number,
        )
        if finding is not None:
            findings.append(finding)

    lowered = stripped_line.lower()
    for term in context.custom_terms:
        if term and term in lowered:
            finding = _new_finding(
                category="custom",
                path=relative_path,
                message=f"Custom sensitive term detected ({term}).",
                config=config,
                context=context,
                line_text=stripped_line,
                line=line_number,
            )
            if finding is not None:
                findings.append(finding)

    return findings


def _new_finding(
    category: str,
    path: str,
    message: str,
    config: RepoGuardConfig,
    context: _ScanContext,
    line_text: str,
    line: int | None,
) -> Finding | None:
    if _is_allowed(path, line_text, context):
        return None

    severity = config.severity_for(category)
    if severity is None:
        return None

    excerpt = line_text.strip()
    if len(excerpt) > 180:
        excerpt = f"{excerpt[:177]}..."

    return Finding(
        severity=severity,
        category=category,
        path=path,
        line=line,
        message=message,
        excerpt=excerpt,
    )


def _is_allowed(path: str, line_text: str, context: _ScanContext) -> bool:
    for pattern in context.allow_patterns:
        if pattern.search(path) or pattern.search(line_text):
            return True
    return False


def _looks_placeholder(value: str) -> bool:
    lowered = value.lower()
    return any(term in lowered for term in PLACEHOLDER_TERMS)


def _is_ignored(relative_path: str, config: RepoGuardConfig) -> bool:
    normalized = relative_path.replace("\\", "/")
    pure_path = Path(normalized)
    for pattern in config.ignore_paths:
        cleaned = pattern.strip()
        if not cleaned:
            continue
        if fnmatch.fnmatch(normalized, cleaned) or pure_path.match(cleaned):
            return True
    return False


def _is_binary_file(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            chunk = handle.read(4096)
    except OSError:
        return True
    return b"\x00" in chunk


def _is_suspicious_tracked_file(relative_path: str) -> bool:
    normalized = relative_path.replace("\\", "/")
    pure_path = Path(normalized)
    return any(
        fnmatch.fnmatch(normalized, pattern) or pure_path.match(pattern)
        for pattern in SUSPICIOUS_TRACKED_FILE_GLOBS
    )

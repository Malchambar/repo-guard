from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Severity = Literal["FAIL", "WARN"]


@dataclass(slots=True, frozen=True)
class Finding:
    severity: Severity
    category: str
    path: str
    message: str
    line: int | None = None
    excerpt: str | None = None


@dataclass(slots=True)
class ScanSummary:
    scan_label: str
    scanned_files: int
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def fail_findings(self) -> list[Finding]:
        return [finding for finding in self.findings if finding.severity == "FAIL"]

    @property
    def warn_findings(self) -> list[Finding]:
        return [finding for finding in self.findings if finding.severity == "WARN"]

    @property
    def has_failures(self) -> bool:
        return bool(self.fail_findings)


def _location(finding: Finding) -> str:
    return f"{finding.path}:{finding.line}" if finding.line is not None else finding.path


def _sorted_findings(findings: list[Finding]) -> list[Finding]:
    severity_rank = {"FAIL": 0, "WARN": 1}
    return sorted(
        findings,
        key=lambda item: (
            severity_rank.get(item.severity, 99),
            item.path,
            item.line if item.line is not None else 0,
            item.category,
        ),
    )


def format_report(summary: ScanSummary) -> str:
    lines: list[str] = [
        f"repo-guard: {summary.scan_label}",
        f"Scanned files: {summary.scanned_files}",
    ]

    for note in summary.notes:
        lines.append(f"Note: {note}")

    ordered_failures = _sorted_findings(summary.fail_findings)
    ordered_warnings = _sorted_findings(summary.warn_findings)

    if ordered_failures:
        lines.append("")
        lines.append(f"FAIL findings ({len(ordered_failures)}):")
        for finding in ordered_failures:
            lines.append(f"- {_location(finding)} [{finding.category}] {finding.message}")
            if finding.excerpt:
                lines.append(f"  -> {finding.excerpt}")

    if ordered_warnings:
        lines.append("")
        lines.append(f"WARN findings ({len(ordered_warnings)}):")
        for finding in ordered_warnings:
            lines.append(f"- {_location(finding)} [{finding.category}] {finding.message}")
            if finding.excerpt:
                lines.append(f"  -> {finding.excerpt}")

    lines.append("")
    if ordered_failures:
        lines.append("Result: FAIL")
    elif ordered_warnings:
        lines.append("Result: PASS (with warnings)")
    else:
        lines.append("Result: PASS")

    return "\n".join(lines)


def recommendations(summary: ScanSummary) -> list[str]:
    if not summary.findings:
        return ["No action required."]

    recs: list[str] = []
    if summary.fail_findings:
        recs.append("Remove or redact likely secrets and rotate exposed credentials.")
    if any(finding.category == "sensitive_files" for finding in summary.findings):
        recs.append("Untrack sensitive files and add matching entries to .gitignore.")
    if any(finding.category == "local_paths" for finding in summary.findings):
        recs.append("Replace personal machine paths with generic examples like ~/project.")
    if any(finding.category == "hygiene" for finding in summary.findings):
        recs.append("Address hygiene warnings before publishing this repository.")
    return recs


def exit_code(summary: ScanSummary) -> int:
    return 1 if summary.has_failures else 0

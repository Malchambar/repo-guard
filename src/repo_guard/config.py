from __future__ import annotations

import textwrap
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_FILE_NAME = ".repo-guard.toml"
CACHE_FILE_NAME = ".repo-guard-cache.json"

DEFAULT_IGNORE_PATHS = [
    ".git/**",
    "venv/**",
    ".venv/**",
    "node_modules/**",
    "build/**",
    "dist/**",
    ".mypy_cache/**",
    ".pytest_cache/**",
    ".ruff_cache/**",
]

DEFAULT_FAIL_ON = {"secrets"}
DEFAULT_WARN_ON = {"pii", "local_paths", "hygiene", "sensitive_files", "custom"}


def _as_string_list(value: object, fallback: list[str]) -> list[str]:
    if not isinstance(value, list):
        return fallback
    output = [item.strip() for item in value if isinstance(item, str) and item.strip()]
    return output if output else fallback


def _as_category_set(value: object, fallback: set[str]) -> set[str]:
    if not isinstance(value, list):
        return set(fallback)
    output = {item.strip().lower() for item in value if isinstance(item, str) and item.strip()}
    return output if output else set(fallback)


@dataclass(slots=True)
class RepoGuardConfig:
    ignore_paths: list[str] = field(default_factory=lambda: list(DEFAULT_IGNORE_PATHS))
    allow_patterns: list[str] = field(default_factory=list)
    custom_sensitive_terms: list[str] = field(default_factory=list)
    fail_on: set[str] = field(default_factory=lambda: set(DEFAULT_FAIL_ON))
    warn_on: set[str] = field(default_factory=lambda: set(DEFAULT_WARN_ON))

    @classmethod
    def from_mapping(cls, data: dict[str, object]) -> RepoGuardConfig:
        return cls(
            ignore_paths=_as_string_list(data.get("ignore_paths"), list(DEFAULT_IGNORE_PATHS)),
            allow_patterns=_as_string_list(data.get("allow_patterns"), []),
            custom_sensitive_terms=_as_string_list(data.get("custom_sensitive_terms"), []),
            fail_on=_as_category_set(data.get("fail_on"), DEFAULT_FAIL_ON),
            warn_on=_as_category_set(data.get("warn_on"), DEFAULT_WARN_ON),
        )

    def severity_for(self, category: str) -> str | None:
        normalized = category.lower()
        if normalized in self.fail_on:
            return "FAIL"
        if normalized in self.warn_on:
            return "WARN"
        return None


def load_config(repo_root: Path) -> tuple[RepoGuardConfig, Path, bool]:
    config_path = repo_root / CONFIG_FILE_NAME
    if not config_path.exists():
        return RepoGuardConfig(), config_path, False

    try:
        parsed = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"Invalid TOML in {config_path}: {exc}") from exc

    if not isinstance(parsed, dict):
        raise ValueError(f"Invalid config structure in {config_path}")

    return RepoGuardConfig.from_mapping(parsed), config_path, True


def default_config_toml() -> str:
    return textwrap.dedent(
        """
        # repo-guard configuration
        ignore_paths = [
          "venv/**",
          ".venv/**",
          "build/**",
          "dist/**",
        ]

        # Regex patterns used to suppress findings for known-safe content.
        allow_patterns = [
          # "example\\.com",
        ]

        # Extra terms to flag when they appear in files.
        custom_sensitive_terms = [
          # "internal-project-name",
        ]

        fail_on = ["secrets"]
        warn_on = ["pii", "local_paths", "hygiene", "sensitive_files", "custom"]
        """
    ).lstrip()


def ensure_default_config(repo_root: Path) -> tuple[Path, bool]:
    config_path = repo_root / CONFIG_FILE_NAME
    if config_path.exists():
        return config_path, False
    config_path.write_text(default_config_toml(), encoding="utf-8")
    return config_path, True

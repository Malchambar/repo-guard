# repo-guard

`repo-guard` is a local repository safety checker for catching likely secrets,
PII, local machine details, and hygiene issues before code is pushed or made
public.

## Features

- Practical secret and sensitive-data scanning
- Incremental checks against your upstream branch for daily use
- Full repository scans for pre-publication safety checks
- Repo health diagnostics (`doctor`)
- Optional pre-push hook installer
- Repo-local configuration via `.repo-guard.toml`

## Requirements

- Python `3.12+`
- Git repository
- Ruff (`ruff`) for linting/formatting and hook integration

## Installation

```bash
python3.12 -m venv venv
venv/bin/pip install -e ".[dev]"
```

The editable install above creates the console script:

```bash
venv/bin/repo-guard --help
```

## Usage

```bash
# Option A (recommended): stable repo-root launcher
./repo-guard check
./repo-guard doctor
```

```bash
# Option B: generated console script from pip install -e
# First-time setup: creates .repo-guard.toml (if missing) and runs full scan
venv/bin/repo-guard init

# Daily use: scans changed tracked files vs upstream, with fallback behavior
venv/bin/repo-guard check

# Full scan (pre-publication / major changes)
venv/bin/repo-guard full

# Diagnose repo and environment hygiene
venv/bin/repo-guard doctor

# Install pre-push hook in .git/hooks/pre-push
venv/bin/repo-guard install-hook
```

```bash
# Module entrypoint
venv/bin/python -m repo_guard check
```

## Config file: `.repo-guard.toml`

`repo-guard` loads `.repo-guard.toml` from the repo root. If missing, defaults
are used, and `repo-guard init` can create a starter file.

Example:

```toml
ignore_paths = [
  "venv/**",
  ".venv/**",
  "build/**",
]

allow_patterns = [
  "example\\.com",
]

custom_sensitive_terms = [
  "internal-project-code",
]

fail_on = ["secrets"]
warn_on = ["pii", "local_paths", "hygiene", "sensitive_files", "custom"]
```

## Exit codes

- Non-zero when any `FAIL` findings exist
- Zero for `PASS` and `WARN`-only results (unless categories are configured to
  fail)

## Development

```bash
venv/bin/ruff format .
venv/bin/ruff check .
```

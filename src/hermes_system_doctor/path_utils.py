from __future__ import annotations

from pathlib import Path


def safe_relpath(path: Path, root: Path) -> str:
    """Return a report-safe path relative to root, or a redacted basename fallback."""
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except (OSError, ValueError, RuntimeError):
        return f"[REDACTED_PATH]/{path.name}"


def safe_home_label(path: Path) -> str:
    """Return a public-report-safe label for the inspected Hermes home."""
    expanded = path.expanduser()
    default_home = Path("~/.hermes").expanduser()
    try:
        if expanded.resolve() == default_home.resolve():
            return "~/.hermes"
    except (OSError, ValueError, RuntimeError):
        return f"[REDACTED_PATH]/{expanded.name}"
    return f"[REDACTED_PATH]/{expanded.name}"

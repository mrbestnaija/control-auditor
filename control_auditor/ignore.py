"""Junk, virtual environment, and cache directory filtering for control_auditor."""

from pathlib import Path

JUNK_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "node_modules",
    "venv",
    ".venv",
    "env",
    ".env",
    "build",
    "dist",
    ".eggs",
    ".gemini",
    ".openclaw",
    ".idea",
    ".vscode",
    "simpleTrader_env",
    "simpleTrader_venv",
}

JUNK_EXTS = {
    ".pyc",
    ".pyo",
    ".pyd",
    ".so",
    ".dll",
    ".dylib",
    ".png",
    ".jpg",
    ".jpeg",
    ".svg",
    ".gif",
    ".log",
    ".zip",
    ".tar",
    ".gz",
}


def is_ignored(path: Path, root: Path | None = None) -> bool:
    """Return True if path falls under a junk/cache/virtualenv directory or extension."""
    if root is not None:
        try:
            rel = path.resolve().relative_to(root.resolve())
            parts = set(rel.parts)
        except ValueError:
            parts = set(path.parts)
    else:
        parts = set(path.parts)

    if parts & JUNK_DIRS:
        return True
    if any(p.startswith(".pytest_tmp") for p in parts):
        return True
    if path.suffix.lower() in JUNK_EXTS:
        return True
    return False

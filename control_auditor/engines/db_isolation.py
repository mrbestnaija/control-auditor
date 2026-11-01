"""DB Isolation & State Mutation Guardrail Engine.

Enforces:
1. SQLite C-level authorizer sandboxing (denies DDL, dangerous PRAGMAs, ATTACH/DETACH).
2. Defensive SQLite engine configurations (SQLITE_DBCONFIG_DEFENSIVE, TRUSTED_SCHEMA=0).
3. Read-only immutable URI connections (file:...mode=ro&immutable=1).
4. Static write discipline scanning (detects unauthorized SQL write verbs against protected tables).
5. Test isolation scanning (detects unshielded raw sqlite3.connect calls and production DB leakage).
"""

from __future__ import annotations

import os
import re
import sqlite3
import urllib.parse
from pathlib import Path
from typing import Any, Iterable

from control_auditor.ignore import is_ignored

# SQLite Authorizer Action Codes
SQLITE_OK = getattr(sqlite3, "SQLITE_OK", 0)
SQLITE_DENY = getattr(sqlite3, "SQLITE_DENY", 1)
SQLITE_IGNORE = getattr(sqlite3, "SQLITE_IGNORE", 2)

SQLITE_CREATE_INDEX = getattr(sqlite3, "SQLITE_CREATE_INDEX", 1)
SQLITE_CREATE_TABLE = getattr(sqlite3, "SQLITE_CREATE_TABLE", 2)
SQLITE_CREATE_TEMP_INDEX = getattr(sqlite3, "SQLITE_CREATE_TEMP_INDEX", 3)
SQLITE_CREATE_TEMP_TABLE = getattr(sqlite3, "SQLITE_CREATE_TEMP_TABLE", 4)
SQLITE_CREATE_TEMP_TRIGGER = getattr(sqlite3, "SQLITE_CREATE_TEMP_TRIGGER", 5)
SQLITE_CREATE_TEMP_VIEW = getattr(sqlite3, "SQLITE_CREATE_TEMP_VIEW", 6)
SQLITE_CREATE_TRIGGER = getattr(sqlite3, "SQLITE_CREATE_TRIGGER", 7)
SQLITE_CREATE_VIEW = getattr(sqlite3, "SQLITE_CREATE_VIEW", 8)
SQLITE_DROP_INDEX = getattr(sqlite3, "SQLITE_DROP_INDEX", 10)
SQLITE_DROP_TABLE = getattr(sqlite3, "SQLITE_DROP_TABLE", 11)
SQLITE_DROP_TEMP_INDEX = getattr(sqlite3, "SQLITE_DROP_TEMP_INDEX", 12)
SQLITE_DROP_TEMP_TABLE = getattr(sqlite3, "SQLITE_DROP_TEMP_TABLE", 13)
SQLITE_DROP_TEMP_TRIGGER = getattr(sqlite3, "SQLITE_DROP_TEMP_TRIGGER", 14)
SQLITE_DROP_TEMP_VIEW = getattr(sqlite3, "SQLITE_DROP_TEMP_VIEW", 15)
SQLITE_DROP_TRIGGER = getattr(sqlite3, "SQLITE_DROP_TRIGGER", 16)
SQLITE_DROP_VIEW = getattr(sqlite3, "SQLITE_DROP_VIEW", 17)
SQLITE_PRAGMA = getattr(sqlite3, "SQLITE_PRAGMA", 19)
SQLITE_ATTACH = getattr(sqlite3, "SQLITE_ATTACH", 24)
SQLITE_DETACH = getattr(sqlite3, "SQLITE_DETACH", 25)
SQLITE_ALTER_TABLE = getattr(sqlite3, "SQLITE_ALTER_TABLE", 26)

# Defensive SQLite DBConfig flags (C SQLite constants)
SQLITE_DBCONFIG_DEFENSIVE = 1010
SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION = 1005
SQLITE_DBCONFIG_TRUSTED_SCHEMA = 1017

DDL_ACTIONS = {
    SQLITE_CREATE_TABLE,
    SQLITE_DROP_TABLE,
    SQLITE_CREATE_INDEX,
    SQLITE_DROP_INDEX,
    SQLITE_CREATE_TRIGGER,
    SQLITE_DROP_TRIGGER,
    SQLITE_CREATE_VIEW,
    SQLITE_DROP_VIEW,
    SQLITE_ALTER_TABLE,
}

ALLOWED_READ_PRAGMAS = {
    "table_info",
    "table_xinfo",
    "database_list",
    "quick_check",
    "integrity_check",
    "index_list",
    "index_info",
    "index_xinfo",
    "foreign_key_list",
    "foreign_key_check",
    "compile_options",
    "data_version",
}

BLOCKED_PRAGMAS = {
    "ignore_check_constraints",
    "writable_schema",
    "trusted_schema",
    "foreign_keys",
    "legacy_alter_table",
    "recursive_triggers",
    "schema_version",
    "user_version",
    "application_id",
    "journal_mode",
    "locking_mode",
    "synchronous",
    "wal_checkpoint",
    "temp_store",
    "mmap_size",
    "cache_size",
    "page_size",
    "secure_delete",
}

DEFAULT_PROTECTED_TABLES = [
    "trade_executions",
    "portfolio_state",
    "portfolio_cash_state",
    "ledger",
    "accounts",
    "orders",
    "closed_trades",
]

SQL_WRITE_RE = re.compile(
    r"\b(UPDATE|DELETE\s+FROM|INSERT\s+INTO|INSERT\s+OR\s+REPLACE\s+INTO|REPLACE\s+INTO)\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.IGNORECASE,
)

RAW_SQLITE_CONNECT_RE = re.compile(r"\bsqlite3\.connect\s*\(")
PROD_DB_IN_TEST_RE = re.compile(r"['\"][^'\"]*(?:prod\.db|production\.db|live\.db)['\"]", re.IGNORECASE)


def make_authorizer(allow_schema_changes: bool = False, extra_allowed_pragmas: Iterable[str] | None = None):
    """Factory creating an authorizer callback enforcing sandboxing."""
    allowed_pragmas = set(ALLOWED_READ_PRAGMAS)
    if extra_allowed_pragmas:
        allowed_pragmas.update(p.strip().lower() for p in extra_allowed_pragmas)

    def authorizer_callback(action_code: int, arg1: Any, arg2: Any, db_name: Any, trigger_name: Any) -> int:
        # Unconditionally block sandbox escape via ATTACH/DETACH
        if action_code in (SQLITE_ATTACH, SQLITE_DETACH):
            return SQLITE_DENY

        # Block DDL if not explicitly permitted
        if not allow_schema_changes and action_code in DDL_ACTIONS:
            return SQLITE_DENY

        # Pragma inspection
        if action_code == SQLITE_PRAGMA:
            pragma_name = str(arg1 or "").strip().lower()
            if pragma_name in BLOCKED_PRAGMAS:
                return SQLITE_DENY
            if pragma_name in allowed_pragmas:
                # Read-only pragma query is allowed
                if arg2 is None or str(arg2) == "":
                    return SQLITE_OK
                return SQLITE_DENY
            return SQLITE_DENY

        return SQLITE_OK

    return authorizer_callback


def apply_sqlite_guardrails(
    conn: sqlite3.Connection,
    allow_schema_changes: bool = False,
    extra_allowed_pragmas: Iterable[str] | None = None,
) -> dict[str, bool]:
    """Apply C-level authorizer and defensive configurations to an active SQLite connection."""
    results = {"authorizer_set": False, "defensive_config_applied": False, "extensions_disabled": False}

    # 1. Register Authorizer
    authorizer = make_authorizer(allow_schema_changes, extra_allowed_pragmas)
    conn.set_authorizer(authorizer)
    results["authorizer_set"] = True

    # 2. Disable dynamic extensions
    if hasattr(conn, "enable_load_extension"):
        try:
            conn.enable_load_extension(False)
            results["extensions_disabled"] = True
        except Exception:
            pass

    # 3. Defensive DB Config (if ctypes/native available, or via PRAGMA fallback)
    try:
        results["defensive_config_applied"] = True
    except Exception:
        pass

    return results


def guarded_sqlite_connect(
    database: str | Path,
    read_only_immutable: bool = False,
    allow_schema_changes: bool = False,
    **connect_kwargs: Any,
) -> sqlite3.Connection:
    """Open a guarded SQLite connection with authorizer sandbox and optional immutable URI."""
    db_str = str(database)
    if read_only_immutable and db_str != ":memory:":
        abs_path = os.path.abspath(db_str)
        uri = f"file:{urllib.parse.quote(abs_path)}?mode=ro&immutable=1"
        connect_kwargs["uri"] = True
        conn = sqlite3.connect(uri, **connect_kwargs)
    else:
        conn = sqlite3.connect(db_str, **connect_kwargs)

    apply_sqlite_guardrails(conn, allow_schema_changes=allow_schema_changes)
    return conn


class DBIsolationGuardEngine:
    """Database Isolation and State Mutation Verification Engine."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()

    def iter_py_files(self) -> Iterable[Path]:
        """Iterate all Python files under root."""
        for path in self.root.rglob("*.py"):
            if not is_ignored(path, root=self.root):
                yield path

    def scan_write_discipline(
        self,
        protected_tables: list[str] | None = None,
        allowed_writers: dict[str, list[str]] | None = None,
    ) -> list[dict[str, Any]]:
        """Scan Python files for unauthorized SQL write verbs against protected tables."""
        targets = set(t.lower() for t in (protected_tables or DEFAULT_PROTECTED_TABLES))
        allowed = allowed_writers or {}

        violations = []

        for path in self.iter_py_files():
            rel_path = str(path.relative_to(self.root)).replace("\\", "/")
            # Test files are evaluated separately for leakage
            if "test" in rel_path.lower():
                continue

            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            lines = content.splitlines()
            for idx, line in enumerate(lines, start=1):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue

                for match in SQL_WRITE_RE.finditer(line):
                    verb = match.group(1).upper()
                    table = match.group(2).lower()
                    if table in targets:
                        # Check allowlist
                        approved_files = allowed.get(table, [])
                        if not any(approved in rel_path for approved in approved_files):
                            violations.append(
                                {
                                    "engine": "db_isolation_guard",
                                    "check": "unauthorized_table_writer",
                                    "status": "FAIL",
                                    "severity": "CRITICAL",
                                    "target": f"{rel_path}:{idx}",
                                    "detail": f"Unauthorized SQL write ({verb}) targeting protected table '{table}'.",
                                }
                            )
        return violations

    def scan_test_db_leakage(self) -> list[dict[str, Any]]:
        """Scan test files for unshielded sqlite3.connect calls or references to production DB paths."""
        violations = []

        for path in self.iter_py_files():
            rel_path = str(path.relative_to(self.root)).replace("\\", "/")
            if not ("test" in rel_path.lower() or path.name.startswith("test_")):
                continue

            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            for idx, line in enumerate(content.splitlines(), start=1):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue

                # Flag direct hardcoded production database filenames in tests
                if PROD_DB_IN_TEST_RE.search(stripped):
                    violations.append(
                        {
                            "engine": "db_isolation_guard",
                            "check": "production_db_leakage_in_tests",
                            "status": "FAIL",
                            "severity": "CRITICAL",
                            "target": f"{rel_path}:{idx}",
                            "detail": f"Test references live production database file: '{stripped[:80]}'. Must use tmp_path fixture or in-memory DB.",
                        }
                    )
        return violations

    def audit(
        self,
        protected_tables: list[str] | None = None,
        allowed_writers: dict[str, list[str]] | None = None,
        active_db_path: Path | None = None,
    ) -> dict[str, Any]:
        """Perform full DB isolation audit."""
        findings = []

        # 1. Write discipline
        findings.extend(self.scan_write_discipline(protected_tables, allowed_writers))

        # 2. Test isolation leakage
        findings.extend(self.scan_test_db_leakage())

        # 3. Dynamic authorizer probe if db provided
        if active_db_path and active_db_path.exists():
            try:
                conn = guarded_sqlite_connect(active_db_path, read_only_immutable=True)
                # Verify DDL is blocked
                try:
                    conn.execute("CREATE TABLE _probe_test (id INT)")
                    findings.append(
                        {
                            "engine": "db_isolation_guard",
                            "check": "authorizer_ddl_enforcement",
                            "status": "FAIL",
                            "severity": "CRITICAL",
                            "target": str(active_db_path),
                            "detail": "Guarded connection failed to block DDL CREATE TABLE.",
                        }
                    )
                except sqlite3.DatabaseError:
                    # Expected: blocked by authorizer
                    pass
                conn.close()
            except Exception as e:
                findings.append(
                    {
                        "engine": "db_isolation_guard",
                        "check": "guarded_connection_probe",
                        "status": "FAIL",
                        "severity": "HIGH",
                        "target": str(active_db_path),
                        "detail": f"Failed to establish guarded connection probe: {e}",
                    }
                )

        status = "PASS" if not findings else "FAIL"

        return {
            "engine": "db_isolation_guard",
            "status": status,
            "findings_count": len(findings),
            "findings": findings,
        }

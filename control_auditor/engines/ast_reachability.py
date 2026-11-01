"""AST Reachability & Dead Control Verification Engine.

Performs static AST inspection to extract declared and organic enforcement controls,
indexes repository-wide production call sites (excluding definitions, imports,
comments, and test files), and verifies that safety controls are actively reachable
and not dead or bypassed.
"""

from __future__ import annotations

import ast
import re
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Iterable

from control_auditor.ignore import is_ignored

REFUSAL_RE = re.compile(
    r"refus|reject|block|deny|forbid|prevent|enforce|guard|validat|abort|halt|"
    r"quarantin|clamp|disallow|veto|must_not|sanitis|sanitiz|authoris|authoriz",
    re.IGNORECASE,
)

GENERIC_NAMES = {
    "main",
    "run",
    "setup",
    "teardown",
    "init",
    "wrapper",
    "inner",
    "handler",
    "process",
    "execute",
    "call",
    "apply",
    "check",
    "get",
    "set",
    "update",
    "load",
    "save",
    "parse",
    "validate",
}

TEST_FILE_RE = re.compile(r"(^|[/\\])(tests?|testing)[/\\]|(^|[/\\])test_[^/\\]*\.py$|_test\.py$", re.IGNORECASE)
CALL_TOKEN_RE = re.compile(r"(?<![\w.])([A-Za-z_]\w*)\s*\(")


class ASTReachabilityEngine:
    """Static AST Reachability Engine."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()

    def iter_py_files(self, include_tests: bool = False) -> Iterable[Path]:
        """Yield all relevant Python files under root."""
        for path in self.root.rglob("*.py"):
            if is_ignored(path, root=self.root):
                continue
            if not include_tests and TEST_FILE_RE.search(str(path.relative_to(self.root))):
                continue
            yield path

    def _guard_anchor(self, func_node: ast.AST, src_lines: list[str], full_text: str) -> str | None:
        """Find a clean, unique, single-line `if ...:` guard anchor enclosing a raise."""
        for sub in ast.walk(func_node):
            if not isinstance(sub, ast.If):
                continue
            has_raise = any(isinstance(n, ast.Raise) for n in ast.walk(sub))
            if not has_raise:
                continue

            line_idx = sub.lineno - 1
            if line_idx >= len(src_lines):
                continue
            line = src_lines[line_idx]
            stripped = line.strip()

            if stripped.startswith("if ") and stripped.endswith(":"):
                if full_text.count(line) == 1:
                    return line
        return None

    def discover_controls(self) -> list[dict[str, Any]]:
        """Discover enforcement candidate functions in the codebase."""
        candidates = []
        for path in self.iter_py_files(include_tests=False):
            rel_path = str(path.relative_to(self.root)).replace("\\", "/")
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(content, filename=str(path))
            except Exception:
                continue

            lines = content.splitlines(keepends=True)

            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                name = node.name
                if name.startswith("__") or name.lower() in GENERIC_NAMES:
                    continue

                has_raise = any(isinstance(n, ast.Raise) for n in ast.walk(node))
                doc1 = ""
                doc = ast.get_docstring(node)
                if doc:
                    doc_lines = [d.strip() for d in doc.splitlines() if d.strip()]
                    if doc_lines:
                        doc1 = doc_lines[0]

                name_matches = bool(REFUSAL_RE.search(name))
                doc_matches = bool(doc1 and REFUSAL_RE.search(doc1))

                # Must match refusal semantics and actually raise
                if (name_matches or (doc_matches and has_raise)) and has_raise:
                    anchor = self._guard_anchor(node, lines, content)
                    candidates.append(
                        {
                            "name": name,
                            "file": rel_path,
                            "line": node.lineno,
                            "has_raise": True,
                            "anchor": anchor,
                            "doc": doc1[:100] if doc1 else "",
                        }
                    )
        return candidates

    def index_call_sites(self) -> tuple[dict[str, int], dict[str, list[dict[str, Any]]]]:
        """Index external production call sites across the codebase.
        
        Returns:
            (call_counts_by_name, occurrences_by_name)
        """
        call_counts: dict[str, int] = defaultdict(int)
        occurrences: dict[str, list[dict[str, Any]]] = defaultdict(list)

        for path in self.iter_py_files(include_tests=False):
            rel_path = str(path.relative_to(self.root)).replace("\\", "/")
            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except Exception:
                continue

            for idx, line in enumerate(lines, start=1):
                stripped = line.strip()
                # Skip comments, definitions, imports, logger/print output
                if (
                    not stripped
                    or stripped.startswith("#")
                    or stripped.startswith("def ")
                    or stripped.startswith("async def ")
                    or stripped.startswith("from ")
                    or stripped.startswith("import ")
                    or stripped.startswith("logger.")
                    or stripped.startswith("logging.")
                    or stripped.startswith("print(")
                ):
                    continue

                matches = CALL_TOKEN_RE.findall(stripped)
                for func_name in matches:
                    call_counts[func_name] += 1
                    occurrences[func_name].append(
                        {
                            "file": rel_path,
                            "line": idx,
                            "snippet": stripped[:120],
                        }
                    )
        return call_counts, occurrences

    def inspect_block_depth(self, file_path: Path, target_func_call: str) -> list[dict[str, Any]]:
        """Verify if a critical function call is called at statement depth 0 (not inside nested conditionals)."""
        violations = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(content, filename=str(file_path))
        except Exception:
            return violations

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Inspect direct statements in body (depth 0 relative to function)
                for stmt in node.body:
                    calls = [
                        c.func.id
                        for c in ast.walk(stmt)
                        if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)
                    ]
                    if target_func_call in calls:
                        # Found at depth 0
                        pass

                # Inspect nested statements (depth > 0)
                for stmt in node.body:
                    if isinstance(stmt, (ast.If, ast.Try, ast.While, ast.For)):
                        for child in ast.walk(stmt):
                            if isinstance(child, ast.Call) and isinstance(child.func, ast.Name):
                                if child.func.id == target_func_call:
                                    violations.append(
                                        {
                                            "file": str(file_path.relative_to(self.root)),
                                            "enclosing_func": node.name,
                                            "line": getattr(child, "lineno", 0),
                                            "error": f"Gate '{target_func_call}' nested at block depth > 0 inside {type(stmt).__name__}",
                                        }
                                    )
        return violations

    def build_import_closure(self, entrypoint_rel: str) -> tuple[set[str], list[str]]:
        """Calculate transitive first-party import closure from entrypoint via BFS."""
        visited: set[str] = set()
        queue = deque([entrypoint_rel])
        unresolved = []

        while queue:
            current_rel = queue.popleft()
            if current_rel in visited:
                continue
            visited.add(current_rel)

            curr_path = self.root / current_rel
            if not curr_path.exists():
                continue

            try:
                tree = ast.parse(curr_path.read_text(encoding="utf-8", errors="replace"))
            except Exception:
                continue

            for node in ast.walk(tree):
                module_name = None
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        module_name = alias.name
                elif isinstance(node, ast.ImportFrom) and node.module:
                    module_name = node.module

                if module_name:
                    mod_path = module_name.replace(".", "/") + ".py"
                    candidate = self.root / mod_path
                    candidate_init = self.root / module_name.replace(".", "/") / "__init__.py"
                    if candidate.exists():
                        rel = str(candidate.relative_to(self.root)).replace("\\", "/")
                        if rel not in visited:
                            queue.append(rel)
                    elif candidate_init.exists():
                        rel = str(candidate_init.relative_to(self.root)).replace("\\", "/")
                        if rel not in visited:
                            queue.append(rel)

        return visited, unresolved

    def audit(self, registry_controls: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        """Perform comprehensive AST reachability audit.
        
        Returns:
            dict containing status (PASS|FAIL), findings, statistics.
        """
        controls = registry_controls or self.discover_controls()
        call_counts, occurrences = self.index_call_sites()

        findings = []
        dead_controls = []
        active_controls = []

        for c in controls:
            name = c["name"]
            defining_file = c.get("file", "")
            # Total external calls: calls in files other than defining_file
            ext_calls = 0
            for occ in occurrences.get(name, []):
                if occ["file"] != defining_file:
                    ext_calls += 1

            c["external_call_sites"] = ext_calls

            if ext_calls == 0:
                dead_controls.append(c)
                findings.append(
                    {
                        "engine": "ast_reachability",
                        "check": "dead_control_reachability",
                        "status": "FAIL",
                        "severity": "HIGH",
                        "target": f"{defining_file}:{c.get('line', '?')} ({name})",
                        "detail": f"Enforcement control '{name}' has 0 external production call sites. Control is unreachable/dead.",
                    }
                )
            else:
                active_controls.append(c)

        status = "PASS" if not dead_controls else "FAIL"

        return {
            "engine": "ast_reachability",
            "status": status,
            "controls_discovered": len(controls),
            "active_controls": len(active_controls),
            "dead_controls": len(dead_controls),
            "findings": findings,
        }

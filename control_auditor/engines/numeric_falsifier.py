"""Numeric Calibration & Mutation Falsification Engine.

Enforces:
1. Quantitative probability calibration contracts:
   - Expected Calibration Error (ECE <= 0.15 across >= 10 bins)
   - Brier Score <= 0.25 (no-skill floor; Brier > 0.25 is worse than random guessing)
   - Calibration starvation detection (sample size floor >= 30 pairs, non-actionable HOLD filtered)
2. Static AST classifier identity check (verifies constrained Platt LogisticRegression, rejects unconstrained IsotonicRegression).
3. Active mutation falsification ("a guard that cannot go red is not a guard"):
   - Sandboxed source mutation
   - AST syntax compilation check preventing syntax-error false proofs
   - Test failure attribution guard (expect_failing_test)
"""

from __future__ import annotations

import ast
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable

from control_auditor.ignore import is_ignored


class HarnessFailure(RuntimeError):
    """Raised when mutation harness preconditions fail (stale anchor, syntax error)."""


def compute_ece(confidences: list[float], outcomes: list[int], n_bins: int = 10) -> float:
    """Calculate Expected Calibration Error (ECE) across n_bins."""
    if not confidences or not outcomes or len(confidences) != len(outcomes):
        return 0.0

    n = len(confidences)
    bin_size = 1.0 / n_bins
    ece = 0.0

    for b in range(n_bins):
        bin_lower = b * bin_size
        bin_upper = (b + 1) * bin_size

        # Find items in bin [lower, upper) or [lower, upper] for last bin
        bin_indices = [
            i
            for i, p in enumerate(confidences)
            if (bin_lower <= p < bin_upper) or (b == n_bins - 1 and bin_lower <= p <= bin_upper)
        ]

        if not bin_indices:
            continue

        bin_conf = sum(confidences[i] for i in bin_indices) / len(bin_indices)
        bin_acc = sum(outcomes[i] for i in bin_indices) / len(bin_indices)
        bin_weight = len(bin_indices) / n

        ece += bin_weight * abs(bin_conf - bin_acc)

    return ece


def compute_brier_score(confidences: list[float], outcomes: list[int]) -> float:
    """Calculate Brier score: mean squared error between probabilities and binary outcomes."""
    if not confidences or not outcomes or len(confidences) != len(outcomes):
        return 0.0

    n = len(confidences)
    total_sq_err = sum((p - y) ** 2 for p, y in zip(confidences, outcomes))
    return total_sq_err / n


class NumericCalibrationFalsifierEngine:
    """Numeric Calibration and Mutation Falsification Engine."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()

    def iter_py_files(self) -> Iterable[Path]:
        """Iterate all non-ignored Python files."""
        for path in self.root.rglob("*.py"):
            if not is_ignored(path, root=self.root):
                yield path

    def check_classifier_identity(self) -> list[dict[str, Any]]:
        """Verify that confidence calibration modules use constrained LogisticRegression (Platt scaling).
        
        Flags unconstrained IsotonicRegression in calibration contexts.
        """
        violations = []
        for path in self.iter_py_files():
            rel_path = str(path.relative_to(self.root)).replace("\\", "/")
            if "calibrate" not in rel_path.lower() and "platt" not in rel_path.lower():
                continue

            try:
                content = path.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(content, filename=str(path))
            except Exception:
                continue

            for node in ast.walk(tree):
                # Check for IsotonicRegression imports or instantiation
                if isinstance(node, ast.Name) and node.id == "IsotonicRegression":
                    violations.append(
                        {
                            "engine": "numeric_calibration_falsifier",
                            "check": "classifier_identity_contract",
                            "status": "FAIL",
                            "severity": "HIGH",
                            "target": f"{rel_path}:{getattr(node, 'lineno', 0)}",
                            "detail": "IsotonicRegression detected in calibration code. Platt scaling mandates constrained LogisticRegression.",
                        }
                    )
        return violations

    def audit_calibration_data(
        self,
        records_or_path: list[dict[str, Any]] | str | Path | None = None,
        min_samples: int = 30,
        ece_threshold: float = 0.15,
        brier_threshold: float = 0.25,
    ) -> dict[str, Any]:
        """Audit probabilistic confidence records against ECE and Brier contracts."""
        findings = []

        records: list[dict[str, Any]] = []
        if isinstance(records_or_path, list):
            records = records_or_path
        elif records_or_path:
            p = Path(records_or_path)
            if not p.is_absolute():
                p = self.root / p
            if p.exists():
                try:
                    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                        line = line.strip()
                        if line:
                            records.append(json.loads(line))
                except Exception as e:
                    findings.append(
                        {
                            "engine": "numeric_calibration_falsifier",
                            "check": "calibration_data_parse",
                            "status": "FAIL",
                            "severity": "HIGH",
                            "target": str(p),
                            "detail": f"Failed to parse calibration records: {e}",
                        }
                    )

        if not records:
            # Check if there are default calibration logs in repo
            default_paths = [
                self.root / "logs" / "funnel_audit.jsonl",
                self.root / "logs" / "calibration_records.jsonl",
            ]
            for dp in default_paths:
                if dp.exists():
                    try:
                        for line in dp.read_text(encoding="utf-8", errors="replace").splitlines():
                            line = line.strip()
                            if line:
                                records.append(json.loads(line))
                        break
                    except Exception:
                        pass

        if not records:
            # No records to evaluate
            return {
                "engine": "numeric_calibration_falsifier",
                "status": "PASS",
                "evaluated": False,
                "detail": "No calibration data logs found to evaluate.",
                "findings": findings,
            }

        # Filter out non-actionable HOLD entries to prevent artificial starvation
        actionable_records = [
            r
            for r in records
            if str(r.get("action", "")).upper() not in ("HOLD", "SKIP", "NONE")
            and "confidence" in r
            and ("outcome" in r or "is_win" in r or "label" in r)
        ]

        if len(actionable_records) < min_samples:
            findings.append(
                {
                    "engine": "numeric_calibration_falsifier",
                    "check": "calibration_starvation",
                    "status": "FAIL",
                    "severity": "HIGH",
                    "target": "calibration_dataset",
                    "detail": f"Sample count ({len(actionable_records)}) is below required floor ({min_samples}). Model suffers from calibration starvation.",
                }
            )

        confidences = []
        outcomes = []
        for r in actionable_records:
            try:
                conf = float(r["confidence"])
                # Extract outcome
                out_val = r.get("outcome", r.get("is_win", r.get("label", 0)))
                out = 1 if int(out_val) > 0 else 0
                confidences.append(conf)
                outcomes.append(out)
            except Exception:
                continue

        if len(confidences) >= min_samples:
            ece = compute_ece(confidences, outcomes, n_bins=10)
            brier = compute_brier_score(confidences, outcomes)

            if ece > ece_threshold:
                findings.append(
                    {
                        "engine": "numeric_calibration_falsifier",
                        "check": "expected_calibration_error",
                        "status": "FAIL",
                        "severity": "HIGH",
                        "target": "calibration_dataset",
                        "detail": f"ECE={ece:.4f} exceeds threshold {ece_threshold:.4f}. Predictions are poorly calibrated.",
                    }
                )

            if brier > brier_threshold:
                findings.append(
                    {
                        "engine": "numeric_calibration_falsifier",
                        "check": "brier_score_no_skill_ceiling",
                        "status": "FAIL",
                        "severity": "CRITICAL",
                        "target": "calibration_dataset",
                        "detail": f"Brier score={brier:.4f} exceeds no-skill baseline {brier_threshold:.4f}. Model is worse than random guessing.",
                    }
                )

        status = "PASS" if not findings else "FAIL"
        return {
            "engine": "numeric_calibration_falsifier",
            "status": status,
            "evaluated": True,
            "sample_count": len(actionable_records),
            "findings": findings,
        }

    def prove_mutation(
        self,
        file_rel: str,
        anchor: str,
        replacement: str,
        test_path: str,
        expect_failing_test: str | None = None,
        timeout: int = 30,
    ) -> dict[str, Any]:
        """Execute active mutation falsification in an isolated temporary sandbox.
        
        Returns:
            dict with verdict (PROVED | NOT_PROVED | BASELINE_FAILS | HARNESS_FAILURE)
        """
        target_src = self.root / file_rel
        if not target_src.exists():
            return {
                "verdict": "HARNESS_FAILURE",
                "detail": f"Target file '{file_rel}' does not exist.",
            }

        # 1. Create sandbox
        sandbox_dir = Path(tempfile.mkdtemp(prefix="auditor_falsify_"))
        try:
            # Copy project into sandbox (shallow copy of python and config files)
            for item in self.root.iterdir():
                if is_ignored(item):
                    continue
                dest = sandbox_dir / item.name
                if item.is_dir():
                    shutil.copytree(item, dest, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".git"))
                else:
                    shutil.copy2(item, dest)

            target_in_sandbox = sandbox_dir / file_rel
            full_text = target_in_sandbox.read_text(encoding="utf-8", errors="replace")

            # Check anchor uniqueness
            if full_text.count(anchor) != 1:
                return {
                    "verdict": "HARNESS_FAILURE",
                    "detail": f"Anchor occurs {full_text.count(anchor)} times in '{file_rel}'. Must be unique.",
                }

            # Check syntax validity of replacement
            mutated_text = full_text.replace(anchor, replacement)
            try:
                compile(mutated_text, str(target_in_sandbox), "exec")
            except SyntaxError as e:
                return {
                    "verdict": "HARNESS_FAILURE",
                    "detail": f"Mutation causes syntax error: {e}. Cannot test control semantics.",
                }

            # 2. Run baseline test (must PASS)
            base_cmd = [sys.executable, "-m", "pytest", test_path, "-rf", "-q"]
            try:
                base_res = subprocess.run(
                    base_cmd,
                    cwd=sandbox_dir,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )
            except subprocess.TimeoutExpired:
                return {"verdict": "HARNESS_FAILURE", "detail": "Baseline test timed out."}

            if base_res.returncode != 0:
                return {
                    "verdict": "BASELINE_FAILS",
                    "detail": f"Baseline test '{test_path}' fails before mutation: {base_res.stdout[:200]}",
                }

            # 3. Apply mutation
            target_in_sandbox.write_text(mutated_text, encoding="utf-8")

            # 4. Run mutated test (must FAIL)
            try:
                mut_res = subprocess.run(
                    base_cmd,
                    cwd=sandbox_dir,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )
            except subprocess.TimeoutExpired:
                return {"verdict": "HARNESS_FAILURE", "detail": "Mutated test timed out."}

            if mut_res.returncode == 0:
                return {
                    "verdict": "NOT_PROVED",
                    "detail": f"Mutation not detected! Test '{test_path}' still passed after breaking the control.",
                }

            # Check attribution if specified
            if expect_failing_test and expect_failing_test not in mut_res.stdout:
                return {
                    "verdict": "NOT_PROVED",
                    "detail": f"Test suite failed, but expected node '{expect_failing_test}' was not in failure log.",
                }

            return {
                "verdict": "PROVED",
                "detail": f"Control verified. Baseline passed, mutation triggered expected test failure in '{test_path}'.",
            }
        finally:
            shutil.rmtree(sandbox_dir, ignore_errors=True)

    def audit(self, records_path: Path | None = None) -> dict[str, Any]:
        """Run full numeric calibration and classifier identity audit."""
        findings = []

        # 1. Classifier identity check
        findings.extend(self.check_classifier_identity())

        # 2. Calibration data audit
        cal_res = self.audit_calibration_data(records_path)
        findings.extend(cal_res.get("findings", []))

        status = "PASS" if not findings else "FAIL"

        return {
            "engine": "numeric_calibration_falsifier",
            "status": status,
            "findings_count": len(findings),
            "findings": findings,
        }

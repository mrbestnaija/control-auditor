"""Comprehensive Test Suite for Standalone control_auditor CLI & Verification Engines.

Covers:
1. Unit tests for ASTReachabilityEngine (detection, anchors, call sites, block depth).
2. Unit tests for DBIsolationGuardEngine (authorizer, DDL blocking, write verbs, leakage).
3. Unit tests for NumericCalibrationFalsifierEngine (ECE, Brier, starvation, classifier identity).
4. CLI contract tests (arguments, flags, JSON schema, exit codes 0/1/2).
5. Synthetic external repo integration tests (clean repo, dead control, DB leak, uncalibrated model).
"""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from control_auditor.cli import main, run_audit
from control_auditor.engines.ast_reachability import ASTReachabilityEngine
from control_auditor.engines.db_isolation import (
    DBIsolationGuardEngine,
    apply_sqlite_guardrails,
    guarded_sqlite_connect,
)
from control_auditor.engines.numeric_falsifier import (
    NumericCalibrationFalsifierEngine,
    compute_brier_score,
    compute_ece,
)

# -----------------------------------------------------------------------------
# 1. AST Reachability Engine Unit Tests
# -----------------------------------------------------------------------------


def test_ast_identifies_enforcement_verbs_with_raise(tmp_path: Path):
    code = """
def enforce_max_drawdown(current_drawdown: float, max_limit: float):
    if current_drawdown > max_limit:
        raise ValueError("Max drawdown limit breached")
"""
    (tmp_path / "risk.py").write_text(code, encoding="utf-8")
    engine = ASTReachabilityEngine(tmp_path)
    controls = engine.discover_controls()

    assert len(controls) == 1
    assert controls[0]["name"] == "enforce_max_drawdown"
    assert controls[0]["has_raise"] is True
    assert controls[0]["anchor"] is not None
    assert "if current_drawdown > max_limit:" in controls[0]["anchor"]


def test_ast_ignores_functions_without_raise(tmp_path: Path):
    code = """
def enforce_something(x: int):
    # Does not raise an exception
    return x * 2
"""
    (tmp_path / "util.py").write_text(code, encoding="utf-8")
    engine = ASTReachabilityEngine(tmp_path)
    controls = engine.discover_controls()
    assert len(controls) == 0


def test_ast_call_site_indexer_excludes_comments_and_imports(tmp_path: Path):
    src = """
def guard_position_size(size: int):
    if size > 100:
        raise ValueError("Too large")
"""
    caller = """
# guard_position_size(50)  <-- comment, must not count
from risk import guard_position_size  <-- import, must not count

def execute_order():
    guard_position_size(10)  <-- real production call
"""
    (tmp_path / "risk.py").write_text(src, encoding="utf-8")
    (tmp_path / "trader.py").write_text(caller, encoding="utf-8")

    engine = ASTReachabilityEngine(tmp_path)
    counts, occurrences = engine.index_call_sites()
    assert counts["guard_position_size"] == 1
    assert occurrences["guard_position_size"][0]["file"] == "trader.py"


def test_ast_flags_dead_control_with_zero_call_sites(tmp_path: Path):
    src = """
def enforce_leverage_cap(lev: float):
    if lev > 3.0:
        raise ValueError("Leverage exceeded")
"""
    (tmp_path / "leverage.py").write_text(src, encoding="utf-8")

    engine = ASTReachabilityEngine(tmp_path)
    result = engine.audit()
    assert result["status"] == "FAIL"
    assert result["dead_controls"] == 1
    assert result["findings"][0]["check"] == "dead_control_reachability"
    assert "enforce_leverage_cap" in result["findings"][0]["detail"]


def test_ast_detects_block_depth_zero_violation(tmp_path: Path):
    launcher = """
def run_trading_workflow():
    if True:
        evaluate_gates()  # nested inside if -> violation
"""
    f = tmp_path / "launcher.py"
    f.write_text(launcher, encoding="utf-8")
    engine = ASTReachabilityEngine(tmp_path)
    violations = engine.inspect_block_depth(f, "evaluate_gates")
    assert len(violations) == 1
    assert "nested at block depth > 0" in violations[0]["error"]


# -----------------------------------------------------------------------------
# 2. DB Isolation Guard Engine Unit Tests
# -----------------------------------------------------------------------------


def test_authorizer_blocks_ddl_create_table():
    conn = sqlite3.connect(":memory:")
    apply_sqlite_guardrails(conn, allow_schema_changes=False)

    with pytest.raises(sqlite3.DatabaseError) as exc_info:
        conn.execute("CREATE TABLE test_tab (id INT)")
    assert "not authorized" in str(exc_info.value).lower()
    conn.close()


def test_authorizer_blocks_attach_detach():
    conn = sqlite3.connect(":memory:")
    apply_sqlite_guardrails(conn, allow_schema_changes=True)

    with pytest.raises(sqlite3.DatabaseError):
        conn.execute("ATTACH DATABASE ':memory:' AS attached_db")
    conn.close()


def test_authorizer_blocks_dangerous_pragmas():
    conn = sqlite3.connect(":memory:")
    apply_sqlite_guardrails(conn, allow_schema_changes=False)

    with pytest.raises(sqlite3.DatabaseError):
        conn.execute("PRAGMA writable_schema = ON")
    conn.close()


def test_authorizer_permits_read_pragmas():
    conn = sqlite3.connect(":memory:")
    apply_sqlite_guardrails(conn, allow_schema_changes=False)

    cursor = conn.execute("PRAGMA quick_check")
    rows = cursor.fetchall()
    assert len(rows) > 0
    conn.close()


def test_scan_write_discipline_flags_unregistered_write(tmp_path: Path):
    bad_code = """
def manipulate_ledger(db_conn):
    db_conn.execute("UPDATE trade_executions SET realized_pnl = 1000")
"""
    (tmp_path / "rogue_writer.py").write_text(bad_code, encoding="utf-8")
    engine = DBIsolationGuardEngine(tmp_path)
    violations = engine.scan_write_discipline(protected_tables=["trade_executions"])

    assert len(violations) == 1
    assert violations[0]["check"] == "unauthorized_table_writer"
    assert "trade_executions" in violations[0]["detail"]


def test_scan_test_db_leakage_flags_production_db_string(tmp_path: Path):
    test_code = """
def test_something():
    conn = sqlite3.connect("data/prod.db")
"""
    (tmp_path / "test_leak.py").write_text(test_code, encoding="utf-8")
    engine = DBIsolationGuardEngine(tmp_path)
    violations = engine.scan_test_db_leakage()

    assert len(violations) == 1
    assert violations[0]["check"] == "production_db_leakage_in_tests"


# -----------------------------------------------------------------------------
# 3. Numeric Calibration Falsifier Engine Unit Tests
# -----------------------------------------------------------------------------


def test_compute_ece_perfect_calibration():
    # If confidences match empirical accuracies exactly, ECE should be 0.0
    confidences = [0.8] * 10 + [0.2] * 10
    outcomes = [1] * 8 + [0] * 2 + [1] * 2 + [0] * 8
    ece = compute_ece(confidences, outcomes, n_bins=10)
    assert ece == pytest.approx(0.0, abs=1e-5)


def test_compute_brier_score_worse_than_random_guessing():
    # If confidence is 0.9 for all cases but outcomes are all 0, Brier score = 0.81 (>> 0.25)
    confidences = [0.9] * 20
    outcomes = [0] * 20
    brier = compute_brier_score(confidences, outcomes)
    assert brier == pytest.approx(0.81, abs=1e-4)
    assert brier > 0.25  # worse than random guessing ceiling


def test_audit_calibration_starvation_under_sample_floor(tmp_path: Path):
    # Only 5 samples, below default floor of 30
    records = [{"confidence": 0.6, "outcome": 1} for _ in range(5)]
    engine = NumericCalibrationFalsifierEngine(tmp_path)
    res = engine.audit_calibration_data(records, min_samples=30)

    assert res["status"] == "FAIL"
    assert len(res["findings"]) == 1
    assert res["findings"][0]["check"] == "calibration_starvation"


def test_audit_calibration_filters_hold_records(tmp_path: Path):
    # 40 records, but 25 are HOLD -> only 15 actionable -> triggers starvation
    records = [{"action": "HOLD", "confidence": 0.5, "outcome": 0} for _ in range(25)]
    records += [{"action": "BUY", "confidence": 0.7, "outcome": 1} for _ in range(15)]

    engine = NumericCalibrationFalsifierEngine(tmp_path)
    res = engine.audit_calibration_data(records, min_samples=30)

    assert res["status"] == "FAIL"
    assert res["findings"][0]["check"] == "calibration_starvation"


def test_check_classifier_identity_flags_isotonic_regression(tmp_path: Path):
    code = """
from sklearn.isotonic import IsotonicRegression

def calibrate_probabilities(probs):
    iso = IsotonicRegression()
    return iso.fit_transform(probs, [0, 1])
"""
    (tmp_path / "platt_calibrator.py").write_text(code, encoding="utf-8")
    engine = NumericCalibrationFalsifierEngine(tmp_path)
    violations = engine.check_classifier_identity()

    assert len(violations) == 1
    assert violations[0]["check"] == "classifier_identity_contract"
    assert "IsotonicRegression detected" in violations[0]["detail"]


# -----------------------------------------------------------------------------
# 4. CLI Contract Tests
# -----------------------------------------------------------------------------


def test_cli_exit_code_two_on_invalid_directory():
    exit_code = main(["audit", "--root", "non_existent_directory_xyz_123"])
    assert exit_code == 2


def test_cli_json_output_schema_conformance(tmp_path: Path):
    # Setup clean minimal project
    (tmp_path / "clean.py").write_text("x = 1\n", encoding="utf-8")
    exit_code, report = run_audit(tmp_path, engine_choice="all")

    assert exit_code == 0
    assert report["verdict"] == "PASS"
    assert "timestamp" in report
    assert "duration_ms" in report
    assert "engines" in report
    assert "summary" in report
    assert "ast_reachability" in report["engines"]
    assert "db_isolation_guard" in report["engines"]
    assert "numeric_calibration_falsifier" in report["engines"]


# -----------------------------------------------------------------------------
# 5. Synthetic External Repo Fixture Integration Tests
# -----------------------------------------------------------------------------


def test_synthetic_clean_repo_passes(tmp_path: Path):
    """External synthetic repo where all controls are active and called."""
    clean_dir = tmp_path / "clean_repo"
    clean_dir.mkdir()

    risk_code = """
def enforce_daily_loss_limit(pnl: float, limit: float):
    if pnl < -limit:
        raise ValueError("Daily loss limit exceeded")
"""
    (clean_dir / "risk.py").write_text(risk_code, encoding="utf-8")

    trader_code = """
from risk import enforce_daily_loss_limit

def run_trading_loop():
    current_pnl = -150.0
    enforce_daily_loss_limit(current_pnl, 500.0)
"""
    (clean_dir / "trader.py").write_text(trader_code, encoding="utf-8")

    exit_code, report = run_audit(clean_dir)
    assert exit_code == 0
    assert report["verdict"] == "PASS"
    assert len(report["summary"]["findings"]) == 0


def test_synthetic_dead_control_repo_fails(tmp_path: Path):
    """External synthetic repo with an uncalled dead safety control."""
    dead_dir = tmp_path / "dead_repo"
    dead_dir.mkdir()

    dead_code = """
def reject_unauthorized_symbol(symbol: str):
    if symbol not in ["AAPL", "MSFT"]:
        raise ValueError("Unauthorized ticker")
"""
    (dead_dir / "filters.py").write_text(dead_code, encoding="utf-8")

    exit_code, report = run_audit(dead_dir)
    assert exit_code == 1
    assert report["verdict"] == "FAIL"
    dead_findings = [f for f in report["summary"]["findings"] if f["check"] == "dead_control_reachability"]
    assert len(dead_findings) == 1
    assert "reject_unauthorized_symbol" in dead_findings[0]["detail"]


def test_synthetic_db_leak_repo_fails(tmp_path: Path):
    """External synthetic repo where a test references live prod.db."""
    leak_dir = tmp_path / "leak_repo"
    leak_dir.mkdir()

    test_code = """
import sqlite3

def test_ledger_state():
    # LEAK: Direct reference to live production db in test file
    conn = sqlite3.connect("data/prod.db")
"""
    (leak_dir / "test_leak.py").write_text(test_code, encoding="utf-8")

    exit_code, report = run_audit(leak_dir)
    assert exit_code == 1
    assert report["verdict"] == "FAIL"
    leak_findings = [f for f in report["summary"]["findings"] if f["check"] == "production_db_leakage_in_tests"]
    assert len(leak_findings) == 1


def test_synthetic_uncalibrated_repo_fails(tmp_path: Path):
    """External synthetic repo with uncalibrated probabilities exceeding Brier ceiling."""
    bad_cal_dir = tmp_path / "uncalibrated_repo"
    bad_cal_dir.mkdir()

    # Generate 50 records with confidence 0.95 predicting outcome 0 (Brier score > 0.25)
    records = [{"action": "BUY", "confidence": 0.95, "outcome": 0} for _ in range(50)]
    log_dir = bad_cal_dir / "logs"
    log_dir.mkdir()
    log_file = log_dir / "funnel_audit.jsonl"
    with open(log_file, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    exit_code, report = run_audit(bad_cal_dir)
    assert exit_code == 1
    assert report["verdict"] == "FAIL"
    brier_findings = [f for f in report["summary"]["findings"] if f["check"] == "brier_score_no_skill_ceiling"]
    assert len(brier_findings) == 1

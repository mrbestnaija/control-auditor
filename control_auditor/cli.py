"""control_auditor: Standalone Command-Line Interface.

Usage:
    control-auditor audit [--root <path>] [--json [<path>]] [--engine <all|ast|db|calibration>] [--strict]
    control-auditor discover [--root <path>] [--json]
    control-auditor prove --file <rel_path> --anchor <anchor> --replacement <replacement> --test <test_path>
"""

from __future__ import annotations

import argparse
import datetime
import sys
import time
from pathlib import Path
from typing import Any

from control_auditor.engines.ast_reachability import ASTReachabilityEngine
from control_auditor.engines.db_isolation import DBIsolationGuardEngine
from control_auditor.engines.numeric_falsifier import NumericCalibrationFalsifierEngine
from control_auditor.formatting import format_json_report, format_terminal_report


def run_audit(
    root_path: Path,
    engine_choice: str = "all",
    strict: bool = False,
    timeout: int = 60,
) -> tuple[int, dict[str, Any]]:
    """Execute auditing workflow across selected engines.
    
    Returns:
        (exit_code, report_dict)
    """
    start_time = time.perf_counter()
    iso_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    engines_report: dict[str, Any] = {}
    all_findings: list[dict[str, Any]] = []

    # 1. AST Reachability Engine
    if engine_choice in ("all", "ast"):
        ast_engine = ASTReachabilityEngine(root_path)
        ast_result = ast_engine.audit()
        engines_report["ast_reachability"] = ast_result
        all_findings.extend(ast_result.get("findings", []))

    # 2. DB Isolation Guard Engine
    if engine_choice in ("all", "db"):
        db_engine = DBIsolationGuardEngine(root_path)
        db_result = db_engine.audit()
        engines_report["db_isolation_guard"] = db_result
        all_findings.extend(db_result.get("findings", []))

    # 3. Numeric Calibration Falsifier Engine
    if engine_choice in ("all", "calibration"):
        cal_engine = NumericCalibrationFalsifierEngine(root_path)
        cal_result = cal_engine.audit()
        engines_report["numeric_calibration_falsifier"] = cal_result
        all_findings.extend(cal_result.get("findings", []))

    # Check overall verdict
    has_failures = any(data.get("status") == "FAIL" for data in engines_report.values())
    if strict and any(f.get("severity") == "MEDIUM" for f in all_findings):
        has_failures = True

    overall_verdict = "FAIL" if has_failures else "PASS"
    exit_code = 1 if has_failures else 0

    duration_ms = int((time.perf_counter() - start_time) * 1000)

    report = {
        "verdict": overall_verdict,
        "timestamp": iso_timestamp,
        "target_root": str(root_path),
        "duration_ms": duration_ms,
        "engines": engines_report,
        "summary": {
            "total_engines_evaluated": len(engines_report),
            "total_findings": len(all_findings),
            "findings": all_findings,
        },
    }

    return exit_code, report


def main(argv: list[str] | None = None) -> int:
    """Main CLI entrypoint."""
    parser = argparse.ArgumentParser(
        prog="control-auditor",
        description="Systemic Invariant Verification & Dead-Control Auditing CLI",
    )
    subparsers = parser.add_subparsers(dest="command", help="Auditor command to execute")

    # Command: audit
    audit_parser = subparsers.add_parser("audit", help="Run comprehensive verification audit on a repository")
    audit_parser.add_argument(
        "--root",
        "-r",
        type=str,
        default=".",
        help="Root path of target repository (default: current directory)",
    )
    audit_parser.add_argument(
        "--engine",
        "-e",
        choices=["all", "ast", "db", "calibration"],
        default="all",
        help="Specific verification engine to run (default: all)",
    )
    audit_parser.add_argument(
        "--json",
        nargs="?",
        const="",
        default=None,
        help="Output results as JSON. If a filepath is provided, writes JSON to file.",
    )
    audit_parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail on any medium severity warnings or unresolved references",
    )
    audit_parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="Max duration allowed per engine in seconds (default: 60)",
    )
    audit_parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress terminal output",
    )

    # Command: discover
    discover_parser = subparsers.add_parser("discover", help="Discover AST control candidates in target codebase")
    discover_parser.add_argument(
        "--root",
        "-r",
        type=str,
        default=".",
        help="Root path of repository (default: .)",
    )
    discover_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit discovered controls as JSON list",
    )

    # Command: prove
    prove_parser = subparsers.add_parser("prove", help="Run active mutation proof for a specific control")
    prove_parser.add_argument("--root", "-r", type=str, default=".", help="Root directory")
    prove_parser.add_argument("--file", "-f", required=True, help="Relative path to file containing control")
    prove_parser.add_argument("--anchor", "-a", required=True, help="Single-line unique anchor to mutate")
    prove_parser.add_argument("--replacement", "-m", required=True, help="Replacement mutated string")
    prove_parser.add_argument("--test", "-t", required=True, help="Test file or node to falsify")
    prove_parser.add_argument("--expect-failing-test", help="Expected test node name in failure log")

    args = parser.parse_args(argv)

    if not args.command or args.command == "audit":
        root_str = getattr(args, "root", ".") if hasattr(args, "root") else "."
        target_root = Path(root_str).resolve()
        if not target_root.exists():
            print(f"Error: Target root '{root_str}' does not exist.", file=sys.stderr)
            return 2

        engine_choice = getattr(args, "engine", "all")
        strict = getattr(args, "strict", False)
        timeout = getattr(args, "timeout", 60)
        json_arg = getattr(args, "json", None)
        quiet = getattr(args, "quiet", False)

        exit_code, report = run_audit(
            root_path=target_root,
            engine_choice=engine_choice,
            strict=strict,
            timeout=timeout,
        )

        json_output = format_json_report(report)

        if json_arg is not None:
            if json_arg:
                # Write to target file
                out_path = Path(json_arg)
                out_path.write_text(json_output, encoding="utf-8")
                if not quiet:
                    print(f"Audit report saved to: {out_path}")
            else:
                # Print JSON to stdout
                print(json_output)
        elif not quiet:
            print(format_terminal_report(report))

        return exit_code

    elif args.command == "discover":
        target_root = Path(args.root).resolve()
        if not target_root.exists():
            print(f"Error: Target root '{args.root}' does not exist.", file=sys.stderr)
            return 2

        ast_engine = ASTReachabilityEngine(target_root)
        controls = ast_engine.discover_controls()

        if args.json:
            import json
            print(json.dumps(controls, indent=2))
        else:
            print(f"\nDiscovered {len(controls)} enforcement candidates in {target_root}:")
            for c in controls:
                print(f"  - {c['file']}:{c['line']} :: {c['name']} (anchor={'YES' if c['anchor'] else 'NO'})")
        return 0

    elif args.command == "prove":
        target_root = Path(args.root).resolve()
        cal_engine = NumericCalibrationFalsifierEngine(target_root)
        result = cal_engine.prove_mutation(
            file_rel=args.file,
            anchor=args.anchor,
            replacement=args.replacement,
            test_path=args.test,
            expect_failing_test=args.expect_failing_test,
        )
        print(f"Mutation Proof Verdict: {result['verdict']}")
        print(f"Detail: {result.get('detail')}")
        return 0 if result["verdict"] == "PROVED" else 1

    return 2


if __name__ == "__main__":
    sys.exit(main())

"""Terminal and JSON output formatting for control_auditor."""

from __future__ import annotations

import json
from typing import Any

# ANSI Colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def format_terminal_report(report: dict[str, Any]) -> str:
    """Render a clean, high-density terminal summary table."""
    verdict = report.get("verdict", "UNKNOWN")
    verdict_badge = f"{GREEN}[PASS]{RESET}" if verdict == "PASS" else f"{RED}[FAIL]{RESET}"
    duration_s = report.get("duration_ms", 0) / 1000.0

    lines = [
        f"\n{BOLD}======================================================================{RESET}",
        f"{BOLD}           CONTROL AUDITOR: SYSTEMIC INVARIANT VERIFICATION           {RESET}",
        f"{BOLD}======================================================================{RESET}",
        f"Target Root : {report.get('target_root')}",
        f"Timestamp   : {report.get('timestamp')}",
        f"Duration    : {duration_s:.2f}s",
        f"Overall     : {verdict_badge}",
        f"{BOLD}----------------------------------------------------------------------{RESET}",
        f"{BOLD}{'ENGINE':<32} {'STATUS':<10} {'FINDINGS':<10}{RESET}",
        f"{BOLD}----------------------------------------------------------------------{RESET}",
    ]

    engines = report.get("engines", {})
    for engine_name, data in engines.items():
        st = data.get("status", "UNKNOWN")
        st_color = GREEN if st == "PASS" else RED
        findings_count = len(data.get("findings", []))
        lines.append(f"{engine_name:<32} {st_color}{st:<10}{RESET} {findings_count:<10}")

    findings = report.get("summary", {}).get("findings", [])
    if findings:
        lines.append(f"{BOLD}----------------------------------------------------------------------{RESET}")
        lines.append(f"{BOLD}BLOCKING FINDINGS & DEFECTS DETECTED:{RESET}")
        lines.append(f"{BOLD}----------------------------------------------------------------------{RESET}")
        for idx, f in enumerate(findings, start=1):
            sev = f.get("severity", "MEDIUM")
            sev_color = RED if sev in ("CRITICAL", "HIGH") else YELLOW
            lines.append(
                f"{idx:2d}. {sev_color}[{sev}]{RESET} {BOLD}{f.get('engine')}{RESET}::{f.get('check')}"
            )
            lines.append(f"    Target : {f.get('target', '-')}")
            lines.append(f"    Detail : {f.get('detail', '-')}")
    else:
        lines.append(f"{BOLD}----------------------------------------------------------------------{RESET}")
        lines.append(f"{GREEN}✓ Zero invariant violations detected. All verification gates passed.{RESET}")

    lines.append(f"{BOLD}======================================================================{RESET}\n")
    return "\n".join(lines)


def format_json_report(report: dict[str, Any], indent: int = 2) -> str:
    """Format machine-readable deterministic JSON report."""
    return json.dumps(report, indent=indent, default=str)

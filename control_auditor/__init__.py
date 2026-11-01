"""control_auditor: Standalone Zero-Fluff Verification Engine CLI.

Extracts and unifies 3 core verification engines:
- ast_reachability: AST-based static call-graph reachability & dead control detection.
- db_isolation_guard: SQLite C-authorizer sandboxing & database write discipline.
- numeric_calibration_falsifier: Mutation falsification, ECE, and Brier calibration contracts.
"""

__version__ = "1.0.0"
__author__ = "Verification & Forensic Engineering Team"

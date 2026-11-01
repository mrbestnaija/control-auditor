# control-auditor

**Systemic Invariant Verification & Dead-Control Auditing CLI for Autonomous Systems**

`control-auditor` is a zero-dependency, high-speed CLI tool designed to audit Python trading repositories, AI agent execution environments, and complex codebases in under 60 seconds with deterministic pass/fail exit codes.

## The 3 Verification Engines

1. **`ast_reachability`**:
   - Compiler-grade AST parsing of enforcement candidates (`refuse`, `reject`, `enforce`, `guard`, `validate`, `quarantine`).
   - Indexes repository-wide production call sites (excluding definitions, imports, comments, and test directories).
   - Detects dead controls (enforcement functions with 0 production callers) and block-depth zero violations (gates nested inside conditionals or try/except blocks).

2. **`db_isolation_guard`**:
   - C-level SQLite engine sandboxing via `conn.set_authorizer` blocking DDL (`CREATE`, `DROP`, `ALTER`), dangerous PRAGMAs, and `ATTACH/DETACH`.
   - Defensive database configuration (`SQLITE_DBCONFIG_DEFENSIVE = 1`, `SQLITE_DBCONFIG_TRUSTED_SCHEMA = 0`).
   - Read-only immutable URI connections (`file:...mode=ro&immutable=1`).
   - Static scan for unauthorized SQL write verbs against protected ledger tables and test database leakage.

3. **`numeric_calibration_falsifier`**:
   - Quantitative evaluation of Expected Calibration Error (ECE $\le 0.15$ across $\ge 10$ bins).
   - Brier score ceiling enforcement ($\le 0.25$ no-skill ceiling; Brier $> 0.25$ proves the model predicts worse than random guessing).
   - Calibration starvation detection with non-actionable `HOLD` filtering.
   - Constrained Platt scaling (`LogisticRegression`) AST enforcement.
   - Active sandboxed mutation falsification ("a guard that cannot go red is not a guard").

---

## Installation

```bash
pip install control-auditor
# or from source:
pip install -e ./control_auditor
```

---

## Usage

### 1. Full Verification Audit
Audit any local or external Python repository:
```bash
python -m control_auditor.cli audit --root /path/to/repo
```

Emit machine-readable JSON report:
```bash
python -m control_auditor.cli audit --root /path/to/repo --json audit_report.json
```

Run a specific engine:
```bash
python -m control_auditor.cli audit --root /path/to/repo --engine ast
python -m control_auditor.cli audit --root /path/to/repo --engine db
python -m control_auditor.cli audit --root /path/to/repo --engine calibration
```

### 2. Discover Controls
Extract all enforcement functions, line numbers, and single-line guard anchors:
```bash
python -m control_auditor.cli discover --root /path/to/repo
```

### 3. Active Mutation Proof
Prove that a specific test genuinely falsifies a control:
```bash
python -m control_auditor.cli prove \
  --root /path/to/repo \
  --file risk/limits.py \
  --anchor "if current_drawdown > max_limit:" \
  --replacement "if False:" \
  --test tests/test_risk.py::test_max_drawdown_rejected
```

---

## Exit Codes
- `0`: All verification checks PASS. Zero invariant violations detected.
- `1`: Verification FAIL. One or more dead controls, DB leakage risks, or calibration flaws detected.
- `2`: CLI usage / argument / filesystem error.
